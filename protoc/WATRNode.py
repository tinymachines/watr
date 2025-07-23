import asyncio
import queue
import threading
import time
import json
from typing import Callable, Optional, Dict, Any
from dataclasses import dataclass
from abc import ABC, abstractmethod

from scapy.all import *
from scapy.layers.dot11 import *
from ollama import AsyncClient



@dataclass
class WATRMessage:
    """Base message structure for WATR protocol"""
    message_type: str
    payload: Dict[str, Any]
    timestamp: float
    src_addr: str
    dst_addr: str

    def to_bytes(self) -> bytes:
        """Serialize message to bytes"""
        data = {
            'type': self.message_type,
            'payload': self.payload,
            'timestamp': self.timestamp,
            'src': self.src_addr,
            'dst': self.dst_addr
        }
        return json.dumps(data).encode('utf-8')

    @classmethod
    def from_bytes(cls, data: bytes, src_addr: str, dst_addr: str) -> 'WATRMessage':
        """Deserialize message from bytes"""
        try:
            parsed = json.loads(data.decode('utf-8'))
            return cls(
                message_type=parsed.get('type', 'unknown'),
                payload=parsed.get('payload', {}),
                timestamp=parsed.get('timestamp', time.time()),
                src_addr=parsed.get('src', src_addr),
                dst_addr=parsed.get('dst', dst_addr)
            )
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Fallback for non-JSON data
            return cls(
                message_type='raw',
                payload={'data': data.decode('utf-8', errors='ignore')},
                timestamp=time.time(),
                src_addr=src_addr,
                dst_addr=dst_addr
            )


class HeartbeatMessage(WATRMessage):
    """Specialized heartbeat message"""
    def __init__(self, src_addr: str, dst_addr: str = "ff:ff:ff:ff:ff:ff"):
        super().__init__(
            message_type='heartbeat',
            payload={
                'node_id': src_addr,
                'status': 'alive',
                'protocol_version': '1.0'
            },
            timestamp=time.time(),
            src_addr=src_addr,
            dst_addr=dst_addr
        )


class WATRProtocol:
    """Main WATR protocol class for 802.11 frame communication"""
    
    def __init__(self, interface: str, src_addr: str, dst_addr: str = "ff:ff:ff:ff:ff:ff"):
        self.interface = interface
        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.protocol_id = 0x8999
        
        # Queues for async communication
        self.outbound_queue = queue.Queue()
        self.inbound_queue = queue.Queue()
        
        # Event loop and threading
        self.loop = None
        self.running = False
        self.sniffer_thread = None
        self.sender_thread = None
        
        # Callbacks
        self.message_handlers: Dict[str, Callable[[WATRMessage], None]] = {}
        self.default_handler: Optional[Callable[[WATRMessage], None]] = None

    def create_frame(self, message: WATRMessage) -> Packet:
        """Creates a custom 802.11 data frame with the message payload"""
        # Create the 802.11 frame
        dot11 = Dot11(
            type=2,  # Type 2 is Data
            subtype=0,  # Subtype 0 is Data
            addr1=message.dst_addr,  # Destination address
            addr2=message.src_addr,  # Source address
            addr3=message.src_addr,  # BSSID
            FCfield='from-DS'
        )
        
        # Create the LLC layer
        llc = LLC(
            dsap=0xAA,
            ssap=0xAA,
            ctrl=0x03
        )
        
        # Create SNAP header with custom protocol ID
        snap = SNAP(
            OUI=0x000000,
            code=self.protocol_id
        )
        
        # Combine layers with payload
        frame = RadioTap()/dot11/llc/snap/Raw(load=message.to_bytes())
        return frame

    def frame_filter(self, pkt) -> bool:
        """Filter for WATR protocol frames"""
        return (
            Dot11 in pkt and
            pkt[Dot11].type == 2 and
            pkt[Dot11].subtype == 0 and
            SNAP in pkt and
            pkt[SNAP].code == self.protocol_id
        )

    def process_received_frame(self, pkt):
        """Process received frame and extract message"""
        try:
            if Raw in pkt:
                payload = pkt[Raw].load
                src_addr = pkt[Dot11].addr2
                dst_addr = pkt[Dot11].addr1
                
                message = WATRMessage.from_bytes(payload, src_addr, dst_addr)
                self.inbound_queue.put(message)
        except Exception as e:
            print(f"Error processing frame: {e}")

    def register_handler(self, message_type: str, handler: Callable[[WATRMessage], None]):
        """Register a handler for specific message types"""
        self.message_handlers[message_type] = handler

    def set_default_handler(self, handler: Callable[[WATRMessage], None]):
        """Set default handler for unhandled message types"""
        self.default_handler = handler

    def send_message(self, message: WATRMessage):
        """Queue a message for sending"""
        self.outbound_queue.put(message)

    def _sender_worker(self):
        """Worker thread for sending queued messages"""
        while self.running:
            try:
                message = self.outbound_queue.get(timeout=1.0)
                frame = self.create_frame(message)
                sendp(frame, iface=self.interface, verbose=False)
                self.outbound_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error sending frame: {e}")

    def _sniffer_worker(self):
        """Worker thread for sniffing frames"""
        try:
            sniff(
                iface=self.interface,
                lfilter=self.frame_filter,
                prn=self.process_received_frame,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            print(f"Error in sniffer: {e}")

    async def _message_processor(self):
        """Async coroutine to process incoming messages"""
        while self.running:
            try:
                # Check for new messages (non-blocking)
                try:
                    message = self.inbound_queue.get_nowait()
                    
                    # Find appropriate handler
                    handler = self.message_handlers.get(
                        message.message_type, 
                        self.default_handler
                    )
                    
                    if handler:
                        # Run handler in thread to avoid blocking event loop
                        loop = asyncio.get_event_loop()
                        await loop.run_in_executor(None, handler, message)
                    
                    self.inbound_queue.task_done()
                    
                except queue.Empty:
                    pass
                
                await asyncio.sleep(0.01)  # Small delay to prevent busy waiting
                
            except Exception as e:
                print(f"Error processing message: {e}")

    async def start(self):
        """Start the protocol"""
        if self.running:
            return
            
        self.running = True
        self.loop = asyncio.get_event_loop()
        
        # Start worker threads
        self.sender_thread = threading.Thread(target=self._sender_worker, daemon=True)
        self.sniffer_thread = threading.Thread(target=self._sniffer_worker, daemon=True)
        
        self.sender_thread.start()
        self.sniffer_thread.start()
        
        # Start message processor
        asyncio.create_task(self._message_processor())
        
        print(f"WATR Protocol started on interface {self.interface}")

    async def stop(self):
        """Stop the protocol"""
        self.running = False
        
        # Wait for threads to finish
        if self.sender_thread and self.sender_thread.is_alive():
            self.sender_thread.join(timeout=2.0)
            
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=2.0)
            
        print("WATR Protocol stopped")


class WATRNode:
    """High-level WATR node with heartbeat functionality"""
    
    def __init__(self, interface: str, node_addr: str, heartbeat_interval: int = 60):
        self.protocol = WATRProtocol(interface, node_addr)
        self.heartbeat_interval = heartbeat_interval
        self.heartbeat_task = None
        
        # Register default handlers
        self.protocol.set_default_handler(self._default_message_handler)
        self.protocol.register_handler('heartbeat', self._heartbeat_handler)

    def _default_message_handler(self, message: WATRMessage):
        """Default handler for received messages"""
        print(f"Received {message.message_type} from {message.src_addr}: {message.payload}")

    def _heartbeat_handler(self, message: WATRMessage):
        """Handler for heartbeat messages"""
        print(f"Heartbeat from {message.src_addr}: {message.payload}")

    async def _heartbeat_loop(self):
        """Async loop for sending heartbeat messages"""
        while self.protocol.running:
            heartbeat = HeartbeatMessage(self.protocol.src_addr)
            self.protocol.send_message(heartbeat)
            print(f"Sent heartbeat from {self.protocol.src_addr}")
            await asyncio.sleep(self.heartbeat_interval)

    async def start(self):
        """Start the node"""
        await self.protocol.start()
        
        # Start heartbeat loop
        self.heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        
        print(f"WATR Node {self.protocol.src_addr} started with heartbeat every {self.heartbeat_interval}s")

    async def stop(self):
        """Stop the node"""
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
            
        await self.protocol.stop()

    async def chat(self):
        message = {'role': 'user', 'content': 'Say something nice.'}
        async for part in await AsyncClient().chat(
                model='qwen3:0.6b', messages=[message], stream=True
        ): print(part['message']['content'], end='', flush=True)

    def send_message(self, message_type: str, payload: Dict[str, Any], dst_addr: str = None):
        """Send a custom message"""
        message = WATRMessage(
            message_type=message_type,
            payload=payload,
            timestamp=time.time(),
            src_addr=self.protocol.src_addr,
            dst_addr=dst_addr or self.protocol.dst_addr
        )
        self.protocol.send_message(message)

    def register_handler(self, message_type: str, handler: Callable[[WATRMessage], None]):
        """Register a message handler"""
        self.protocol.register_handler(message_type, handler)


# Entry point application
async def main():
    """Main application entry point"""
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python watr_async.py <interface> <node_address>")
        print("Example: python watr_async.py wlan0 00:11:22:33:44:55")
        return
    
    interface = sys.argv[1]
    node_addr = sys.argv[2]
    
    # Create and configure node
    node = WATRNode(interface, node_addr, heartbeat_interval=60)
    
    # Example custom message handler
    def custom_handler(message: WATRMessage):
        print(f"Custom handler received: {message.message_type} - {message.payload}")
    
    node.register_handler('chat', custom_handler)
    
    try:
        # Start the node
        await node.start()
        
        # Example: send a custom message after 5 seconds
        await asyncio.sleep(5)
        await node.chat()
       # from ollama import chat
       # from ollama import ChatResponse

       # response: ChatResponse = chat(model='qwen3:0.6b', messages=[{
       #     'role': 'user',
       #     'content': 'Say Hello in a random language.',
       #     'format': 'json',
       #     'think': true,
       #     'stream': false
       #     },])
       # #print(response['message']['content'])
       # node.send_message('chat', {'text': response.message.content[0:100]})
        
        # Keep running
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        print("\nShutting down...")
        await node.stop()


if __name__ == "__main__":
    asyncio.run(main())
