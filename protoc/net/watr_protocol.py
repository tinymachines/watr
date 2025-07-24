"""
WATR Protocol Core Components
Handles 802.11 frame communication and message serialization
"""

import asyncio
import queue
import threading
import time
import json
from typing import Callable, Optional, Dict, Any
from dataclasses import dataclass

from scapy.all import *
from scapy.layers.dot11 import *


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