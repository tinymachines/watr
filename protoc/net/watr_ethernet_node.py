"""
WATR Ethernet Node Implementation
High-level node with heartbeat functionality for Ethernet networks
"""

import asyncio
import time
import uuid
from typing import Callable, Dict, Any, List

from ollama import AsyncClient

from watr_ethernet_protocol import WATREthernetProtocol, WATRMessage, HeartbeatMessage
from watr_handlers import WATRHandler, HandlerManager


class WATREthernetNode:
    """High-level WATR node for Ethernet communication"""
    
    def __init__(self, interface: str, node_addr: str = None, heartbeat_interval: int = 60):
        # Get MAC address if not provided
        if node_addr is None:
            node_addr = self._get_mac_address(interface)
            
        self.protocol = WATREthernetProtocol(interface, node_addr)
        self.heartbeat_interval = heartbeat_interval
        self.heartbeat_task = None
        
        # Dynamic handler management
        self.handler_manager = HandlerManager(self)
        
        # Register default handlers
        self.protocol.set_default_handler(self._default_message_handler)
        self.protocol.register_handler('heartbeat', self._heartbeat_handler)

    def _get_mac_address(self, interface: str) -> str:
        """Get MAC address of the interface"""
        try:
            from scapy.arch import get_if_hwaddr
            return get_if_hwaddr(interface)
        except Exception as e:
            print(f"Error getting MAC address: {e}")
            # Generate a random MAC if we can't get the real one
            import random
            return ':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)])

    def _default_message_handler(self, message: WATRMessage):
        """Default handler for received messages"""
        print(f"[ETH] Received {message.message_type} from {message.src_addr}: {message.payload}")

    def _heartbeat_handler(self, message: WATRMessage):
        """Handler for heartbeat messages"""
        print(f"[ETH] Heartbeat from {message.src_addr}: {message.payload}")

    async def _heartbeat_loop(self):
        """Async loop for sending heartbeat messages"""
        while self.protocol.running:
            heartbeat = HeartbeatMessage(self.protocol.src_addr)
            self.protocol.send_message(heartbeat)
            print(f"[ETH] Sent heartbeat from {self.protocol.src_addr}")
            await asyncio.sleep(self.heartbeat_interval)

    async def start(self):
        """Start the node"""
        await self.protocol.start()
        
        # Start heartbeat loop
        self.heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        
        print(f"WATR Ethernet Node {self.protocol.src_addr} started")
        print(f"Interface: {self.protocol.interface}")
        print(f"Heartbeat interval: {self.heartbeat_interval}s")

    async def stop(self):
        """Stop the node"""
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
            
        # Unload all handlers
        for handler_name in list(self.handler_manager.handlers.keys()):
            await self.handler_manager.unload_handler(handler_name)
            
        await self.protocol.stop()

    async def chat(self, prompt: str = "Hi", model: str = "gemma3:1b"):
        """Send a streaming chat message using Ollama"""
        cid = uuid.uuid4().hex
        seg = 0
        message = {'role': 'user', 'content': prompt}
        
        try:
            async for part in await AsyncClient().chat(
                    model=model, messages=[message], stream=True
            ):
                self.send_message(
                        'chat', 
                        {'cid': cid, "seg": seg, 'text': part['message']['content']}
                )
                seg += 1
            
            # Send termination segment
            self.send_message(
                    'chat',
                    {'cid': cid, "seg": seg, 'text': None}
            )
            
            print(f"[ETH] Sent complete chat conversation {cid[:8]}... ({seg} segments)")
            
        except Exception as e:
            print(f"[ETH] Error in chat: {e}")
            # Send error termination
            self.send_message(
                    'chat',
                    {'cid': cid, "seg": seg, 'text': None}
            )

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
        """Register a message handler (legacy compatibility)"""
        self.protocol.register_handler(message_type, handler)

    # Dynamic handler methods
    async def load_handler(self, name: str, handler: WATRHandler) -> bool:
        """Load a dynamic handler"""
        return await self.handler_manager.load_handler(name, handler)

    async def unload_handler(self, name: str) -> bool:
        """Unload a dynamic handler"""
        return await self.handler_manager.unload_handler(name)

    def list_handlers(self) -> Dict[str, List[str]]:
        """List all loaded handlers"""
        return self.handler_manager.list_handlers()

    # Utility methods
    def get_node_addr(self) -> str:
        """Get this node's address"""
        return self.protocol.src_addr

    def is_running(self) -> bool:
        """Check if the node is running"""
        return self.protocol.running

    async def send_custom_chat(self, conversation_id: str, segments: List[str]):
        """Send a pre-segmented chat conversation"""
        for seg, text in enumerate(segments):
            self.send_message(
                'chat',
                {'cid': conversation_id, 'seg': seg, 'text': text}
            )
            await asyncio.sleep(0.01)  # Smaller delay for more reliable Ethernet
        
        # Send termination
        self.send_message(
            'chat',
            {'cid': conversation_id, 'seg': len(segments), 'text': None}
        )
