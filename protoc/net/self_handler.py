"""
Self-Awareness Handler for WATR Nodes
Maintains and shares node capabilities, memory, and identity
"""

import time
import uuid
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

from watr_handlers import WATRHandler
from watr_protocol import WATRMessage


@dataclass
class NodeCapability:
    """Describes a capability this node has"""
    name: str
    version: str
    description: str
    message_types: List[str]
    created_at: float
    performance_metrics: Dict[str, float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NodeMemory:
    """Simple key-value memory for the node"""
    memories: Dict[str, Any]
    created_at: float
    
    def remember(self, key: str, value: Any):
        """Store a memory"""
        self.memories[key] = {
            'value': value,
            'timestamp': time.time()
        }
    
    def recall(self, key: str) -> Optional[Any]:
        """Retrieve a memory"""
        memory = self.memories.get(key)
        return memory['value'] if memory else None
    
    def forget(self, key: str):
        """Remove a memory"""
        if key in self.memories:
            del self.memories[key]


@dataclass
class NodeIdentity:
    """Node's identity and basic info"""
    node_id: str
    name: str
    description: str
    birth_time: float
    location: Optional[str] = None
    operator: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SelfHandler(WATRHandler):
    """Handler for node self-awareness and capability sharing"""
    
    def __init__(self, node: 'WATRNode', node_name: str = None, description: str = None):
        super().__init__(node)
        
        # Generate or use provided identity
        self.identity = NodeIdentity(
            node_id=str(uuid.uuid4()),
            name=node_name or f"WATRNode-{node.get_node_addr()[:8]}",
            description=description or "Self-organizing WATR mesh node",
            birth_time=time.time()
        )
        
        # Node memory system
        self.memory = NodeMemory(
            memories={},
            created_at=time.time()
        )
        
        # Track capabilities
        self.capabilities: Dict[str, NodeCapability] = {}
        
        # Discovered peers and their capabilities
        self.known_peers: Dict[str, Dict[str, Any]] = {}
        
        # Initialize with basic capabilities
        self._register_basic_capabilities()
    
    def get_handled_message_types(self) -> List[str]:
        return ['self_query', 'self_response', 'capability_announce']
    
    def _register_basic_capabilities(self):
        """Register the node's basic built-in capabilities"""
        # Communication capability
        self.add_capability(NodeCapability(
            name="basic_communication",
            version="1.0",
            description="Send and receive WATR protocol messages",
            message_types=["heartbeat", "chat"],
            created_at=time.time(),
            performance_metrics={"uptime": time.time()}
        ))
        
        # Handler management
        self.add_capability(NodeCapability(
            name="dynamic_handlers",
            version="1.0", 
            description="Load and unload message handlers at runtime",
            message_types=["handler_load", "handler_unload"],
            created_at=time.time()
        ))
    
    def register_conversation_capability(self):
        """Register conversation processing capability after handler is loaded"""
        self.add_capability(NodeCapability(
            name="conversation_processing",
            version="1.0",
            description="Accumulate and process streaming conversations",
            message_types=["chat"],
            created_at=time.time()
        ))
    
    def add_capability(self, capability: NodeCapability):
        """Add a capability to this node"""
        self.capabilities[capability.name] = capability
        print(f"Node '{self.identity.name}' gained capability: {capability.name}")
        
        # Announce to network
        self._announce_capability(capability)
    
    def remove_capability(self, capability_name: str):
        """Remove a capability from this node"""
        if capability_name in self.capabilities:
            del self.capabilities[capability_name]
            print(f"Node '{self.identity.name}' lost capability: {capability_name}")
    
    def _announce_capability(self, capability: NodeCapability):
        """Announce a new capability to the network"""
        self.node.send_message('capability_announce', {
            'node_id': self.identity.node_id,
            'node_name': self.identity.name,
            'capability': capability.to_dict()
        })
    
    async def handle_message(self, message: WATRMessage) -> None:
        """Handle incoming self-related messages"""
        if not self.is_active:
            return
        
        if message.message_type == 'self_query':
            await self._handle_self_query(message)
        elif message.message_type == 'self_response':
            await self._handle_self_response(message)
        elif message.message_type == 'capability_announce':
            await self._handle_capability_announce(message)
    
    async def _handle_self_query(self, message: WATRMessage):
        """Respond to queries about this node's capabilities"""
        query_type = message.payload.get('query_type', 'full')
        
        response_data = {
            'node_id': self.identity.node_id,
            'query_id': message.payload.get('query_id', str(uuid.uuid4())),
            'timestamp': time.time()
        }
        
        if query_type == 'identity':
            response_data['identity'] = self.identity.to_dict()
        elif query_type == 'capabilities':
            response_data['capabilities'] = {
                name: cap.to_dict() for name, cap in self.capabilities.items()
            }
        elif query_type == 'memory':
            # Only share non-sensitive memories
            response_data['memory_keys'] = list(self.memory.memories.keys())
        elif query_type == 'full':
            response_data.update({
                'identity': self.identity.to_dict(),
                'capabilities': {name: cap.to_dict() for name, cap in self.capabilities.items()},
                'memory_keys': list(self.memory.memories.keys()),
                'known_peers': len(self.known_peers)
            })
        
        # Send response back to querier
        self.node.send_message('self_response', response_data, dst_addr=message.src_addr)
        print(f"Responded to {query_type} query from {message.src_addr}")
    
    async def _handle_self_response(self, message: WATRMessage):
        """Process responses from other nodes"""
        node_id = message.payload.get('node_id')
        if not node_id:
            return
        
        # Store peer information
        peer_info = {
            'node_id': node_id,
            'last_seen': time.time(),
            'src_addr': message.src_addr,
            'data': message.payload
        }
        
        self.known_peers[node_id] = peer_info
        
        # Extract interesting info
        identity = message.payload.get('identity', {})
        capabilities = message.payload.get('capabilities', {})
        
        print(f"Learned about peer '{identity.get('name', 'Unknown')}' with {len(capabilities)} capabilities")
        
        # Remember interesting facts
        if identity.get('name'):
            self.memory.remember(f"peer_{node_id}_name", identity['name'])
        
        if capabilities:
            self.memory.remember(f"peer_{node_id}_capabilities", list(capabilities.keys()))
    
    async def _handle_capability_announce(self, message: WATRMessage):
        """Handle capability announcements from other nodes"""
        node_id = message.payload.get('node_id')
        capability = message.payload.get('capability')
        
        if node_id and capability:
            # Update peer info
            if node_id not in self.known_peers:
                self.known_peers[node_id] = {
                    'node_id': node_id,
                    'capabilities': {},
                    'last_seen': time.time(),
                    'src_addr': message.src_addr
                }
            
            self.known_peers[node_id]['capabilities'][capability['name']] = capability
            self.known_peers[node_id]['last_seen'] = time.time()
            
            print(f"Peer {message.payload.get('node_name', node_id[:8])} announced capability: {capability['name']}")
    
    def query_peer(self, peer_addr: str = None, query_type: str = 'full'):
        """Query a specific peer or broadcast to all"""
        query_id = str(uuid.uuid4())
        
        self.node.send_message('self_query', {
            'query_id': query_id,
            'query_type': query_type,
            'querier_id': self.identity.node_id,
            'querier_name': self.identity.name
        }, dst_addr=peer_addr)
        
        if peer_addr:
            print(f"Queried peer {peer_addr} for {query_type}")
        else:
            print(f"Broadcast query for {query_type}")
    
    def get_peer_capabilities(self) -> Dict[str, List[str]]:
        """Get a summary of all known peer capabilities"""
        summary = {}
        for node_id, peer in self.known_peers.items():
            capabilities = peer.get('capabilities', {})
            summary[node_id] = list(capabilities.keys())
        return summary
    
    def find_peers_with_capability(self, capability_name: str) -> List[str]:
        """Find all peers that have a specific capability"""
        peers = []
        for node_id, peer in self.known_peers.items():
            capabilities = peer.get('capabilities', {})
            if capability_name in capabilities:
                peers.append(node_id)
        return peers
    
    def get_identity(self) -> NodeIdentity:
        """Get this node's identity"""
        return self.identity
    
    def update_identity(self, **kwargs):
        """Update identity fields"""
        for key, value in kwargs.items():
            if hasattr(self.identity, key):
                setattr(self.identity, key, value)
    
    def get_status_summary(self) -> Dict[str, Any]:
        """Get a summary of this node's status"""
        return {
            'identity': self.identity.to_dict(),
            'capabilities': len(self.capabilities),
            'capability_names': list(self.capabilities.keys()),
            'known_peers': len(self.known_peers),
            'memories': len(self.memory.memories),
            'uptime': time.time() - self.identity.birth_time
        }
