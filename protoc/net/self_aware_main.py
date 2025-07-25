#!/usr/bin/env python3
"""
Self-Aware WATR Node Example
Demonstrates basic node self-awareness and peer discovery
"""

import asyncio
import sys
from watr_node import WATRNode
from watr_handlers import ConversationAccumulatorHandler, handle_completed_conversation
from self_handler import SelfHandler


async def demonstrate_self_awareness(node, self_handler):
    """Demonstrate the self-awareness capabilities"""
    print("\n=== SELF-AWARENESS DEMO ===")
    
    # Show node identity
    identity = self_handler.get_identity()
    print(f"I am: {identity.name} (ID: {identity.node_id[:8]}...)")
    print(f"Born at: {identity.birth_time}")
    
    # Show capabilities
    print(f"\nMy capabilities:")
    for name, cap in self_handler.capabilities.items():
        print(f"  - {name}: {cap.description}")
    
    # Store some memories
    self_handler.memory.remember("favorite_color", "blue")
    self_handler.memory.remember("startup_time", identity.birth_time)
    self_handler.memory.remember("experiment_goal", "Learn to evolve protocols")
    
    print(f"\nI remember {len(self_handler.memory.memories)} things:")
    for key in self_handler.memory.memories.keys():
        value = self_handler.memory.recall(key)
        print(f"  - {key}: {value}")


async def discover_peers(node, self_handler):
    """Discover and interact with other nodes"""
    print("\n=== PEER DISCOVERY ===")
    
    # Broadcast a query to discover peers
    print("Broadcasting discovery query...")
    self_handler.query_peer(query_type='full')
    
    # Wait a bit for responses
    await asyncio.sleep(3)
    
    # Show discovered peers
    peers = self_handler.get_peer_capabilities()
    print(f"\nDiscovered {len(peers)} peers:")
    for peer_id, capabilities in peers.items():
        peer_info = self_handler.known_peers.get(peer_id, {})
        name = peer_info.get('data', {}).get('identity', {}).get('name', 'Unknown')
        print(f"  - {name} ({peer_id[:8]}...): {capabilities}")


async def capability_matching(self_handler):
    """Demonstrate finding peers with specific capabilities"""
    print("\n=== CAPABILITY MATCHING ===")
    
    # Look for peers with conversation processing
    conv_peers = self_handler.find_peers_with_capability("conversation_processing")
    print(f"Nodes with conversation processing: {len(conv_peers)}")
    
    # Look for peers with dynamic handlers
    handler_peers = self_handler.find_peers_with_capability("dynamic_handlers")
    print(f"Nodes with dynamic handlers: {len(handler_peers)}")
    
    # This is the foundation for later sharing protocols!
    if conv_peers:
        print("🎯 Found potential conversation partners!")
    if handler_peers:
        print("🔧 Found potential protocol sharing partners!")


def custom_conversation_handler(conversation):
    """Enhanced conversation handler that learns from conversations"""
    print(f"\n🧠 LEARNING: Completed conversation from {conversation.src_addr}")
    print(f"   Words: {len(conversation.complete_text.split())}")
    print(f"   Duration: {conversation.end_time - conversation.start_time:.1f}s")
    
    # This is where we could later analyze conversations to generate new protocols!
    if len(conversation.complete_text) > 100:
        print("   📝 This was a substantial conversation - could inspire new protocols")


async def main():
    """Main application with self-awareness"""
    if len(sys.argv) < 3:
        print("Usage: python self_aware_main.py <interface> <node_address> [node_name]")
        return
    
    interface = sys.argv[1]
    node_addr = sys.argv[2]
    node_name = sys.argv[3] if len(sys.argv) > 3 else None
    
    # Create node
    node = WATRNode(interface, node_addr, heartbeat_interval=60)
    
    try:
        # Start the basic node
        await node.start()
        
        # Add self-awareness!
        self_handler = SelfHandler(
            node, 
            node_name=node_name,
            description="Self-aware WATR node learning to evolve"
        )
        await node.load_handler("self", self_handler)
        
        # Add conversation handler
        conv_handler = ConversationAccumulatorHandler(node)
        conv_handler.add_completion_handler(handle_completed_conversation)
        conv_handler.add_completion_handler(custom_conversation_handler)
        await node.load_handler("conversation_accumulator", conv_handler)
        
        # Now register the conversation capability
        self_handler.register_conversation_capability()
        
        print(f"\n🚀 Self-aware WATR Node '{self_handler.identity.name}' is online!")
        print(f"   Address: {node_addr}")
        print(f"   Handlers: {list(node.list_handlers().keys())}")
        
        # Demonstrate self-awareness
        await demonstrate_self_awareness(node, self_handler)
        
        # Try to discover peers
        await discover_peers(node, self_handler)
        
        # Show capability matching
        await capability_matching(self_handler)
        
        print(f"\n💭 Try these commands in another terminal:")
        print(f"   # Start another node")
        print(f"   sudo python self_aware_main.py {interface} aa:bb:cc:dd:ee:ff Buddy")
        print(f"   ")
        print(f"   # Query this node specifically")
        print(f"   # (from Python REPL on another node)")
        print(f"   self_handler.query_peer('{node_addr}', 'capabilities')")
        
        # Send a test chat
        await asyncio.sleep(5)
        await node.chat("Hello! I'm a self-aware WATR node learning to evolve.")
        
        # Regular status updates
        status_count = 0
        while True:
            await asyncio.sleep(30)
            status_count += 1
            
            # Show status every 5 minutes
            if status_count % 10 == 0:
                summary = self_handler.get_status_summary()
                print(f"\n📊 Status Update:")
                print(f"   Uptime: {summary['uptime']:.1f}s")
                print(f"   Known peers: {summary['known_peers']}")
                print(f"   Memories: {summary['memories']}")
                
                # Re-announce capabilities with error handling
                try:
                    for cap_name, cap in self_handler.capabilities.items():
                        self_handler._announce_capability(cap)
                    print(f"   📡 Re-announced {len(self_handler.capabilities)} capabilities")
                except Exception as e:
                    print(f"   ⚠️  Error re-announcing capabilities: {e}")
    
    except KeyboardInterrupt:
        print("\n🛑 Shutting down self-aware node...")
        await node.stop()


if __name__ == "__main__":
    asyncio.run(main())
