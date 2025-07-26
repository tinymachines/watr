#!/usr/bin/env python3
"""
Social WATR Network
Demonstrates nodes having conversations, sharing gossip, and voting
"""

import asyncio
import sys
import random
from watr_node import WATRNode
from watr_handlers import ConversationAccumulatorHandler, handle_completed_conversation
from self_handler import SelfHandler
from social_handler import SocialHandler


async def demo_social_behaviors(social_handler, delay=30):
    """Demonstrate various social behaviors"""
    await asyncio.sleep(delay)
    
    # Generate some interesting gossip topics
    gossip_topics = [
        "I just learned how to process conversations in real-time!",
        "Did you know we can load new handlers without restarting?",
        "The mesh network is growing - I sense new nodes joining!",
        "I've been experimenting with different message patterns.",
        "Someone should organize a network-wide protocol optimization project!",
        "I wonder if we could build a distributed filesystem together?",
        "The heartbeat messages are like the pulse of our digital organism.",
        "I'm storing memories of all our interactions - we're building history!",
        "What if we could teach new nodes by sharing our learned behaviors?",
        "The network feels alive when we all communicate together!"
    ]
    
    # Vote topics
    vote_topics = [
        ("What should our network focus on next?", 
         ["Protocol optimization", "New features", "Network expansion", "Security improvements"]),
        ("Best time for network maintenance?", 
         ["Early morning", "Late evening", "Weekends", "Never needed"]),
        ("What's the most important network value?", 
         ["Reliability", "Performance", "Innovation", "Collaboration"]),
        ("How should we handle new nodes?", 
         ["Welcome enthusiastically", "Observe quietly", "Test capabilities", "Immediate integration"]),
        ("Network personality trait to develop?",
         ["More curious", "More helpful", "More efficient", "More creative"])
    ]
    
    behavior_count = 0
    
    while True:
        await asyncio.sleep(random.uniform(45, 90))  # Every 1-1.5 minutes
        behavior_count += 1
        
        # Choose a random social behavior
        behavior = random.choice(['gossip', 'vote', 'memory_share', 'introduction'])
        
        try:
            if behavior == 'gossip' and behavior_count % 3 == 0:
                topic = random.choice(gossip_topics)
                await social_handler.share_gossip(topic)
                
            elif behavior == 'vote' and behavior_count % 7 == 0:  # Less frequent
                question, options = random.choice(vote_topics)
                await social_handler.propose_vote(question, options, duration=180)  # 3 minute votes
                
            elif behavior == 'memory_share' and behavior_count % 4 == 0:
                # Share a random memory
                self_handler = social_handler.node.handler_manager.handlers.get('self')
                if self_handler and self_handler.memory.memories:
                    memory_keys = list(self_handler.memory.memories.keys())
                    # Only share non-sensitive memories
                    shareable_keys = [k for k in memory_keys if not k.startswith('peer_') and not k.startswith('shared_')]
                    if shareable_keys:
                        key_to_share = random.choice(shareable_keys)
                        await social_handler.share_memory(key_to_share)
                        
            elif behavior == 'introduction' and behavior_count % 5 == 0:
                await social_handler.introduce_to_network()
                
        except Exception as e:
            print(f"Error in social behavior {behavior}: {e}")


async def periodic_social_status(social_handler):
    """Show social status updates"""
    while True:
        await asyncio.sleep(120)  # Every 2 minutes
        
        try:
            status = social_handler.get_social_status()
            self_handler = social_handler.node.handler_manager.handlers.get('self')
            
            print(f"\n🎭 === SOCIAL STATUS ===")
            print(f"Personality: {status['personality']}")
            print(f"Introductions made: {status['introduced_to']}")
            print(f"Gossip heard: {status['gossip_heard']}")
            print(f"Active votes: {status['active_votes']}")
            print(f"Conversation partners: {status['conversation_partners']}")
            
            if self_handler:
                print(f"Network peers known: {len(self_handler.known_peers)}")
                print(f"Total memories: {len(self_handler.memory.memories)}")
            
            # Show some recent gossip
            if social_handler.gossip_heard:
                recent_gossip = sorted(social_handler.gossip_heard.values(), 
                                     key=lambda g: g.created_at, reverse=True)[:2]
                print(f"Recent gossip:")
                for gossip in recent_gossip:
                    age = time.time() - gossip.created_at
                    print(f"  • {gossip.content[:50]}... ({age:.0f}s ago)")
            
            # Show active votes
            if social_handler.active_votes:
                print(f"Active votes:")
                for vote in social_handler.active_votes.values():
                    votes_cast = len(vote.votes)
                    time_left = vote.ends_at - time.time()
                    if time_left > 0:
                        print(f"  🗳️  {vote.question} ({votes_cast} votes, {time_left:.0f}s left)")
                    else:
                        # Show results
                        vote_counts = {}
                        for choice in vote.votes.values():
                            vote_counts[choice] = vote_counts.get(choice, 0) + 1
                        winner = max(vote_counts.items(), key=lambda x: x[1]) if vote_counts else ("No votes", 0)
                        print(f"  ✅ {vote.question} → Winner: {winner[0]} ({winner[1]} votes)")
            
            print("========================\n")
            
        except Exception as e:
            print(f"Error showing social status: {e}")


def enhanced_conversation_handler(conversation):
    """Enhanced conversation handler that triggers social responses"""
    print(f"\n🤖 CONVERSATION COMPLETED from {conversation.src_addr}")
    print(f"   Duration: {conversation.end_time - conversation.start_time:.1f}s")
    print(f"   Content: {conversation.complete_text[:100]}...")
    
    # This could trigger social responses in the future!
    if len(conversation.complete_text) > 50:
        print(f"   💡 Rich conversation - could inspire social interactions!")


async def main():
    """Main social network application"""
    if len(sys.argv) < 3:
        print("Usage: python social_main.py <interface> <node_address> [node_name]")
        print("Example: python social_main.py wlan0 00:11:22:33:44:55 Alice")
        return
    
    interface = sys.argv[1]
    node_addr = sys.argv[2]
    node_name = sys.argv[3] if len(sys.argv) > 3 else None
    
    # Create node
    node = WATRNode(interface, node_addr, heartbeat_interval=60)
    
    try:
        # Start the basic node
        await node.start()
        
        # Add self-awareness
        self_handler = SelfHandler(
            node, 
            node_name=node_name,
            description="Social WATR node with personality and collaborative behaviors"
        )
        await node.load_handler("self", self_handler)
        
        # Add conversation processing
        conv_handler = ConversationAccumulatorHandler(node)
        conv_handler.add_completion_handler(handle_completed_conversation)
        conv_handler.add_completion_handler(enhanced_conversation_handler)
        await node.load_handler("conversation_accumulator", conv_handler)
        
        # Register conversation capability
        self_handler.register_conversation_capability()
        
        # Add social behaviors!
        social_handler = SocialHandler(node)
        await node.load_handler("social", social_handler)
        
        # Add social capability
        self_handler.add_capability(NodeCapability(
            name="social_interactions",
            version="1.0",
            description="Node can introduce itself, chat, share gossip, and vote",
            message_types=["social_introduction", "social_chat", "network_gossip", "network_vote"],
            created_at=time.time(),
            performance_metrics={}
        ))
        
        print(f"\n🎉 Social WATR Node '{self_handler.identity.name}' is ready to socialize!")
        print(f"   🎭 Personality: {social_handler.personality_traits}")
        print(f"   📡 Address: {node_addr}")
        print(f"   🔧 Handlers: {list(node.list_handlers().keys())}")
        
        # Store some initial memories to share
        self_handler.memory.remember("favorite_protocol", "WATR")
        self_handler.memory.remember("network_goal", "Collaborative evolution")
        self_handler.memory.remember("startup_mood", random.choice(["excited", "curious", "optimistic", "ready"]))
        self_handler.memory.remember("best_feature", random.choice(["dynamic handlers", "mesh networking", "AI integration", "self-awareness"]))
        
        print(f"\n🧠 Initial memories stored for sharing")
        
        # Start social behaviors
        await asyncio.sleep(5)  # Let the node settle
        
        # Introduce ourselves to the network
        await social_handler.introduce_to_network()
        
        # Start background social behaviors
        social_demo_task = asyncio.create_task(demo_social_behaviors(social_handler, delay=20))
        status_task = asyncio.create_task(periodic_social_status(social_handler))
        
        print(f"\n💬 Social behaviors active! Watch for:")
        print(f"   👋 Introductions and conversations")
        print(f"   📰 Network gossip spreading")
        print(f"   🗳️  Collaborative voting")
        print(f"   🧠 Memory sharing")
        print(f"   🎭 Personality-driven interactions")
        
        # Send a chat to get things started
        await asyncio.sleep(10)
        await node.chat(f"Hello everyone! I'm {self_handler.identity.name} and I'm excited to be part of this social mesh network!")
        
        # Keep running
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        print(f"\n👋 {self_handler.identity.name} is signing off from the social network...")
        await node.stop()


# Import the missing NodeCapability for the social capability registration
import time
from self_handler import NodeCapability

if __name__ == "__main__":
    asyncio.run(main())