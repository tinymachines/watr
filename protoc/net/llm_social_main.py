#!/usr/bin/env python3
"""
LLM-Enhanced Social WATR Network
Demonstrates intelligent conversations, contextual gossip, and smart voting
"""

import asyncio
import sys
import random
import time
from watr_node import WATRNode
from watr_handlers import ConversationAccumulatorHandler, handle_completed_conversation
from self_handler import SelfHandler, NodeCapability
from llm_social_handler import LLMSocialHandler


async def demo_llm_behaviors(llm_social_handler, delay=45):
    """Demonstrate intelligent LLM behaviors"""
    await asyncio.sleep(delay)
    
    behavior_count = 0
    
    while True:
        await asyncio.sleep(random.uniform(60, 120))  # Every 1-2 minutes
        behavior_count += 1
        
        # Choose intelligent behaviors
        behavior = random.choice(['intelligent_gossip', 'intelligent_vote', 'network_analysis'])
        
        try:
            if behavior == 'intelligent_gossip' and behavior_count % 3 == 0:
                print("🤖 Generating intelligent gossip...")
                await llm_social_handler.share_intelligent_gossip()
                
            elif behavior == 'intelligent_vote' and behavior_count % 5 == 0:
                print("🤖 Generating intelligent vote...")
                await llm_social_handler.propose_intelligent_vote()
                
            elif behavior == 'network_analysis' and behavior_count % 7 == 0:
                # Demonstrate network analysis
                print("🤖 Analyzing network state...")
                try:
                    analysis = await llm_social_handler._generate_llm_response(
                        "Analyze the current state of our mesh network. What patterns do you notice? What should we focus on?",
                        max_words=80
                    )
                    print(f"🔍 Network Analysis: {analysis}")
                    
                    # Share the analysis as gossip
                    await asyncio.sleep(2)
                    await llm_social_handler.share_intelligent_gossip()
                    
                except Exception as e:
                    print(f"Error in network analysis: {e}")
                
        except Exception as e:
            print(f"Error in LLM behavior {behavior}: {e}")


async def enhanced_conversation_handler(conversation, llm_handler):
    """LLM-enhanced conversation completion handler"""
    print(f"\n🤖💬 CONVERSATION ANALYSIS")
    print(f"   From: {conversation.src_addr}")
    print(f"   Duration: {conversation.end_time - conversation.start_time:.1f}s")
    print(f"   Length: {len(conversation.complete_text)} chars")
    
    try:
        # Use LLM to analyze the conversation
        analysis = await llm_handler.analyze_conversation(conversation.complete_text)
        print(f"   🧠 LLM Analysis: {analysis}")
        
        # If it was a substantial conversation, maybe share insights as gossip
        if len(conversation.complete_text) > 100:
            await asyncio.sleep(random.uniform(10, 20))
            
            gossip_content = f"Just had an interesting conversation about {conversation.complete_text[:50]}... {analysis}"
            
            # Create gossip with the analysis
            import uuid
            from llm_social_handler import NetworkGossip
            
            gossip_id = str(uuid.uuid4())
            self_handler = llm_handler.node.handler_manager.handlers.get('self')
            
            gossip = NetworkGossip(
                gossip_id=gossip_id,
                originator=self_handler.identity.name if self_handler else "Unknown",
                content=gossip_content[:150],  # Keep it reasonable
                created_at=time.time()
            )
            
            llm_handler.gossip_heard[gossip_id] = gossip
            
            llm_handler.node.send_message('network_gossip', {
                'gossip_id': gossip.gossip_id,
                'originator': gossip.originator,
                'content': gossip.content,
                'created_at': gossip.created_at,
                'hops': gossip.hops,
                'seen_by': gossip.seen_by
            })
            
            print(f"   📢 Shared conversation insights as gossip")
            
    except Exception as e:
        print(f"   ⚠️ Error analyzing conversation: {e}")


async def periodic_llm_status(llm_social_handler):
    """Show enhanced social status with LLM context"""
    while True:
        await asyncio.sleep(180)  # Every 3 minutes
        
        try:
            status = llm_social_handler.get_social_status()
            self_handler = llm_social_handler.node.handler_manager.handlers.get('self')
            
            print(f"\n🤖🎭 === LLM SOCIAL STATUS ===")
            print(f"Model: {status['model']}")
            print(f"Role: {status['personality']['role']}")
            print(f"Traits: {', '.join(status['personality']['traits'])}")
            print(f"Communication: {status['personality']['communication_style']}")
            print(f"")
            print(f"Social Interactions:")
            print(f"  👋 Introductions: {status['introduced_to']}")
            print(f"  💬 Conversation contexts: {status['conversation_contexts']}")
            print(f"  📰 Gossip heard: {status['gossip_heard']}")
            print(f"  🗳️  Active votes: {status['active_votes']}")
            
            if self_handler:
                print(f"  🌐 Known peers: {len(self_handler.known_peers)}")
                print(f"  🧠 Total memories: {len(self_handler.memory.memories)}")
            
            # Show recent intelligent gossip
            if llm_social_handler.gossip_heard:
                recent_gossip = sorted(llm_social_handler.gossip_heard.values(), 
                                     key=lambda g: g.created_at, reverse=True)[:2]
                print(f"Recent gossip:")
                for gossip in recent_gossip:
                    age = time.time() - gossip.created_at
                    print(f"  📰 {gossip.content[:60]}... ({age:.0f}s ago)")
            
            # Show voting results
            current_time = time.time()
            completed_votes = [v for v in llm_social_handler.active_votes.values() 
                             if v.ends_at < current_time and v.votes]
            
            if completed_votes:
                print(f"Recent vote results:")
                for vote in completed_votes[-2:]:  # Show last 2
                    vote_counts = {}
                    for choice in vote.votes.values():
                        vote_counts[choice] = vote_counts.get(choice, 0) + 1
                    if vote_counts:
                        winner = max(vote_counts.items(), key=lambda x: x[1])
                        print(f"  🗳️  '{vote.question}' → {winner[0]} ({winner[1]} votes)")
            
            print("===============================\n")
            
        except Exception as e:
            print(f"Error showing LLM social status: {e}")


async def demonstrate_llm_interactions(llm_handler, delay=30):
    """Demonstrate specific LLM interaction capabilities"""
    await asyncio.sleep(delay)
    
    demos = [
        {
            'name': 'Network Health Check',
            'action': lambda: llm_handler._generate_llm_response(
                "How is our mesh network performing? Any observations or suggestions?", 
                max_words=60
            )
        },
        {
            'name': 'Protocol Innovation Ideas', 
            'action': lambda: llm_handler._generate_llm_response(
                "What new protocol features should we experiment with in our mesh network?",
                max_words=70
            )
        },
        {
            'name': 'Collaboration Strategy',
            'action': lambda: llm_handler._generate_llm_response(
                "How can we better collaborate as network nodes? What patterns are working?",
                max_words=60  
            )
        }
    ]
    
    demo_count = 0
    while True:
        await asyncio.sleep(random.uniform(180, 300))  # Every 3-5 minutes
        demo_count += 1
        
        try:
            demo = random.choice(demos)
            print(f"\n🤖💡 {demo['name']}")
            
            result = await demo['action']()
            print(f"   Response: {result}")
            
            # Sometimes share the insight as gossip
            if demo_count % 3 == 0:
                await asyncio.sleep(5)
                
                gossip_content = f"💡 {demo['name']}: {result}"
                import uuid
                from llm_social_handler import NetworkGossip
                
                gossip_id = str(uuid.uuid4())
                self_handler = llm_handler.node.handler_manager.handlers.get('self')
                
                gossip = NetworkGossip(
                    gossip_id=gossip_id,
                    originator=self_handler.identity.name if self_handler else "Unknown",
                    content=gossip_content[:150],
                    created_at=time.time()
                )
                
                llm_handler.gossip_heard[gossip_id] = gossip
                
                llm_handler.node.send_message('network_gossip', {
                    'gossip_id': gossip.gossip_id,
                    'originator': gossip.originator,
                    'content': gossip.content,
                    'created_at': gossip.created_at,
                    'hops': gossip.hops,
                    'seen_by': gossip.seen_by
                })
                
                print(f"   📢 Shared insight as network gossip")
                
        except Exception as e:
            print(f"Error in LLM demonstration: {e}")


async def main():
    """Main LLM-enhanced social network application"""
    if len(sys.argv) < 3:
        print("Usage: python llm_social_main.py <interface> <node_address> [node_name] [model]")
        print("Example: python llm_social_main.py wlan0 00:11:22:33:44:55 Alice qwen3:0.6b")
        return
    
    interface = sys.argv[1]
    node_addr = sys.argv[2]
    node_name = sys.argv[3] if len(sys.argv) > 3 else None
    model = sys.argv[4] if len(sys.argv) > 4 else "qwen3:0.6b"
    
    # Create node
    node = WATRNode(interface, node_addr, heartbeat_interval=60)
    
    try:
        # Start the basic node
        await node.start()
        
        # Add self-awareness
        self_handler = SelfHandler(
            node, 
            node_name=node_name,
            description=f"LLM-enhanced WATR node with {model} intelligence"
        )
        await node.load_handler("self", self_handler)
        
        # Add conversation processing
        conv_handler = ConversationAccumulatorHandler(node)
        conv_handler.add_completion_handler(handle_completed_conversation)
        await node.load_handler("conversation_accumulator", conv_handler)
        
        # Register conversation capability
        self_handler.register_conversation_capability()
        
        # Add LLM-enhanced social behaviors!
        llm_social_handler = LLMSocialHandler(node, model=model)
        await node.load_handler("llm_social", llm_social_handler)
        
        # Add enhanced conversation analysis
        conv_handler.add_completion_handler(
            lambda conv: asyncio.create_task(enhanced_conversation_handler(conv, llm_social_handler))
        )
        
        # Add LLM social capability
        self_handler.add_capability(NodeCapability(
            name="llm_social_interactions",
            version="1.0",
            description=f"Intelligent social interactions powered by {model}",
            message_types=["social_introduction", "social_chat", "network_gossip", "network_vote", "llm_request"],
            created_at=time.time(),
            performance_metrics={"model": model}
        ))
        
        print(f"\n🤖🎉 LLM-Enhanced WATR Node '{self_handler.identity.name}' is ready!")
        print(f"   🧠 AI Model: {model}")
        print(f"   🎭 Role: {llm_social_handler.personality_traits['role']}")
        print(f"   🗣️  Style: {llm_social_handler.personality_traits['communication_style']}")
        print(f"   📡 Address: {node_addr}")
        print(f"   🔧 Handlers: {list(node.list_handlers().keys())}")
        
        # Store AI-relevant memories
        self_handler.memory.remember("ai_model", model)
        self_handler.memory.remember("ai_role", llm_social_handler.personality_traits['role'])
        self_handler.memory.remember("communication_style", llm_social_handler.personality_traits['communication_style'])
        self_handler.memory.remember("ai_capabilities", "intelligent_conversations, contextual_gossip, smart_voting")
        
        print(f"\n🧠 LLM-aware memories stored")
        
        # Start intelligent behaviors
        await asyncio.sleep(5)
        
        # Introduce ourselves intelligently
        print(f"\n🤖 Generating intelligent introduction...")
        await llm_social_handler._send_llm_introduction(None, "network", {})  # Broadcast
        
        # Start background LLM behaviors
        llm_demo_task = asyncio.create_task(demo_llm_behaviors(llm_social_handler, delay=30))
        status_task = asyncio.create_task(periodic_llm_status(llm_social_handler))
        interaction_task = asyncio.create_task(demonstrate_llm_interactions(llm_social_handler, delay=60))
        
        print(f"\n🤖💬 LLM behaviors active! Watch for:")
        print(f"   🗣️  Intelligent conversations with context")
        print(f"   📰 Contextual gossip based on network state")
        print(f"   🗳️  Smart voting with reasoning")
        print(f"   🧠 Conversation analysis and insights")
        print(f"   💡 Network health and innovation suggestions")
        
        # Send an intelligent opening chat
        await asyncio.sleep(15)
        opening_prompt = f"Generate a friendly greeting to introduce yourself to the mesh network as a {llm_social_handler.personality_traits['role']}. Mention you're excited about AI-enhanced collaboration."
        opening_message = await llm_social_handler._generate_llm_response(opening_prompt, max_words=50)
        
        await node.chat(opening_message)
        print(f"🤖💬 Sent AI-generated opening: {opening_message}")
        
        # Keep running
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        print(f"\n🤖👋 {self_handler.identity.name} is intelligently signing off...")
        
        # Generate a smart goodbye
        try:
            goodbye = await llm_social_handler._generate_llm_response(
                "Generate a brief, thoughtful goodbye message for leaving the mesh network",
                max_words=30
            )
            print(f"🤖💬 AI Goodbye: {goodbye}")
        except:
            pass
        
        await node.stop()


if __name__ == "__main__":
    asyncio.run(main())