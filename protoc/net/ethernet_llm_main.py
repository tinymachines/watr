#!/usr/bin/env python3
"""
WATR Ethernet LLM-Enhanced Node
Ethernet-based mesh networking with LLM integration
"""

import asyncio
import sys
import random
import time
import traceback
from pathlib import Path

# Import logging setup first
from watr_logging import setup_watr_logging, WATRLoggerMixin, log_network_topology

# Import Ethernet-specific components
from watr_ethernet_node import WATREthernetNode

# Import existing handlers (they work with both WiFi and Ethernet)
from watr_handlers import ConversationAccumulatorHandler, handle_completed_conversation
from self_handler import SelfHandler, NodeCapability
from llm_social_handler import LLMSocialHandler


async def periodic_network_status(node, self_handler, llm_handler):
    """Periodic network status logging"""
    logger = logging.getLogger('watr.network.events')
    
    while True:
        await asyncio.sleep(60)  # Every minute
        
        try:
            handlers = list(node.list_handlers().keys())
            known_peers = len(self_handler.known_peers)
            
            logger.info(
                "[ETH] Network status update",
                extra={
                    'interface_type': 'ethernet',
                    'node_name': self_handler.identity.name,
                    'uptime': time.time() - self_handler.identity.birth_time,
                    'handlers': handlers,
                    'known_peers': known_peers,
                    'capabilities': len(self_handler.capabilities),
                    'active_gossip': len(llm_handler.gossip_heard),
                    'active_votes': len(llm_handler.active_votes)
                }
            )
                
        except Exception as e:
            logger.error(f"[ETH] Error in status logging: {e}", exc_info=True)


async def demo_llm_behaviors(llm_handler, delay=30):
    """Demonstrate LLM behaviors over Ethernet"""
    await asyncio.sleep(delay)
    
    print("[ETH] Starting LLM behavior demonstrations...")
    behavior_count = 0
    
    while True:
        await asyncio.sleep(random.uniform(45, 90))
        behavior_count += 1
        
        behavior = random.choice(['intelligent_gossip', 'intelligent_vote', 'network_analysis'])
        
        try:
            if behavior == 'intelligent_gossip' and behavior_count % 3 == 0:
                print("[ETH] Generating intelligent gossip...")
                await llm_handler.share_intelligent_gossip()
                
            elif behavior == 'intelligent_vote' and behavior_count % 5 == 0:
                print("[ETH] Proposing intelligent vote...")
                await llm_handler.propose_intelligent_vote()
                
            elif behavior == 'network_analysis' and behavior_count % 7 == 0:
                print("[ETH] Performing network analysis...")
                analysis = await llm_handler._generate_llm_response(
                    "Analyze our Ethernet-based mesh network. What advantages does Ethernet have over WiFi for this use case?",
                    max_words=80
                )
                print(f"[ETH] Analysis: {analysis}")
                
        except Exception as e:
            print(f"[ETH] Error in behavior {behavior}: {e}")


async def conversation_completion_handler(conversation, llm_handler):
    """Handle completed conversations with LLM analysis"""
    print(f"[ETH] Analyzing completed conversation from {conversation.src_addr}")
    
    try:
        analysis = await llm_handler.analyze_conversation(conversation.complete_text)
        print(f"[ETH] Analysis: {analysis}")
        
        # Share insights if substantial
        if len(conversation.complete_text) > 100:
            await asyncio.sleep(random.uniform(5, 15))
            gossip = f"Interesting Ethernet conversation insight: {analysis}"
            await llm_handler.share_gossip(gossip)
            
    except Exception as e:
        print(f"[ETH] Error analyzing conversation: {e}")


async def main():
    """Main application for Ethernet WATR nodes"""
    if len(sys.argv) < 2:
        print("Usage: python ethernet_llm_main.py <interface> [node_name] [model] [log_level]")
        print("Example: python ethernet_llm_main.py eth0 EthNode qwen3:0.6b INFO")
        print("\nNote: MAC address will be auto-detected from interface")
        return
    
    interface = sys.argv[1]
    node_name = sys.argv[2] if len(sys.argv) > 2 else f"EthNode-{interface}"
    model = sys.argv[3] if len(sys.argv) > 3 else "qwen3:0.6b"
    log_level = sys.argv[4] if len(sys.argv) > 4 else "INFO"
    
    # Setup logging
    loggers = setup_watr_logging(
        node_name=node_name,
        log_level=log_level,
        log_dir=f"eth_logs",
        enable_console=True,
        enable_file=True,
        enable_json=True
    )
    
    main_logger = loggers['watr.node']
    network_logger = loggers['watr.network.events']
    
    main_logger.info(
        "[ETH] WATR Ethernet Node starting",
        extra={
            'interface': interface,
            'node_name': node_name,
            'model': model,
            'protocol': 'ethernet'
        }
    )
    
    try:
        # Create Ethernet node (MAC address auto-detected)
        node = WATREthernetNode(interface, heartbeat_interval=30)
        
        # Start the node
        await node.start()
        
        main_logger.info(
            f"[ETH] Node started on {interface}",
            extra={
                'mac_address': node.get_node_addr(),
                'interface': interface
            }
        )
        
        # Add self-awareness handler
        self_handler = SelfHandler(
            node, 
            node_name=node_name,
            description=f"Ethernet-based LLM-enhanced WATR node using {model}"
        )
        await node.load_handler("self", self_handler)
        
        # Add conversation handler
        conv_handler = ConversationAccumulatorHandler(node)
        conv_handler.add_completion_handler(handle_completed_conversation)
        await node.load_handler("conversation_accumulator", conv_handler)
        
        # Register conversation capability
        self_handler.register_conversation_capability()
        
        # Add LLM social handler
        llm_handler = LLMSocialHandler(node, model=model)
        await node.load_handler("llm_social", llm_handler)
        
        # Enhanced conversation completion
        conv_handler.add_completion_handler(
            lambda conv: asyncio.create_task(conversation_completion_handler(conv, llm_handler))
        )
        
        # Add Ethernet-specific capability
        self_handler.add_capability(NodeCapability(
            name="ethernet_communication",
            version="1.0",
            description="High-speed, reliable Ethernet-based mesh communication",
            message_types=["all"],
            created_at=time.time(),
            performance_metrics={"protocol": "802.3", "reliability": "high"}
        ))
        
        # Add LLM capability
        self_handler.add_capability(NodeCapability(
            name="llm_ethernet_intelligence",
            version="1.0", 
            description=f"Intelligent interactions over Ethernet using {model}",
            message_types=["social_introduction", "social_chat", "network_gossip", "network_vote"],
            created_at=time.time(),
            performance_metrics={"model": model}
        ))
        
        network_logger.info(
            f"[ETH] WATR Ethernet Node '{self_handler.identity.name}' is online",
            extra={
                'node_name': self_handler.identity.name,
                'mac_address': node.get_node_addr(),
                'model': model,
                'handlers': list(node.list_handlers().keys())
            }
        )
        
        # Store initial memories
        self_handler.memory.remember("protocol", "ethernet")
        self_handler.memory.remember("ai_model", model)
        self_handler.memory.remember("interface", interface)
        self_handler.memory.remember("advantages", "reliability, speed, no interference")
        
        # Initial introduction after short delay
        await asyncio.sleep(3)
        await llm_handler._send_llm_introduction(
            None, 
            "Ethernet network",
            {"medium": "wired", "reliability": "high"}
        )
        
        # Start background tasks
        demo_task = asyncio.create_task(demo_llm_behaviors(llm_handler))
        status_task = asyncio.create_task(periodic_network_status(node, self_handler, llm_handler))
        
        print(f"\n🔌🤖 WATR Ethernet Node '{self_handler.identity.name}' ready!")
        print(f"   📊 Interface: {interface}")
        print(f"   🏷️  MAC: {node.get_node_addr()}")
        print(f"   🧠 Model: {model}")
        print(f"   📁 Logs: eth_logs/")
        print(f"   ⚡ Advantages: More reliable than WiFi, no interference!")
        
        # Opening message
        await asyncio.sleep(5)
        opening = await llm_handler._generate_llm_response(
            f"Introduce yourself as an Ethernet-based mesh node. Mention the benefits of wired networking.",
            max_words=40
        )
        await node.chat(opening)
        
        # Keep running
        while True:
            await asyncio.sleep(300)  # Status every 5 minutes
            
            network_logger.info(
                f"[ETH] Node health check",
                extra={
                    'uptime': time.time() - self_handler.identity.birth_time,
                    'known_peers': len(self_handler.known_peers),
                    'status': 'healthy'
                }
            )
            
    except KeyboardInterrupt:
        print(f"\n[ETH] Shutting down {node_name}...")
        
        # Generate goodbye
        try:
            if 'llm_handler' in locals():
                goodbye = await llm_handler._generate_llm_response(
                    "Say goodbye as an Ethernet node leaving the network", 
                    max_words=20
                )
                print(f"[ETH] 🔌💬 {goodbye}")
        except:
            pass
        
        await node.stop()
        print("[ETH] Shutdown complete")
        
    except Exception as e:
        print(f"[ETH] Fatal error: {e}")
        traceback.print_exc()
        
        if 'node' in locals():
            await node.stop()


if __name__ == "__main__":
    # Import logging after setup
    import logging
    asyncio.run(main())
