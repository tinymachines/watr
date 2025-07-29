#!/usr/bin/env python3
"""
Fully-Logged WiFi Geometry-Aware WATR Node
Comprehensive logging of WiFi-based geometric discovery and LLM-enhanced analysis
"""

import asyncio
import sys
import random
import time
import traceback
from pathlib import Path

# Import logging setup first
from watr_logging import setup_watr_logging, WATRLoggerMixin, log_network_topology, log_protocol_evolution

from watr_node import WATRNode
from watr_handlers import ConversationAccumulatorHandler, handle_completed_conversation
from self_handler import SelfHandler, NodeCapability
from llm_social_handler import LLMSocialHandler
from social_handler import NetworkGossip
from wifi_geometry_handler import LoggedWiFiGeometryHandler, GeometryEstimate
from chunked_message_handler import ChunkedMessageHandler


class GeometryAwareLLMHandler(LLMSocialHandler, WATRLoggerMixin):
    """LLM handler enhanced with geometric awareness"""
    
    def __init__(self, node: 'WATRNode', model: str = "qwen3:0.6b", wifi_handler=None):
        WATRLoggerMixin.__init__(self)
        LLMSocialHandler.__init__(self, node, model)
        
        self.wifi_handler = wifi_handler
        self.last_geometry_gossip = 0
        
        self.logger.info(
            "Geometry-Aware LLM Handler initialized",
            extra={
                **self.log_extra,
                'model': model,
                'has_wifi_handler': wifi_handler is not None
            }
        )
    
    async def share_gossip(self, content: str):
        """Share gossip with the network (from SocialHandler)"""
        import uuid
        from social_handler import NetworkGossip
        
        gossip_id = str(uuid.uuid4())
        self_handler = self.node.handler_manager.handlers.get('self')
        
        gossip = NetworkGossip(
            gossip_id=gossip_id,
            originator=self_handler.identity.name if self_handler else "Unknown",
            content=content,
            created_at=time.time()
        )
        
        self.gossip_heard[gossip_id] = gossip
        
        self.node.send_message('network_gossip', {
            'gossip_id': gossip.gossip_id,
            'originator': gossip.originator,
            'content': gossip.content,
            'created_at': gossip.created_at,
            'hops': gossip.hops,
            'seen_by': gossip.seen_by
        })
        
        self.logger.info(
            f"Shared gossip: {content[:50]}...",
            extra={
                **self.log_extra,
                'gossip_id': gossip_id,
                'content_length': len(content),
                'event_type': 'gossip_shared'
            }
        )
    
    async def generate_geometry_aware_gossip(self) -> str:
        """Generate gossip that includes geometric insights"""
        try:
            geometry_context = ""
            
            if self.wifi_handler and self.wifi_handler.last_geometry:
                geometry = self.wifi_handler.last_geometry
                scan_summary = self.wifi_handler.get_scan_summary()
                
                geometry_context = f"""
Current network geometry: {len(geometry.clusters)} physical clusters detected.
WiFi scan shows {scan_summary['unique_networks']} unique networks from {scan_summary['peer_count']} peers.
My location hint: {self.wifi_handler.location_hint or 'Unknown'}.
Geometry confidence: {geometry.confidence:.2f}.
"""
                
                # Find if we're in a cluster
                my_cluster_size = 0
                for cluster in geometry.clusters:
                    if self.node.protocol.src_addr in cluster:
                        my_cluster_size = len(cluster)
                        break
                
                if my_cluster_size > 1:
                    geometry_context += f"I'm in a cluster with {my_cluster_size-1} other nodes nearby!"
            
            prompt = f"""Generate interesting gossip about our mesh network's physical distribution.
{geometry_context}

Create gossip that:
- Mentions something about physical location or network geometry
- Shows awareness of distributed nature of the network
- Is relevant to a WiFi mesh network
- Reflects your personality as a {self.personality_traits['role']}

Keep it under 80 words and conversational."""
            
            return await self._generate_llm_response(prompt, max_words=80)
            
        except Exception as e:
            self.log_error(e, "generating geometry-aware gossip")
            return await self.generate_intelligent_gossip()  # Fallback to regular gossip
    
    async def analyze_geometry_implications(self, geometry: GeometryEstimate) -> str:
        """Use LLM to analyze implications of current geometry"""
        try:
            # Prepare geometry summary
            node_count = len(set().union(*geometry.clusters)) if geometry.clusters else 0
            cluster_sizes = [len(c) for c in geometry.clusters]
            
            prompt = f"""Analyze the physical geometry of our mesh network:

- {len(geometry.clusters)} distinct physical locations/clusters
- Cluster sizes: {cluster_sizes}
- Total nodes: {node_count}
- Confidence: {geometry.confidence:.2f}

As a {self.personality_traits['role']}, what interesting observations or implications do you see?
Consider: emergency communication, data redundancy, network resilience, or collaborative sensing.

Keep response under 100 words and conversational."""
            
            analysis = await self._generate_llm_response(prompt, max_words=100)
            
            self.logger.info(
                "LLM geometry analysis completed",
                extra={
                    **self.log_extra,
                    'cluster_count': len(geometry.clusters),
                    'confidence': geometry.confidence,
                    'analysis_preview': analysis[:100]
                }
            )
            
            return analysis
            
        except Exception as e:
            self.log_error(e, "analyzing geometry implications")
            return "The network's physical distribution is fascinating!"


async def geometry_update_handler(geometry: GeometryEstimate, llm_handler: GeometryAwareLLMHandler, logger):
    """Handle geometry updates with LLM analysis"""
    logger.info(
        "Geometry update received",
        extra={
            'confidence': geometry.confidence,
            'cluster_count': len(geometry.clusters),
            'event_type': 'geometry_update_callback'
        }
    )
    
    # Only analyze significant updates
    if geometry.confidence > 0.5:
        try:
            # Get LLM analysis
            analysis = await llm_handler.analyze_geometry_implications(geometry)
            
            logger.info(
                f"GEOMETRY ANALYSIS: {analysis}",
                extra={
                    'event_type': 'llm_geometry_analysis',
                    'full_analysis': analysis,
                    'confidence': geometry.confidence
                }
            )
            
            # Share as gossip if interesting enough
            if time.time() - llm_handler.last_geometry_gossip > 600:  # Every 10 minutes max
                await asyncio.sleep(random.uniform(5, 15))
                gossip = f"Geometry insight: {analysis[:80]}..."
                await llm_handler.share_gossip(gossip)
                llm_handler.last_geometry_gossip = time.time()
                
        except Exception as e:
            logger.error(
                f"Error in geometry analysis: {e}",
                exc_info=True
            )


async def periodic_network_status_with_geometry(node, self_handler, llm_handler, wifi_handler):
    """Enhanced periodic status including geometry information"""
    logger = logging.getLogger('watr.network.events')
    
    while True:
        await asyncio.sleep(60)  # Every minute
        
        try:
            # Standard status
            handlers = list(node.list_handlers().keys())
            known_peers = len(self_handler.known_peers)
            total_memories = len(self_handler.memory.memories)
            capabilities = len(self_handler.capabilities)
            gossip_count = len(llm_handler.gossip_heard)
            vote_count = len(llm_handler.active_votes)
            
            # Geometry status
            geometry_info = {}
            if wifi_handler and wifi_handler.last_geometry:
                geometry = wifi_handler.last_geometry
                scan_summary = wifi_handler.get_scan_summary()
                
                geometry_info = {
                    'geometry_confidence': geometry.confidence,
                    'cluster_count': len(geometry.clusters),
                    'wifi_networks': scan_summary['unique_networks'],
                    'total_scans': scan_summary['total_scans']
                }
            
            # Log comprehensive status
            logger.info(
                "Periodic network status update with geometry",
                extra={
                    'node_name': self_handler.identity.name,
                    'uptime': time.time() - self_handler.identity.birth_time,
                    'handlers': handlers,
                    'known_peers': known_peers,
                    'total_memories': total_memories,
                    'capabilities': capabilities,
                    'active_gossip': gossip_count,
                    'active_votes': vote_count,
                    'personality_role': llm_handler.personality_traits['role'],
                    'conversation_contexts': len(llm_handler.conversation_context),
                    **geometry_info
                }
            )
            
            # Log network topology with geometry awareness
            log_network_topology(known_peers, capabilities, gossip_count, vote_count)
                
        except Exception as e:
            logger.error(
                f"Error in network status logging: {e}",
                exc_info=True
            )


async def demo_geometry_behaviors(llm_handler, wifi_handler, delay=60):
    """Demonstrate geometry-aware behaviors"""
    await asyncio.sleep(delay)
    
    logger = llm_handler.logger
    logger.info("Starting geometry-aware behavior demonstrations")
    
    behavior_count = 0
    
    while True:
        await asyncio.sleep(random.uniform(90, 180))
        behavior_count += 1
        
        try:
            # Prioritize geometry-aware behaviors
            if wifi_handler and wifi_handler.last_geometry and wifi_handler.last_geometry.confidence > 0.4:
                behavior = random.choice(['geometry_gossip', 'location_vote', 'cluster_chat'])
            else:
                behavior = random.choice(['intelligent_gossip', 'intelligent_vote'])
            
            logger.debug(
                f"Executing geometry behavior: {behavior}",
                extra={
                    'behavior_type': behavior,
                    'behavior_count': behavior_count
                }
            )
            
            if behavior == 'geometry_gossip':
                logger.info("Generating geometry-aware gossip")
                gossip = await llm_handler.generate_geometry_aware_gossip()
                await llm_handler.share_gossip(gossip)
                
            elif behavior == 'location_vote':
                logger.info("Proposing location-aware vote")
                question = "Should nodes in the same physical cluster coordinate more closely?"
                options = ["Yes - form sub-networks", "No - stay fully distributed", "Sometimes - based on task", "Let clusters self-organize"]
                
                vote_id = str(uuid.uuid4())
                await llm_handler.node.send_message('network_vote', {
                    'vote_id': vote_id,
                    'question': question,
                    'options': options,
                    'created_by': llm_handler.node.handler_manager.handlers['self'].identity.name,
                    'created_at': time.time(),
                    'ends_at': time.time() + 300
                })
                
            elif behavior == 'cluster_chat':
                # Send a message to nodes in the same cluster
                geometry = wifi_handler.last_geometry
                my_cluster = None
                
                for cluster in geometry.clusters:
                    if llm_handler.node.protocol.src_addr in cluster:
                        my_cluster = cluster
                        break
                
                if my_cluster and len(my_cluster) > 1:
                    logger.info("Sending cluster-local chat")
                    msg = await llm_handler._generate_llm_response(
                        "Send a friendly message to nodes that are physically near you",
                        max_words=30
                    )
                    
                    for peer in my_cluster:
                        if peer != llm_handler.node.protocol.src_addr:
                            await llm_handler.node.send_message('social_chat', {
                                'sender_id': llm_handler.node.handler_manager.handlers['self'].identity.node_id,
                                'sender_name': llm_handler.node.handler_manager.handlers['self'].identity.name,
                                'content': f"[Cluster message] {msg}",
                                'timestamp': time.time()
                            }, dst_addr=peer)
            
            else:
                # Fallback to standard behaviors
                if behavior == 'intelligent_gossip':
                    await llm_handler.share_intelligent_gossip()
                else:
                    await llm_handler.propose_intelligent_vote()
                    
        except Exception as e:
            logger.error(
                f"Error in geometry behavior {behavior}: {e}",
                extra={
                    'behavior_type': behavior,
                    'behavior_count': behavior_count,
                    'error_type': type(e).__name__
                },
                exc_info=True
            )


async def main():
    """Fully logged main application with WiFi geometry"""
    if len(sys.argv) < 3:
        print("Usage: python logged_wifi_geometry_main.py <interface> <node_address> [node_name] [location] [model] [log_level]")
        print("Example: python logged_wifi_geometry_main.py wlan0 00:11:22:33:44:55 Alice 'Building-A-Floor-2' qwen3:0.6b INFO")
        return
    
    interface = sys.argv[1]
    node_addr = sys.argv[2]
    node_name = sys.argv[3] if len(sys.argv) > 3 else f"GeoNode-{node_addr[-8:]}"
    location_hint = sys.argv[4] if len(sys.argv) > 4 else None
    model = sys.argv[5] if len(sys.argv) > 5 else "qwen3:0.6b"
    log_level = sys.argv[6] if len(sys.argv) > 6 else "INFO"
    
    # Setup comprehensive logging FIRST
    loggers = setup_watr_logging(
        node_name=node_name,
        log_level=log_level,
        log_dir=f"logs",
        enable_console=True,
        enable_file=True,
        enable_json=True
    )
    
    # Get main loggers
    main_logger = loggers['watr.node']
    network_logger = loggers['watr.network.events']
    
    main_logger.info(
        "WATR Geometry-Aware Node application starting",
        extra={
            'interface': interface,
            'node_addr': node_addr,
            'node_name': node_name,
            'location_hint': location_hint,
            'model': model,
            'log_level': log_level,
            'log_dir': 'logs'
        }       
    )
    
    try:
        # Create node
        node = WATRNode(interface, node_addr, heartbeat_interval=120)
        
        # Start the node
        start_time = time.time()
        await node.start()
        startup_time = time.time() - start_time
        
        main_logger.info(
            f"Node started successfully",
            extra={
                'startup_time': startup_time,
                'node_addr': node_addr,
                'heartbeat_interval': 120
            }
        )
        
        # Add self-awareness handler
        self_handler = SelfHandler(
            node, 
            node_name=node_name,
            description=f"Geometry-aware LLM-enhanced WATR node at {location_hint or 'unknown location'}"
        )
        await node.load_handler("self", self_handler)
        
        # Store location in memory
        if location_hint:
            self_handler.memory.remember("location_hint", location_hint)
        
        # Add conversation handler
        conv_handler = ConversationAccumulatorHandler(node)
        conv_handler.add_completion_handler(handle_completed_conversation)
        await node.load_handler("conversation_accumulator", conv_handler)
        
        # Register conversation capability
        self_handler.register_conversation_capability()
        
        # Add chunked message handler for large payloads
        chunk_handler = ChunkedMessageHandler(node, chunk_size=1000)
        await node.load_handler("chunk_handler", chunk_handler)
        
        main_logger.info(
            "Chunked message handler loaded",
            extra={
                'chunk_size': chunk_handler.chunk_size,
                'timeout': chunk_handler.timeout
            }
        )
        
        # Add WiFi geometry handler
        wifi_handler = LoggedWiFiGeometryHandler(
            node,
            scan_interval=180,  # 3 minutes
            location_hint=location_hint,
            chunk_handler=chunk_handler  # Pass chunk handler for large scans
        )
        
        # Register wifi_scan handler with chunk handler for reassembly
        chunk_handler.register_message_handler('wifi_scan', wifi_handler._handle_wifi_scan)
        
        await node.load_handler("wifi_geometry", wifi_handler)
        
        # Add geometry-aware LLM handler
        llm_handler = GeometryAwareLLMHandler(node, model=model, wifi_handler=wifi_handler)
        await node.load_handler("geometry_llm_social", llm_handler)
        
        # Add geometry update callback
        wifi_handler.add_geometry_callback(
            lambda geom: asyncio.create_task(
                geometry_update_handler(geom, llm_handler, network_logger)
            )
        )
        
        # Save reference to main event loop for handlers
        main_loop = asyncio.get_running_loop()
        
        # Enhanced conversation handler
        def conversation_completion_wrapper(conv):
            # Schedule the async handler on the main event loop
            try:
                asyncio.run_coroutine_threadsafe(
                    logged_conversation_handler(conv, llm_handler), 
                    main_loop
                )
            except Exception as e:
                main_logger.error(f"Error scheduling conversation handler: {e}", exc_info=True)
        
        conv_handler.add_completion_handler(conversation_completion_wrapper)
        
        # Add capabilities
        self_handler.add_capability(NodeCapability(
            name="chunked_messaging",
            version="1.0",
            description="Support for chunked transmission of large messages",
            message_types=["chunk"],
            created_at=time.time(),
            performance_metrics={"chunk_size": chunk_handler.chunk_size}
        ))
        
        self_handler.add_capability(NodeCapability(
            name="wifi_geometry_discovery",
            version="1.0", 
            description="WiFi-based physical geometry discovery and clustering",
            message_types=["wifi_scan", "geometry_query", "geometry_response"],
            created_at=time.time(),
            performance_metrics={"scan_interval": wifi_handler.scan_interval}
        ))
        
        self_handler.add_capability(NodeCapability(
            name="geometry_aware_llm",
            version="1.0", 
            description=f"Location-aware AI interactions using {model}",
            message_types=["social_introduction", "social_chat", "network_gossip", "network_vote"],
            created_at=time.time(),
            performance_metrics={"model": model, "location": location_hint or "unknown"}
        ))
        
        network_logger.info(
            f"Geometry-Aware WATR Node '{self_handler.identity.name}' is online",
            extra={
                'node_name': self_handler.identity.name,
                'node_id': self_handler.identity.node_id,
                'location_hint': location_hint,
                'model': model,
                'personality_role': llm_handler.personality_traits['role'],
                'handlers': list(node.list_handlers().keys()),
                'capabilities': list(self_handler.capabilities.keys()),
                'startup_complete': True
            }
        )
        
        # Store initial memories
        self_handler.memory.remember("ai_model", model)
        self_handler.memory.remember("geometry_enabled", True)
        self_handler.memory.remember("scan_interval", wifi_handler.scan_interval)
        self_handler.memory.remember("startup_time", time.time())
        
        # Initial WiFi scan
        await asyncio.sleep(2)
        main_logger.info("Performing initial WiFi scan")
        networks = await wifi_handler._scan_wifi()
        
        main_logger.info(
            f"Initial WiFi scan complete",
            extra={
                'network_count': len(networks),
                'top_networks': [
                    {'ssid': n.ssid, 'signal': n.signal_strength} 
                    for n in networks[:5]
                ]
            }
        )
        
        # Generate location-aware introduction
        await asyncio.sleep(5)
        intro_prompt = f"Introduce yourself as a mesh node located at '{location_hint or 'an unknown location'}' with WiFi scanning capabilities"
        intro = await llm_handler._generate_llm_response(intro_prompt, max_words=50)
        await llm_handler._send_llm_introduction(None, "geometry-aware network", {"location": location_hint})
        
        # Start background tasks
        geometry_demo_task = asyncio.create_task(
            demo_geometry_behaviors(llm_handler, wifi_handler, delay=45)
        )
        status_task = asyncio.create_task(
            periodic_network_status_with_geometry(node, self_handler, llm_handler, wifi_handler)
        )
        
        main_logger.info("All geometry-aware background tasks started")
        
        # Send opening message
        await asyncio.sleep(10)
        opening = await llm_handler._generate_llm_response(
            f"Greet the network as a {llm_handler.personality_traits['role']} located at {location_hint or 'somewhere interesting'}",
            max_words=50
        )
        await node.chat(opening)
        
        network_logger.info(
            f"Node {self_handler.identity.name} fully operational with geometry awareness",
            extra={
                'node_name': self_handler.identity.name,
                'total_startup_time': time.time() - start_time,
                'location': location_hint,
                'geometry_enabled': True,
                'ai_model': model
            }
        )
        
        print(f"\n🌐📍 Geometry-Aware WATR Node '{self_handler.identity.name}' ready!")
        print(f"   📁 Logs in: logs/")
        print(f"   📊 Log Level: {log_level}")
        print(f"   🧠 AI Model: {model}")
        print(f"   🎭 Role: {llm_handler.personality_traits['role']}")
        print(f"   📍 Location: {location_hint or 'Not specified'}")
        print(f"   📡 WiFi scanning every {wifi_handler.scan_interval} seconds")
        print(f"   🗺️  Geometry discovery enabled - start nodes in different locations!")
        
        # Keep running with periodic status
        while True:
            await asyncio.sleep(300)  # Every 5 minutes
            
            # Log major status update
            geometry_status = {}
            if wifi_handler.last_geometry:
                geometry_status = {
                    'geometry_confidence': wifi_handler.last_geometry.confidence,
                    'cluster_count': len(wifi_handler.last_geometry.clusters)
                }
            
            network_logger.info(
                f"Node {self_handler.identity.name} periodic health check",
                extra={
                    'uptime': time.time() - self_handler.identity.birth_time,
                    'known_peers': len(self_handler.known_peers),
                    'total_memories': len(self_handler.memory.memories),
                    'gossip_heard': len(llm_handler.gossip_heard),
                    'active_votes': len(llm_handler.active_votes),
                    'conversation_contexts': len(llm_handler.conversation_context),
                    'status': 'healthy',
                    **geometry_status
                }
            )
            
    except KeyboardInterrupt:
        main_logger.info(
            f"Node {node_name} shutdown initiated by user",
            extra={'shutdown_reason': 'keyboard_interrupt'}
        )
        
        print(f"\n🛑 Shutting down geometry-aware node {node_name}...")
        
        # Generate location-aware goodbye
        try:
            if 'llm_handler' in locals():
                goodbye = await llm_handler._generate_llm_response(
                    f"Say goodbye as a node leaving from {location_hint or 'your location'}", 
                    max_words=20
                )
                main_logger.info(f"Geometry-aware goodbye: {goodbye}")
                print(f"🌐💬 {goodbye}")
        except:
            pass
        
        await node.stop()
        
        network_logger.info(
            f"Node {node_name} shutdown complete",
            extra={
                'shutdown_clean': True,
                'final_uptime': time.time() - start_time if 'start_time' in locals() else 0,
                'location': location_hint
            }
        )
        
    except Exception as e:
        main_logger.error(
            f"Fatal error in node {node_name}: {e}",
            extra={'error_type': type(e).__name__},
            exc_info=True
        )
        
        print(f"💥 Fatal error: {e}")
        traceback.print_exc()
        
        if 'node' in locals():
            await node.stop()


# Import uuid for vote generation
import uuid


# Add the logged conversation handler function
async def logged_conversation_handler(conversation, llm_handler):
    """Fully logged conversation completion handler"""
    logger = logging.getLogger('watr.conversation')
    
    # Skip empty conversations
    if not conversation.complete_text or len(conversation.complete_text.strip()) == 0:
        logger.debug(
            "Skipping empty conversation",
            extra={
                'conversation_id': conversation.cid,
                'src_addr': conversation.src_addr,
                'segment_count': len(conversation.segments)
            }
        )
        return
    
    logger.info(
        "Conversation completion analysis started",
        extra={
            'conversation_id': conversation.cid,
            'src_addr': conversation.src_addr,
            'segment_count': len(conversation.segments),
            'total_length': len(conversation.complete_text),
            'duration': conversation.end_time - conversation.start_time,
            'words': len(conversation.complete_text.split()),
            'handler_type': 'geometry_aware_llm'
        }
    )
    
    try:
        # Use LLM to analyze
        start_time = time.time()
        analysis = await llm_handler.analyze_conversation(conversation.complete_text)
        analysis_time = time.time() - start_time
        
        logger.info(
            f"LLM conversation analysis completed",
            extra={
                'conversation_id': conversation.cid,
                'analysis_text': analysis,
                'analysis_time': analysis_time,
                'analysis_length': len(analysis)
            }
        )
        
        # Share insights if substantial
        if len(conversation.complete_text) > 100:
            await asyncio.sleep(random.uniform(10, 20))
            
            # Maybe include geometry context
            if llm_handler.wifi_handler and llm_handler.wifi_handler.last_geometry:
                if random.random() < 0.3:  # 30% chance
                    gossip_content = f"From {llm_handler.wifi_handler.location_hint or 'my location'}: {analysis}"
                else:
                    gossip_content = f"Interesting conversation insight: {analysis}"
            else:
                gossip_content = f"Conversation insight: {analysis}"
            
            await llm_handler.share_gossip(gossip_content)
            
    except Exception as e:
        logger.error(
            f"Error analyzing conversation {conversation.cid}: {e}",
            extra={
                'conversation_id': conversation.cid,
                'error_type': type(e).__name__
            },
            exc_info=True
        )


if __name__ == "__main__":
    # Import logging after setup
    import logging
    asyncio.run(main())