#!/usr/bin/env python3
"""
Fully-Logged LLM-Enhanced Social WATR Network
Comprehensive logging of all network activities, interactions, and behaviors
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


class LoggedLLMSocialHandler(LLMSocialHandler, WATRLoggerMixin):
    """LLM Social Handler with comprehensive logging"""
    
    def __init__(self, node: 'WATRNode', model: str = "qwen3:0.6b"):
        WATRLoggerMixin.__init__(self)
        LLMSocialHandler.__init__(self, node, model)
        
        self.logger.info(
            "LLM Social Handler initialized",
            extra={
                **self.log_extra,
                'model': model,
                'personality_role': self.personality_traits['role'],
                'communication_style': self.personality_traits['communication_style'],
                'handled_message_types': self.get_handled_message_types()
            }
        )
    
    async def handle_message(self, message):
        """Handle messages with detailed logging"""
        start_time = time.time()
        
        # Log incoming message with full content
        self.log_message_received(message, {
            'handler_type': 'llm_social',
            'personality_role': self.personality_traits['role']
        })
        
        # Log detailed message content for social interactions
        if message.message_type in ['social_chat', 'social_introduction', 'network_gossip']:
            content = message.payload.get('content', '')
            self.logger.info(
                f"Social message content: {content}",
                extra={
                    **self.log_extra,
                    'msg_type': message.message_type,
                    'full_content': content,
                    'content_length': len(content),
                    'from_peer': message.src_addr
                }
            )
        
        try:
            # Call parent handler
            await super().handle_message(message)
            
            # Log successful processing
            duration = time.time() - start_time
            self.log_performance(f"handle_{message.message_type}", duration, {
                'success': True
            })
            
        except Exception as e:
            duration = time.time() - start_time
            self.log_error(e, f"handling {message.message_type}", {
                'duration': duration,
                'message_payload': message.payload
            })
            
            # Log the error but don't crash
            self.logger.error(
                f"Failed to handle {message.message_type}: {e}",
                extra={
                    **self.log_extra,
                    'msg_type': message.message_type,
                    'error_type': type(e).__name__,
                    'duration': duration
                },
                exc_info=True
            )
    
    async def _send_llm_chat_response(self, target_addr: str, peer_name: str, content: str, peer_id: str):
        """Send LLM chat response with detailed logging"""
        start_time = time.time()
        
        self.logger.info(
            f"Generating LLM chat response to {peer_name}",
            extra={
                **self.log_extra,
                'target_addr': target_addr,
                'peer_name': peer_name,
                'peer_id': peer_id,
                'conversation_context_length': len(self.conversation_context.get(peer_id, [])),
                'incoming_content_length': len(content)
            }
        )
        
        try:
            # Call parent method
            await super()._send_llm_chat_response(target_addr, peer_name, content, peer_id)
            
            duration = time.time() - start_time
            self.log_performance("llm_chat_response_generation", duration, {
                'target': peer_name,
                'success': True
            })
            
        except Exception as e:
            duration = time.time() - start_time
            self.log_error(e, "generating LLM chat response", {
                'target': peer_name,
                'duration': duration
            })
    
    async def generate_intelligent_gossip(self):
        """Generate gossip with logging"""
        start_time = time.time()
        
        self.logger.info(
            "Generating intelligent gossip",
            extra={
                **self.log_extra,
                'personality_role': self.personality_traits['role'],
                'network_context': 'gathering'
            }
        )
        
        try:
            result = await super().generate_intelligent_gossip()
            
            duration = time.time() - start_time
            self.log_performance("intelligent_gossip_generation", duration)
            
            self.logger.info(
                f"Generated intelligent gossip",
                extra={
                    **self.log_extra,
                    'gossip_length': len(result),
                    'generation_time': duration,
                    'full_gossip_content': result,  # Log full content
                    'event_type': 'gossip_generated'
                }
            )
            
            # Log gossip content separately for easy reading
            self.logger.info(
                f"GOSSIP CONTENT: {result}",
                extra={
                    **self.log_extra,
                    'event_type': 'gossip_content_detail',
                    'gossip_text': result,
                    'personality_role': self.personality_traits['role']
                }
            )
            
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            self.log_error(e, "generating intelligent gossip", {'duration': duration})
            return "Network collaboration is fascinating!"
    
    async def _generate_llm_response(self, prompt: str, max_words: int = 100) -> str:
        """Generate LLM response with detailed logging"""
        start_time = time.time()
        
        self.logger.info(
            f"LLM request started",
            extra={
                **self.log_extra,
                'model': self.model,
                'prompt_length': len(prompt),
                'max_words': max_words,
                'full_prompt': prompt  # Log the complete prompt
            }
        )
        
        try:
            response = await super()._generate_llm_response(prompt, max_words)
            
            duration = time.time() - start_time
            
            # Log the complete interaction with full content
            self.logger.info(
                f"LLM Response Generated",
                extra={
                    **self.log_extra,
                    'model': self.model,
                    'prompt_length': len(prompt),
                    'response_length': len(response),
                    'duration_s': duration,
                    'max_words': max_words,
                    'actual_words': len(response.split()),
                    'full_prompt': prompt,
                    'full_response': response  # Log the complete response
                }
            )
            
            # Also use the structured LLM interaction logger
            self.log_llm_interaction(prompt, response, self.model, duration, {
                'max_words': max_words,
                'actual_words': len(response.split())
            })
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            self.log_error(e, "LLM response generation", {
                'model': self.model,
                'duration': duration,
                'prompt_length': len(prompt),
                'full_prompt': prompt
            })
            
            # Return fallback
            return "That's interesting! Tell me more."


class LoggedConversationHandler(ConversationAccumulatorHandler, WATRLoggerMixin):
    """Conversation handler with logging"""
    
    def __init__(self, node, conversation_timeout=420.0):
        WATRLoggerMixin.__init__(self)
        ConversationAccumulatorHandler.__init__(self, node, conversation_timeout)
        
        self.logger.info(
            "Conversation Accumulator Handler initialized",
            extra={
                **self.log_extra,
                'conversation_timeout': conversation_timeout,
                'handled_message_types': self.get_handled_message_types()
            }
        )
    
    async def handle_message(self, message):
        """Handle conversation messages with logging"""
        # Log the message
        self.log_message_received(message, {'handler_type': 'conversation_accumulator'})
        
        # Track conversation state
        cid = message.payload.get('cid')
        seg = message.payload.get('seg', 0)
        text = message.payload.get('text')
        
        if cid:
            self.logger.info(
                f"Processing conversation segment",
                extra={
                    **self.log_extra,
                    'conversation_id': cid,
                    'segment': seg,
                    'is_terminator': text is None,
                    'text_length': len(text) if text else 0,
                    'segment_text': text,  # Log the actual segment content
                    'segment_type': type(text).__name__,  # Debug: log the type
                    'active_conversations': len(self.active_conversations)
                }
            )
            
            # Log segment content for easier debugging with type information
            if text is not None:
                self.logger.info(
                    f"Conversation segment content: {text}",
                    extra={
                        **self.log_extra,
                        'conversation_id': cid,
                        'segment': seg,
                        'full_segment_text': text,
                        'segment_value_type': type(text).__name__,
                        'segment_repr': repr(text)  # This will show quotes for strings, etc.
                    }
                )
            else:
                self.logger.info(
                    f"Conversation terminator received",
                    extra={
                        **self.log_extra,
                        'conversation_id': cid,
                        'segment': seg,
                        'is_terminator': True
                    }
                )
        
        # Call parent handler
        await super().handle_message(message)
    
    async def _complete_conversation(self, cid: str):
        """Complete conversation with logging"""
        if cid not in self.active_conversations:
            return
        
        conversation = self.active_conversations[cid]
        segment_count = len(conversation['segments'])
        duration = time.time() - conversation['start_time']
        
        # Build complete conversation text for logging - safely convert all segments to strings
        try:
            # Convert all segments to strings to handle any type mismatches
            string_segments = [str(segment) for segment in conversation['segments']]
            complete_text = ''.join(string_segments)
        except Exception as e:
            self.logger.error(
                f"Error building conversation text: {e}",
                extra={
                    **self.log_extra,
                    'conversation_id': cid,
                    'segments_types': [type(seg).__name__ for seg in conversation['segments']],
                    'segments_raw': conversation['segments']
                }
            )
            complete_text = f"[Error reconstructing conversation: {e}]"
        
        self.logger.info(
            f"Completing conversation {cid[:8]}",
            extra={
                **self.log_extra,
                'conversation_id': cid,
                'segment_count': segment_count,
                'duration': duration,
                'src_addr': conversation['src_addr'],
                'complete_conversation_text': complete_text,  # Log full conversation
                'conversation_length': len(complete_text),
                'word_count': len(complete_text.split()),
                'segments_debug': conversation['segments']  # Debug info
            }
        )
        
        # Log the complete conversation content separately for readability
        self.logger.info(
            f"COMPLETE CONVERSATION [{cid[:8]}]: {complete_text}",
            extra={
                **self.log_extra,
                'conversation_id': cid,
                'event_type': 'complete_conversation_content',
                'full_text': complete_text,
                'src_addr': conversation['src_addr']
            }
        )
        
        # Call parent method
        await super()._complete_conversation(cid)
        
        # Log completion
        self.log_network_event(
            'conversation_completed',
            f"Conversation from {conversation['src_addr']} completed with {segment_count} segments in {duration:.1f}s: {complete_text[:100]}{'...' if len(complete_text) > 100 else ''}",
            {
                'conversation_id': cid,
                'segment_count': segment_count,
                'duration': duration,
                'src_addr': conversation['src_addr'],
                'complete_text': complete_text,
                'conversation_preview': complete_text[:200]
            }
        )


class LoggedSelfHandler(SelfHandler, WATRLoggerMixin):
    """Self handler with comprehensive logging"""
    
    def __init__(self, node, node_name=None, description=None):
        WATRLoggerMixin.__init__(self)
        SelfHandler.__init__(self, node, node_name, description)
        
        self.logger.info(
            "Self Handler initialized",
            extra={
                **self.log_extra,
                'node_name': self.identity.name,
                'node_id': self.identity.node_id,
                'description': self.identity.description,
                'birth_time': self.identity.birth_time,
                'initial_capabilities': len(self.capabilities)
            }
        )
    
    def add_capability(self, capability):
        """Add capability with logging"""
        old_cap_count = len(self.capabilities)
        
        super().add_capability(capability)
        
        self.logger.info(
            f"Capability added: {capability.name}",
            extra={
                **self.log_extra,
                'capability_name': capability.name,
                'capability_version': capability.version,
                'capability_description': capability.description,
                'message_types': capability.message_types,
                'total_capabilities': len(self.capabilities)
            }
        )
        
        self.log_network_event(
            'capability_added',
            f"Node {self.identity.name} gained capability: {capability.name}",
            {
                'capability_name': capability.name,
                'node_name': self.identity.name,
                'total_capabilities': len(self.capabilities)
            }
        )
    
    async def _handle_self_response(self, message):
        """Handle self responses with logging"""
        node_id = message.payload.get('node_id')
        identity = message.payload.get('identity', {})
        capabilities = message.payload.get('capabilities', {})
        
        self.logger.info(
            f"Processing self response from peer",
            extra={
                **self.log_extra,
                'peer_node_id': node_id,
                'peer_name': identity.get('name', 'Unknown'),
                'peer_capabilities': len(capabilities),
                'known_peers_before': len(self.known_peers)
            }
        )
        
        # Call parent method
        await super()._handle_self_response(message)
        
        self.log_network_event(
            'peer_discovered',
            f"Discovered peer {identity.get('name', 'Unknown')} with {len(capabilities)} capabilities",
            {
                'peer_node_id': node_id,
                'peer_name': identity.get('name', 'Unknown'),
                'peer_capabilities': list(capabilities.keys()),
                'total_known_peers': len(self.known_peers)
            }
        )
    
    def memory_remember(self, key: str, value):
        """Remember with logging"""
        self.memory.remember(key, value)
        
        self.logger.debug(
            f"Memory stored: {key}",
            extra={
                **self.log_extra,
                'memory_key': key,
                'memory_type': type(value).__name__,
                'total_memories': len(self.memory.memories)
            }
        )


async def demo_llm_behaviors_logged(llm_social_handler, delay=45):
    """Logged version of LLM behavior demo"""
    logger = llm_social_handler.logger
    
    await asyncio.sleep(delay)
    
    logger.info(
        "Starting LLM behavior demonstrations",
        extra={
            **llm_social_handler.log_extra,
            'demo_delay': delay,
            'personality_role': llm_social_handler.personality_traits['role']
        }
    )
    
    behavior_count = 0
    
    while True:
        await asyncio.sleep(random.uniform(60, 120))
        behavior_count += 1
        
        behavior = random.choice(['intelligent_gossip', 'intelligent_vote', 'network_analysis'])
        
        logger.debug(
            f"Executing behavior demonstration: {behavior}",
            extra={
                **llm_social_handler.log_extra,
                'behavior_type': behavior,
                'behavior_count': behavior_count
            }
        )
        
        try:
            if behavior == 'intelligent_gossip' and behavior_count % 3 == 0:
                logger.info("Generating intelligent gossip for network")
                await llm_social_handler.share_intelligent_gossip()
                
            elif behavior == 'intelligent_vote' and behavior_count % 5 == 0:
                logger.info("Generating intelligent vote for network")
                await llm_social_handler.propose_intelligent_vote()
                
            elif behavior == 'network_analysis' and behavior_count % 7 == 0:
                logger.info("Performing network analysis")
                start_time = time.time()
                
                analysis = await llm_social_handler._generate_llm_response(
                    "Analyze the current state of our mesh network. What patterns do you notice?",
                    max_words=80
                )
                
                duration = time.time() - start_time
                logger.info(
                    f"Network analysis completed: {analysis[:50]}...",
                    extra={
                        **llm_social_handler.log_extra,
                        'analysis_length': len(analysis),
                        'generation_time': duration
                    }
                )
                
                await asyncio.sleep(2)
                await llm_social_handler.share_intelligent_gossip()
                
        except Exception as e:
            logger.error(
                f"Error in behavior {behavior}: {e}",
                extra={
                    **llm_social_handler.log_extra,
                    'behavior_type': behavior,
                    'behavior_count': behavior_count,
                    'error_type': type(e).__name__
                },
                exc_info=True
            )


async def logged_conversation_handler(conversation, llm_handler):
    """Fully logged conversation completion handler"""
    logger = logging.getLogger('watr.conversation')
    
    logger.info(
        "Conversation completion analysis started",
        extra={
            'conversation_id': conversation.cid,
            'src_addr': conversation.src_addr,
            'segment_count': len(conversation.segments),
            'total_length': len(conversation.complete_text),
            'duration': conversation.end_time - conversation.start_time,
            'words': len(conversation.complete_text.split()),
            'handler_type': 'llm_enhanced',
            'complete_conversation_text': conversation.complete_text  # Log full text
        }
    )
    
    # Log the conversation content in a dedicated log entry
    logger.info(
        f"CONVERSATION CONTENT [{conversation.cid[:8]}]: {conversation.complete_text}",
        extra={
            'conversation_id': conversation.cid,
            'event_type': 'conversation_analysis',
            'full_conversation': conversation.complete_text,
            'src_addr': conversation.src_addr,
            'word_count': len(conversation.complete_text.split())
        }
    )
    
    try:
        # Use LLM to analyze
        start_time = time.time()
        analysis_prompt = f"Analyze this conversation and provide insights: {conversation.complete_text}"
        analysis = await llm_handler.analyze_conversation(conversation.complete_text)
        analysis_time = time.time() - start_time
        
        logger.info(
            f"LLM conversation analysis completed",
            extra={
                'conversation_id': conversation.cid,
                'analysis_text': analysis,
                'analysis_time': analysis_time,
                'analysis_length': len(analysis),
                'original_conversation': conversation.complete_text,
                'analysis_prompt': analysis_prompt
            }
        )
        
        # Log the analysis result separately for clarity
        logger.info(
            f"CONVERSATION ANALYSIS [{conversation.cid[:8]}]: {analysis}",
            extra={
                'conversation_id': conversation.cid,
                'event_type': 'llm_analysis_result',
                'full_analysis': analysis,
                'original_text': conversation.complete_text
            }
        )
        
        # Share insights if substantial
        if len(conversation.complete_text) > 100:
            logger.info(
                "Conversation substantial enough to share insights",
                extra={
                    'conversation_id': conversation.cid,
                    'text_length': len(conversation.complete_text),
                    'sharing_threshold': 100,
                    'will_create_gossip': True
                }
            )
            
            # Create and share gossip about the conversation
            await asyncio.sleep(random.uniform(10, 20))
            
            gossip_content = f"Interesting conversation insight: {analysis}"
            
            # Log the gossip creation with full content
            logger.info(
                f"Creating gossip from conversation analysis: {gossip_content}",
                extra={
                    'conversation_id': conversation.cid,
                    'gossip_content': gossip_content,
                    'gossip_length': len(gossip_content),
                    'original_conversation': conversation.complete_text,
                    'analysis_that_generated_gossip': analysis
                }
            )
            
    except Exception as e:
        logger.error(
            f"Error analyzing conversation {conversation.cid}: {e}",
            extra={
                'conversation_id': conversation.cid,
                'error_type': type(e).__name__,
                'conversation_text': conversation.complete_text
            },
            exc_info=True
        )


async def periodic_network_status_logging(node, self_handler, llm_handler):
    """Periodic comprehensive network status logging"""
    logger = logging.getLogger('watr.network.events')
    
    while True:
        await asyncio.sleep(60)  # Every minute
        
        try:
            # Gather comprehensive network state
            handlers = list(node.list_handlers().keys())
            known_peers = len(self_handler.known_peers)
            total_memories = len(self_handler.memory.memories)
            capabilities = len(self_handler.capabilities)
            gossip_count = len(llm_handler.gossip_heard)
            vote_count = len(llm_handler.active_votes)
            
            # Log network topology
            log_network_topology(known_peers, capabilities, gossip_count, vote_count)
            
            # Detailed status
            logger.info(
                "Periodic network status update",
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
                    'conversation_contexts': len(llm_handler.conversation_context)
                }
            )
            
            # Log memory insights
            if total_memories > 0:
                recent_memories = list(self_handler.memory.memories.keys())[-5:]
                logger.debug(
                    f"Recent memories: {recent_memories}",
                    extra={
                        'node_name': self_handler.identity.name,
                        'recent_memory_keys': recent_memories,
                        'total_memories': total_memories
                    }
                )
                
        except Exception as e:
            logger.error(
                f"Error in network status logging: {e}",
                exc_info=True
            )


async def main():
    """Fully logged main application"""
    if len(sys.argv) < 3:
        print("Usage: python logged_llm_social_main.py <interface> <node_address> [node_name] [model] [log_level]")
        print("Example: python logged_llm_social_main.py wlan0 00:11:22:33:44:55 Alice qwen3:0.6b INFO")
        return
    
    interface = sys.argv[1]
    node_addr = sys.argv[2]
    node_name = sys.argv[3] if len(sys.argv) > 3 else f"Node-{node_addr[-8:]}"
    model = sys.argv[4] if len(sys.argv) > 4 else "qwen3:0.6b"
    log_level = sys.argv[5] if len(sys.argv) > 5 else "INFO"
    
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
        "WATR Node application starting",
        extra={
            'interface': interface,
            'node_addr': node_addr,
            'node_name': node_name,
            'model': model,
            'log_level': log_level,
            'log_dir': 'logs'
        }       
    )
    
    try:
        # Create logged node components
        node = WATRNode(interface, node_addr, heartbeat_interval=60)
        
        # Start the node
        start_time = time.time()
        await node.start()
        startup_time = time.time() - start_time
        
        main_logger.info(
            f"Node started successfully",
            extra={
                'startup_time': startup_time,
                'node_addr': node_addr,
                'heartbeat_interval': 60
            }
        )
        
        # Add logged self-awareness
        self_handler = LoggedSelfHandler(
            node, 
            node_name=node_name,
            description=f"Fully-logged LLM-enhanced WATR node with {model}"
        )
        await node.load_handler("self", self_handler)
        
        # Add logged conversation processing
        conv_handler = LoggedConversationHandler(node)
        conv_handler.add_completion_handler(handle_completed_conversation)
        await node.load_handler("conversation_accumulator", conv_handler)
        
        # Register conversation capability
        self_handler.register_conversation_capability()
        
        # Add logged LLM social behaviors
        llm_social_handler = LoggedLLMSocialHandler(node, model=model)
        await node.load_handler("llm_social", llm_social_handler)
        
        # Enhanced conversation handler with logging
        conv_handler.add_completion_handler(
            lambda conv: asyncio.create_task(logged_conversation_handler(conv, llm_social_handler))
        )
        
        # Add LLM capability
        self_handler.add_capability(NodeCapability(
            name="llm_social_interactions_logged",
            version="1.0", 
            description=f"Fully logged intelligent social interactions powered by {model}",
            message_types=["social_introduction", "social_chat", "network_gossip", "network_vote", "llm_request"],
            created_at=time.time(),
            performance_metrics={"model": model, "logging": "comprehensive"}
        ))
        
        network_logger.info(
            f"Fully-logged LLM WATR Node '{self_handler.identity.name}' is online",
            extra={
                'node_name': self_handler.identity.name,
                'node_id': self_handler.identity.node_id,
                'model': model,
                'personality_role': llm_social_handler.personality_traits['role'],
                'communication_style': llm_social_handler.personality_traits['communication_style'],
                'handlers': list(node.list_handlers().keys()),
                'capabilities': list(self_handler.capabilities.keys()),
                'startup_complete': True
            }
        )
        
        # Store comprehensive memories
        self_handler.memory_remember("ai_model", model)
        self_handler.memory_remember("logging_enabled", True)
        self_handler.memory_remember("log_level", log_level)
        self_handler.memory_remember("startup_time", time.time())
        self_handler.memory_remember("personality_role", llm_social_handler.personality_traits['role'])
        
        main_logger.info("Initial memories stored with logging")
        
        # Start logged background behaviors
        await asyncio.sleep(5)
        
        # Generate and log intelligent introduction
        main_logger.info("Generating intelligent network introduction")
        intro_start = time.time()
        await llm_social_handler._send_llm_introduction(None, "network", {})
        intro_time = time.time() - intro_start
        
        main_logger.info(
            f"Network introduction sent",
            extra={'generation_time': intro_time}
        )
        
        # Start all logged background tasks
        llm_demo_task = asyncio.create_task(demo_llm_behaviors_logged(llm_social_handler, delay=30))
        status_task = asyncio.create_task(periodic_network_status_logging(node, self_handler, llm_social_handler))
        
        main_logger.info("All background tasks started with comprehensive logging")
        
        # Send logged opening message
        await asyncio.sleep(15)
        opening_prompt = f"Generate a friendly greeting as a {llm_social_handler.personality_traits['role']} joining a logged mesh network"
        opening_start = time.time()
        opening_message = await llm_social_handler._generate_llm_response(opening_prompt, max_words=50)
        opening_time = time.time() - opening_start
        
        main_logger.info(
            f"Generated opening message",
            extra={
                'opening_message': opening_message,  # FIXED: Changed from 'message' to 'opening_message'
                'generation_time': opening_time,
                'personality_role': llm_social_handler.personality_traits['role']
            }
        )
        
        await node.chat(opening_message)
        
        network_logger.info(
            f"Node {self_handler.identity.name} fully operational with comprehensive logging",
            extra={
                'node_name': self_handler.identity.name,
                'total_startup_time': time.time() - start_time,
                'logging_comprehensive': True,
                'ai_model': model,
                'ready_for_collaboration': True
            }
        )
        
        print(f"\n🤖📊 Fully-Logged WATR Node '{self_handler.identity.name}' ready!")
        print(f"   📁 Logs in: logs/")
        print(f"   📊 Log Level: {log_level}")
        print(f"   🧠 AI Model: {model}")
        print(f"   🎭 Role: {llm_social_handler.personality_traits['role']}")
        print(f"   📈 All interactions, LLM calls, and network events are being logged!")
        
        # Keep running with periodic status
        while True:
            await asyncio.sleep(300)  # Every 5 minutes
            
            # Log major status update
            network_logger.info(
                f"Node {self_handler.identity.name} status check",
                extra={
                    'uptime': time.time() - self_handler.identity.birth_time,
                    'known_peers': len(self_handler.known_peers),
                    'total_memories': len(self_handler.memory.memories),
                    'gossip_heard': len(llm_social_handler.gossip_heard),
                    'active_votes': len(llm_social_handler.active_votes),
                    'conversation_contexts': len(llm_social_handler.conversation_context),
                    'status': 'healthy'
                }
            )
            
    except KeyboardInterrupt:
        main_logger.info(
            f"Node {node_name} shutdown initiated by user",
            extra={'shutdown_reason': 'keyboard_interrupt'}
        )
        
        print(f"\n🛑 Shutting down logged node {node_name}...")
        
        # Generate intelligent goodbye if possible
        try:
            if 'llm_social_handler' in locals():
                goodbye = await llm_social_handler._generate_llm_response(
                    "Generate a brief goodbye for leaving the mesh network", max_words=20
                )
                mai_logger.info(f"AI-generated goodbye: {goodbye}")
                print(f"🤖💬 {goodbye}")
        except:
            pass
        
        await node.stop()
        
        network_logger.info(
            f"Node {node_name} shutdown complete",
            extra={
                'shutdown_clean': True,
                'final_uptime': time.time() - start_time if 'start_time' in locals() else 0
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


if __name__ == "__main__":
    # Import logging after setup
    import logging
    asyncio.run(main())
