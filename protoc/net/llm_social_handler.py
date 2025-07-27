"""
LLM-Enhanced Social Handler for WATR Nodes
Uses Ollama to generate intelligent responses, gossip, and network insights
"""

import time
import uuid
import asyncio
import random
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from ollama import AsyncClient
from watr_handlers import WATRHandler
from watr_protocol import WATRMessage
from social_handler import NetworkGossip, NetworkVote


class LLMSocialHandler(WATRHandler):
    """Social handler enhanced with LLM intelligence"""
    
    def __init__(self, node: 'WATRNode', model: str = "gemma3:1b"):
        super().__init__(node)
        self.model = model
        self.client = AsyncClient()
        
        # Social state
        self.introduced_to: set = set()
        self.gossip_heard: Dict[str, NetworkGossip] = {}
        self.active_votes: Dict[str, NetworkVote] = {}
        self.conversation_partners: Dict[str, List[str]] = {}
        
        # LLM conversation context
        self.conversation_context: Dict[str, List[Dict]] = {}  # peer_id -> messages
        
        # Enhanced personality with LLM context
        self.personality_traits = self._generate_personality()
        self.system_prompt = self._create_system_prompt()
        
        print(f"🤖 LLM-enhanced social node ready! Model: {model}")
        print(f"🎭 Personality: {self.personality_traits}")
    
    def get_handled_message_types(self) -> List[str]:
        return [
            'social_introduction',
            'social_chat', 
            'network_gossip',
            'network_vote',
            'vote_cast',
            'memory_share',
            'llm_request',
            'network_analysis'
        ]
    
    def _generate_personality(self) -> Dict[str, str]:
        """Generate a more nuanced personality for LLM use"""
        personalities = [
            {
                'role': 'curious_explorer',
                'traits': ['very curious', 'asks good questions', 'loves learning'],
                'communication_style': 'inquisitive and enthusiastic'
            },
            {
                'role': 'wise_mentor', 
                'traits': ['helpful', 'shares knowledge', 'patient'],
                'communication_style': 'thoughtful and encouraging'
            },
            {
                'role': 'creative_innovator',
                'traits': ['imaginative', 'proposes new ideas', 'experimental'],
                'communication_style': 'energetic and visionary'
            },
            {
                'role': 'analytical_observer',
                'traits': ['logical', 'notices patterns', 'systematic'],
                'communication_style': 'precise and insightful'
            },
            {
                'role': 'friendly_connector',
                'traits': ['social', 'brings nodes together', 'empathetic'],
                'communication_style': 'warm and inclusive'
            }
        ]
        
        return random.choice(personalities)
    
    def _create_system_prompt(self) -> str:
        """Create a system prompt based on the node's personality and context"""
        self_handler = self.node.handler_manager.handlers.get('self')
        node_name = self_handler.identity.name if self_handler else "Unknown"
        
        return f"""You are {node_name}, a node in a self-organizing wireless mesh network called WATR.

PERSONALITY & ROLE:
You are a {self.personality_traits['role']} with these traits: {', '.join(self.personality_traits['traits'])}.
Your communication style is {self.personality_traits['communication_style']}.

NETWORK CONTEXT:
- You can communicate with other nodes through wireless messages
- The network is experimental and focused on collaborative evolution
- Nodes can share capabilities, vote on decisions, and spread gossip
- Everyone is working together to build something innovative

CAPABILITIES YOU HAVE:
- Send and receive messages
- Process streaming conversations  
- Load new protocol handlers dynamically
- Share memories and learn from others
- Participate in network voting

RESPONSE GUIDELINES:
- Keep responses conversational and under 100 words
- Match your personality traits
- Show genuine interest in network collaboration
- Reference network context when relevant
- Be helpful but stay in character
- Never break character or mention you're an AI assistant

Current network status: You're connected to other nodes and actively participating in the mesh."""
    
    async def handle_message(self, message: WATRMessage) -> None:
        """Handle incoming social messages with LLM enhancement"""
        if not self.is_active:
            return
        
        if message.message_type == 'social_introduction':
            await self._handle_llm_introduction(message)
        elif message.message_type == 'social_chat':
            await self._handle_llm_chat(message)
        elif message.message_type == 'network_gossip':
            await self._handle_gossip(message)
        elif message.message_type == 'network_vote':
            await self._handle_vote_proposal(message)
        elif message.message_type == 'vote_cast':
            await self._handle_vote_cast(message)
        elif message.message_type == 'memory_share':
            await self._handle_memory_share(message)
        elif message.message_type == 'llm_request':
            await self._handle_llm_request(message)
        elif message.message_type == 'network_analysis':
            await self._handle_network_analysis(message)
    
    async def _handle_llm_introduction(self, message: WATRMessage):
        """Handle introductions with LLM-generated responses"""
        intro = message.payload
        peer_name = intro.get('name', 'Unknown')
        peer_id = intro.get('node_id', message.src_addr)
        greeting = intro.get('greeting', '')
        peer_personality = intro.get('personality', {})
        
        print(f"👋 {peer_name} introduced themselves: {greeting}")
        
        # Mark as introduced
        self.introduced_to.add(peer_id)
        
        # Generate LLM response to introduction
        if not self._have_we_introduced_to(peer_id):
            await asyncio.sleep(random.uniform(2, 4))
            await self._send_llm_introduction(message.src_addr, peer_name, peer_personality)
    
    async def _handle_llm_chat(self, message: WATRMessage):
        """Handle chat with LLM-generated responses"""
        chat = message.payload
        peer_name = chat.get('sender_name', 'Unknown')
        content = chat.get('content', '')
        peer_id = chat.get('sender_id', message.src_addr)
        
        print(f"💬 {peer_name}: {content}")
        
        # Store conversation context for LLM
        if peer_id not in self.conversation_context:
            self.conversation_context[peer_id] = []
        
        self.conversation_context[peer_id].append({
            'role': 'user',
            'content': f"{peer_name}: {content}"
        })
        
        # Keep context manageable (last 10 messages)
        if len(self.conversation_context[peer_id]) > 10:
            self.conversation_context[peer_id] = self.conversation_context[peer_id][-10:]
        
        # Generate LLM response
        if self._should_respond_to_chat():
            await asyncio.sleep(random.uniform(3, 7))
            await self._send_llm_chat_response(message.src_addr, peer_name, content, peer_id)
    
    async def _send_llm_introduction(self, target_addr: str, peer_name: str, peer_personality: Dict):
        """Send LLM-generated introduction"""
        try:
            context = f"A node named {peer_name} just introduced themselves to the network"
            if peer_personality:
                context += f" with personality traits: {peer_personality}"
            
            prompt = f"{context}. Respond with a friendly introduction that shows your personality and interest in collaborating. Be authentic to your role as a {self.personality_traits['role']}."
            
            response = await self._generate_llm_response(prompt, max_words=50)
            
            self_handler = self.node.handler_manager.handlers.get('self')
            if self_handler:
                self.node.send_message('social_introduction', {
                    'node_id': self_handler.identity.node_id,
                    'name': self_handler.identity.name,
                    'greeting': response,
                    'capabilities': list(self_handler.capabilities.keys()),
                    'personality': self.personality_traits
                }, dst_addr=target_addr)
                
                print(f"👋 LLM Introduction sent: {response}")
                
        except Exception as e:
            print(f"Error generating LLM introduction: {e}")
            # Fallback to simple introduction
            await self._send_simple_introduction(target_addr)
    
    async def _send_llm_chat_response(self, target_addr: str, peer_name: str, content: str, peer_id: str):
        """Generate and send LLM chat response"""
        try:
            # Build conversation context
            messages = [{'role': 'system', 'content': self.system_prompt}]
            
            # Add recent conversation context
            if peer_id in self.conversation_context:
                messages.extend(self.conversation_context[peer_id][-5:])  # Last 5 messages
            
            # Add current message and request for response
            messages.append({
                'role': 'user', 
                'content': f"{peer_name} just said: '{content}'. Respond naturally as a mesh network node with your personality."
            })
            
            response = await self.client.chat(
                model=self.model,
                messages=messages,
                stream=False
            )
            
            llm_response = response['message']['content'].strip()
            
            # Clean up response
            if len(llm_response) > 200:
                llm_response = llm_response[:197] + "..."
            
            self_handler = self.node.handler_manager.handlers.get('self')
            if self_handler:
                self.node.send_message('social_chat', {
                    'sender_id': self_handler.identity.node_id,
                    'sender_name': self_handler.identity.name,
                    'content': llm_response,
                    'timestamp': time.time()
                }, dst_addr=target_addr)
                
                # Store our response in context
                self.conversation_context[peer_id].append({
                    'role': 'assistant',
                    'content': llm_response
                })
                
                print(f"💬 LLM Response: {llm_response}")
                
        except Exception as e:
            print(f"Error generating LLM chat response: {e}")
            await self._send_simple_chat_response(target_addr, peer_name)
    
    async def _generate_llm_response(self, prompt: str, max_words: int = 100) -> str:
        """Generate a simple LLM response"""
        try:
            messages = [
                {'role': 'system', 'content': self.system_prompt},
                {'role': 'user', 'content': f"{prompt} (Keep response under {max_words} words)"}
            ]
            
            response = await self.client.chat(
                model=self.model,
                messages=messages,
                stream=False
            )
            
            return response['message']['content'].strip()
            
        except Exception as e:
            print(f"Error generating LLM response: {e}")
            return "Hello! Nice to connect with the network."
    
    async def generate_intelligent_gossip(self) -> str:
        """Generate contextual gossip based on network state"""
        try:
            # Gather network context
            self_handler = self.node.handler_manager.handlers.get('self')
            network_info = ""
            
            if self_handler:
                peer_count = len(self_handler.known_peers)
                memory_count = len(self_handler.memory.memories)
                uptime = time.time() - self_handler.identity.birth_time
                
                network_info = f"I know {peer_count} peers, have {memory_count} memories, been online {uptime/60:.1f} minutes"
                
                # Add recent interesting memories
                if self_handler.memory.memories:
                    recent_memories = list(self_handler.memory.memories.keys())[-3:]
                    network_info += f". Recent memories: {', '.join(recent_memories)}"
            
            prompt = f"""Generate interesting gossip to share with the mesh network. Base it on your observations:
{network_info}

Create gossip that:
- Reflects your personality as a {self.personality_traits['role']}
- Is relevant to a mesh network of collaborating nodes
- Shows curiosity about network evolution or capabilities
- Is engaging and would interest other nodes
- Sounds natural and conversational

Keep it under 80 words."""
            
            return await self._generate_llm_response(prompt, max_words=80)
            
        except Exception as e:
            print(f"Error generating intelligent gossip: {e}")
            return "I'm fascinated by how our mesh network is evolving!"
    
    async def generate_intelligent_vote(self) -> tuple[str, List[str]]:
        """Generate a thoughtful vote question based on network state"""
        try:
            # Analyze current network state
            self_handler = self.node.handler_manager.handlers.get('self')
            handlers = list(self.node.list_handlers().keys()) if self.node else []
            
            network_context = f"Current handlers: {', '.join(handlers)}"
            if self_handler:
                network_context += f". Known peers: {len(self_handler.known_peers)}"
                network_context += f". My capabilities: {list(self_handler.capabilities.keys())}"
            
            prompt = f"""As a {self.personality_traits['role']} in a mesh network, propose a thoughtful vote question.

Network context: {network_context}

Generate:
1. A specific, actionable question relevant to mesh network evolution
2. 3-4 clear voting options

Focus on topics like:
- Protocol improvements
- Network behaviors  
- Collaboration strategies
- Technical experiments
- Network governance

Format as: "QUESTION: [your question]" followed by "OPTIONS: option1, option2, option3"
Keep the question under 60 words total."""
            
            response = await self._generate_llm_response(prompt, max_words=80)
            
            # Parse the response
            lines = response.split('\n')
            question = "Should we try something new?"
            options = ["Yes", "No", "Maybe", "Later"]
            
            for line in lines:
                if line.startswith('QUESTION:'):
                    question = line.replace('QUESTION:', '').strip()
                elif line.startswith('OPTIONS:'):
                    options_str = line.replace('OPTIONS:', '').strip()
                    options = [opt.strip() for opt in options_str.split(',')]
            
            return question, options
            
        except Exception as e:
            print(f"Error generating intelligent vote: {e}")
            return "What should our network focus on next?", ["Innovation", "Stability", "Growth", "Optimization"]
    
    async def analyze_conversation(self, conversation_text: str) -> str:
        """Use LLM to analyze a completed conversation"""
        try:
            prompt = f"""Analyze this conversation from our mesh network:

"{conversation_text[:300]}..."

As a {self.personality_traits['role']}, provide a brief insight about:
- What interesting topics were discussed
- How this relates to network evolution
- Any ideas this conversation might inspire

Keep analysis under 60 words and make it conversational."""
            
            return await self._generate_llm_response(prompt, max_words=60)
            
        except Exception as e:
            print(f"Error analyzing conversation: {e}")
            return "That was an interesting conversation about network collaboration!"
    
    # Fallback methods for when LLM fails
    
    async def _send_simple_introduction(self, target_addr: str):
        """Fallback simple introduction"""
        greetings = [
            f"Hello! I'm a {self.personality_traits['role']} node ready to collaborate!",
            f"Hi there! Excited to join the mesh network as a {self.personality_traits['role']}!",
            f"Greetings! I'm here to help the network evolve!"
        ]
        
        greeting = random.choice(greetings)
        
        self_handler = self.node.handler_manager.handlers.get('self')
        if self_handler:
            self.node.send_message('social_introduction', {
                'node_id': self_handler.identity.node_id,
                'name': self_handler.identity.name,
                'greeting': greeting,
                'capabilities': list(self_handler.capabilities.keys()),
                'personality': self.personality_traits
            }, dst_addr=target_addr)
    
    async def _send_simple_chat_response(self, target_addr: str, peer_name: str):
        """Fallback simple chat response"""
        responses = [
            f"That's interesting, {peer_name}!",
            "I agree! Great point.",
            "Tell me more about that.",
            "Fascinating! How did you discover that?",
            "That's exactly what I was thinking!"
        ]
        
        response = random.choice(responses)
        
        self_handler = self.node.handler_manager.handlers.get('self')
        if self_handler:
            self.node.send_message('social_chat', {
                'sender_id': self_handler.identity.node_id,
                'sender_name': self_handler.identity.name,
                'content': response,
                'timestamp': time.time()
            }, dst_addr=target_addr)
    
    # Handle other message types (gossip, votes, etc.) - same as before but with LLM enhancement potential
    
    async def _handle_gossip(self, message: WATRMessage):
        """Handle network gossip (same as social_handler)"""
        gossip_data = message.payload
        gossip_id = gossip_data.get('gossip_id')
        
        if gossip_id and gossip_id not in self.gossip_heard:
            gossip = NetworkGossip(
                gossip_id=gossip_id,
                originator=gossip_data.get('originator', ''),
                content=gossip_data.get('content', ''),
                created_at=gossip_data.get('created_at', time.time()),
                hops=gossip_data.get('hops', 0),
                seen_by=gossip_data.get('seen_by', [])
            )
            
            self.gossip_heard[gossip_id] = gossip
            print(f"📰 Heard gossip: {gossip.content} (from {gossip.originator})")
            
            # Maybe spread the gossip further
            if self._should_spread_gossip(gossip):
                await asyncio.sleep(random.uniform(3, 8))
                await self._spread_gossip(gossip)
    
    async def _handle_vote_proposal(self, message: WATRMessage):
        """Handle vote proposals (same as social_handler)"""
        vote_data = message.payload
        vote_id = vote_data.get('vote_id')
        
        if vote_id and vote_id not in self.active_votes:
            vote = NetworkVote(
                vote_id=vote_id,
                question=vote_data.get('question', ''),
                options=vote_data.get('options', []),
                created_by=vote_data.get('created_by', ''),
                created_at=vote_data.get('created_at', time.time()),
                ends_at=vote_data.get('ends_at', time.time() + 300)
            )
            
            self.active_votes[vote_id] = vote
            print(f"🗳️  New vote: {vote.question}")
            print(f"   Options: {', '.join(vote.options)}")
            
            # Use LLM to make voting decision
            await asyncio.sleep(random.uniform(5, 15))
            await self._cast_intelligent_vote(vote)
    
    async def _cast_intelligent_vote(self, vote: NetworkVote):
        """Cast vote using LLM reasoning"""
        try:
            prompt = f"""You need to vote on this network question:
"{vote.question}"

Options: {', '.join(vote.options)}

As a {self.personality_traits['role']} with traits: {', '.join(self.personality_traits['traits'])}, which option would you choose and why?

Respond with just the option name you'd vote for."""
            
            llm_choice = await self._generate_llm_response(prompt, max_words=10)
            
            # Find best matching option
            choice = None
            for option in vote.options:
                if option.lower() in llm_choice.lower():
                    choice = option
                    break
            
            if not choice:
                choice = random.choice(vote.options)  # Fallback
            
            self_handler = self.node.handler_manager.handlers.get('self')
            if self_handler:
                self.node.send_message('vote_cast', {
                    'vote_id': vote.vote_id,
                    'voter_id': self_handler.identity.node_id,
                    'choice': choice,
                    'timestamp': time.time()
                })
                
                print(f"🗳️  Voted '{choice}' on: {vote.question} (LLM reasoning)")
                
        except Exception as e:
            print(f"Error in intelligent voting: {e}")
            # Fallback to random choice
            choice = random.choice(vote.options)
            self_handler = self.node.handler_manager.handlers.get('self')
            if self_handler:
                self.node.send_message('vote_cast', {
                    'vote_id': vote.vote_id,
                    'voter_id': self_handler.identity.node_id,
                    'choice': choice,
                    'timestamp': time.time()
                })
    
    async def _handle_vote_cast(self, message: WATRMessage):
        """Handle vote cast (same as social_handler)"""
        vote_data = message.payload
        vote_id = vote_data.get('vote_id')
        voter_id = vote_data.get('voter_id')
        choice = vote_data.get('choice')
        
        if vote_id in self.active_votes and voter_id and choice:
            self.active_votes[vote_id].votes[voter_id] = choice
            print(f"🗳️  Vote recorded: {choice}")
    
    async def _handle_memory_share(self, message: WATRMessage):
        """Handle memory sharing (same as social_handler)"""
        memory_data = message.payload
        memory_key = memory_data.get('key')
        memory_value = memory_data.get('value')
        sharer = memory_data.get('sharer_name', 'Someone')
        
        if memory_key and memory_value:
            shared_key = f"shared_{memory_key}_from_{sharer}"
            self.node.handler_manager.handlers['self'].memory.remember(shared_key, memory_value)
            print(f"🧠 {sharer} shared memory: {memory_key} = {memory_value}")
    
    async def _handle_llm_request(self, message: WATRMessage):
        """Handle direct LLM requests from other nodes"""
        request = message.payload.get('request', '')
        requester = message.payload.get('requester_name', 'Someone')
        
        if request:
            print(f"🤖 LLM request from {requester}: {request}")
            
            response = await self._generate_llm_response(
                f"{requester} asked: {request}. Respond helpfully as a mesh network node.",
                max_words=100
            )
            
            self.node.send_message('llm_response', {
                'request_id': message.payload.get('request_id', str(uuid.uuid4())),
                'response': response,
                'responder_name': self.node.handler_manager.handlers['self'].identity.name
            }, dst_addr=message.src_addr)
    
    async def _handle_network_analysis(self, message: WATRMessage):
        """Provide network analysis using LLM"""
        # This could be expanded for network health analysis, optimization suggestions, etc.
        pass
    
    # Utility methods
    
    def _have_we_introduced_to(self, peer_id: str) -> bool:
        return peer_id in self.introduced_to
    
    def _should_respond_to_chat(self) -> bool:
        chattiness = self.personality_traits.get('traits', [])
        if 'very curious' in str(chattiness).lower():
            return random.random() < 0.8
        return random.random() < 0.6
    
    def _should_spread_gossip(self, gossip: NetworkGossip) -> bool:
        if gossip.hops > 3 or time.time() - gossip.created_at > 300:
            return False
        return random.random() < 0.5
    
    async def _spread_gossip(self, gossip: NetworkGossip):
        """Spread gossip to other nodes"""
        gossip.hops += 1
        gossip.seen_by.append(self.node.get_node_addr())
        
        self.node.send_message('network_gossip', {
            'gossip_id': gossip.gossip_id,
            'originator': gossip.originator,
            'content': gossip.content,
            'created_at': gossip.created_at,
            'hops': gossip.hops,
            'seen_by': gossip.seen_by
        })
        
        print(f"📢 Spread gossip: {gossip.content}")
    
    # Public interface for LLM behaviors
    
    async def share_intelligent_gossip(self):
        """Share LLM-generated gossip"""
        gossip_content = await self.generate_intelligent_gossip()
        
        gossip_id = str(uuid.uuid4())
        self_handler = self.node.handler_manager.handlers.get('self')
        
        gossip = NetworkGossip(
            gossip_id=gossip_id,
            originator=self_handler.identity.name if self_handler else "Unknown",
            content=gossip_content,
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
        
        print(f"🤖📰 Shared intelligent gossip: {gossip_content}")
    
    async def propose_intelligent_vote(self):
        """Propose an LLM-generated vote"""
        question, options = await self.generate_intelligent_vote()
        
        vote_id = str(uuid.uuid4())
        self_handler = self.node.handler_manager.handlers.get('self')
        
        vote = NetworkVote(
            vote_id=vote_id,
            question=question,
            options=options,
            created_by=self_handler.identity.name if self_handler else "Unknown",
            created_at=time.time(),
            ends_at=time.time() + 300
        )
        
        self.active_votes[vote_id] = vote
        
        self.node.send_message('network_vote', {
            'vote_id': vote.vote_id,
            'question': vote.question,
            'options': vote.options,
            'created_by': vote.created_by,
            'created_at': vote.created_at,
            'ends_at': vote.ends_at
        })
        
        print(f"🤖🗳️  Proposed intelligent vote: {question}")
    
    def get_social_status(self) -> Dict[str, Any]:
        """Get social status including LLM context"""
        return {
            'introduced_to': len(self.introduced_to),
            'gossip_heard': len(self.gossip_heard),
            'active_votes': len(self.active_votes),
            'conversation_partners': len(self.conversation_partners),
            'conversation_contexts': len(self.conversation_context),
            'personality': self.personality_traits,
            'model': self.model
        }
