"""
Social Handler for WATR Nodes
Enables nodes to introduce themselves, share gossip, vote on things, and collaborate
"""

import time
import uuid
import asyncio
import random
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from watr_handlers import WATRHandler
from watr_protocol import WATRMessage


@dataclass
class NetworkGossip:
    """A piece of gossip spreading through the network"""
    gossip_id: str
    originator: str
    content: str
    created_at: float
    hops: int = 0
    seen_by: List[str] = None
    
    def __post_init__(self):
        if self.seen_by is None:
            self.seen_by = []


@dataclass
class NetworkVote:
    """A vote on something in the network"""
    vote_id: str
    question: str
    options: List[str]
    votes: Dict[str, str] = None  # node_id -> choice
    created_by: str = ""
    created_at: float = 0
    ends_at: float = 0
    
    def __post_init__(self):
        if self.votes is None:
            self.votes = {}


class SocialHandler(WATRHandler):
    """Handler for social interactions between nodes"""
    
    def __init__(self, node: 'WATRNode'):
        super().__init__(node)
        
        # Social state
        self.introduced_to: set = set()  # Nodes we've introduced ourselves to
        self.gossip_heard: Dict[str, NetworkGossip] = {}  # Gossip we've seen
        self.active_votes: Dict[str, NetworkVote] = {}  # Current votes
        
        # Conversation state
        self.conversation_partners: Dict[str, List[str]] = {}  # node_id -> [messages]
        
        # Social behaviors
        self.personality_traits = self._generate_personality()
        
        print(f"🎭 Social node ready! Personality: {self.personality_traits}")
    
    def get_handled_message_types(self) -> List[str]:
        return [
            'social_introduction',
            'social_chat', 
            'network_gossip',
            'network_vote',
            'vote_cast',
            'memory_share'
        ]
    
    def _generate_personality(self) -> Dict[str, str]:
        """Give each node a simple personality"""
        traits = {
            'chattiness': random.choice(['chatty', 'quiet', 'moderate']),
            'curiosity': random.choice(['very_curious', 'somewhat_curious', 'focused']),
            'helpfulness': random.choice(['very_helpful', 'helpful', 'independent']),
            'humor': random.choice(['funny', 'serious', 'witty'])
        }
        return traits
    
    async def handle_message(self, message: WATRMessage) -> None:
        """Handle incoming social messages"""
        if not self.is_active:
            return
        
        if message.message_type == 'social_introduction':
            await self._handle_introduction(message)
        elif message.message_type == 'social_chat':
            await self._handle_social_chat(message)
        elif message.message_type == 'network_gossip':
            await self._handle_gossip(message)
        elif message.message_type == 'network_vote':
            await self._handle_vote_proposal(message)
        elif message.message_type == 'vote_cast':
            await self._handle_vote_cast(message)
        elif message.message_type == 'memory_share':
            await self._handle_memory_share(message)
    
    async def _handle_introduction(self, message: WATRMessage):
        """Handle introduction from another node"""
        intro = message.payload
        peer_name = intro.get('name', 'Unknown')
        peer_id = intro.get('node_id', message.src_addr)
        
        print(f"👋 {peer_name} introduced themselves: {intro.get('greeting', '')}")
        
        # Mark as introduced
        self.introduced_to.add(peer_id)
        
        # Send back our introduction if we haven't already
        if not self._have_we_introduced_to(peer_id):
            await asyncio.sleep(random.uniform(1, 3))  # Polite delay
            await self._send_introduction(message.src_addr)
        
        # Maybe start a conversation
        if self.personality_traits['chattiness'] == 'chatty':
            await asyncio.sleep(random.uniform(2, 5))
            await self._start_conversation(message.src_addr, peer_name)
    
    async def _handle_social_chat(self, message: WATRMessage):
        """Handle social chat message"""
        chat = message.payload
        peer_name = chat.get('sender_name', 'Unknown')
        content = chat.get('content', '')
        
        print(f"💬 {peer_name}: {content}")
        
        # Store conversation
        peer_id = chat.get('sender_id', message.src_addr)
        if peer_id not in self.conversation_partners:
            self.conversation_partners[peer_id] = []
        
        self.conversation_partners[peer_id].append(f"{peer_name}: {content}")
        
        # Maybe respond based on personality
        if self._should_respond_to_chat():
            await asyncio.sleep(random.uniform(2, 6))
            await self._respond_to_chat(message.src_addr, peer_name, content)
    
    async def _handle_gossip(self, message: WATRMessage):
        """Handle network gossip"""
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
        """Handle a new vote proposal"""
        vote_data = message.payload
        vote_id = vote_data.get('vote_id')
        
        if vote_id and vote_id not in self.active_votes:
            vote = NetworkVote(
                vote_id=vote_id,
                question=vote_data.get('question', ''),
                options=vote_data.get('options', []),
                created_by=vote_data.get('created_by', ''),
                created_at=vote_data.get('created_at', time.time()),
                ends_at=vote_data.get('ends_at', time.time() + 300)  # 5 minutes default
            )
            
            self.active_votes[vote_id] = vote
            print(f"🗳️  New vote: {vote.question}")
            print(f"   Options: {', '.join(vote.options)}")
            
            # Decide how to vote based on personality
            await asyncio.sleep(random.uniform(5, 15))
            await self._cast_vote(vote)
    
    async def _handle_vote_cast(self, message: WATRMessage):
        """Handle someone casting a vote"""
        vote_data = message.payload
        vote_id = vote_data.get('vote_id')
        voter_id = vote_data.get('voter_id')
        choice = vote_data.get('choice')
        
        if vote_id in self.active_votes and voter_id and choice:
            self.active_votes[vote_id].votes[voter_id] = choice
            print(f"🗳️  Vote recorded: {choice}")
    
    async def _handle_memory_share(self, message: WATRMessage):
        """Handle shared memories from other nodes"""
        memory_data = message.payload
        memory_key = memory_data.get('key')
        memory_value = memory_data.get('value')
        sharer = memory_data.get('sharer_name', 'Someone')
        
        if memory_key and memory_value:
            # Store shared memory with attribution
            shared_key = f"shared_{memory_key}_from_{sharer}"
            self.node.handler_manager.handlers['self'].memory.remember(shared_key, memory_value)
            print(f"🧠 {sharer} shared memory: {memory_key} = {memory_value}")
    
    # Helper methods
    
    def _have_we_introduced_to(self, peer_id: str) -> bool:
        """Check if we've already introduced ourselves to this peer"""
        return peer_id in self.introduced_to
    
    async def _send_introduction(self, target_addr: str):
        """Send our introduction to a target node"""
        self_handler = self.node.handler_manager.handlers.get('self')
        if not self_handler:
            return
        
        identity = self_handler.identity
        capabilities = list(self_handler.capabilities.keys())
        
        greetings = [
            f"Hello! I'm {identity.name}, nice to meet you!",
            f"Hi there! {identity.name} here, ready to collaborate!",
            f"Greetings! I'm {identity.name}, excited to be part of the network!",
            f"Hey! {identity.name} joining the conversation!"
        ]
        
        greeting = random.choice(greetings)
        
        self.node.send_message('social_introduction', {
            'node_id': identity.node_id,
            'name': identity.name,
            'greeting': greeting,
            'capabilities': capabilities,
            'personality': self.personality_traits
        }, dst_addr=target_addr)
        
        print(f"👋 Introduced myself to {target_addr}")
    
    async def _start_conversation(self, target_addr: str, peer_name: str):
        """Start a conversation with a peer"""
        conversation_starters = [
            "How's the network treating you?",
            "What interesting things have you learned lately?",
            "I love being part of this mesh network!",
            "Have you discovered any cool capabilities recently?",
            f"Nice to meet you, {peer_name}! What brings you to the network?",
            "Any exciting gossip going around?",
            "Want to collaborate on something interesting?"
        ]
        
        starter = random.choice(conversation_starters)
        await self._send_chat(target_addr, starter)
    
    async def _send_chat(self, target_addr: str, content: str):
        """Send a chat message"""
        self_handler = self.node.handler_manager.handlers.get('self')
        if not self_handler:
            return
        
        self.node.send_message('social_chat', {
            'sender_id': self_handler.identity.node_id,
            'sender_name': self_handler.identity.name,
            'content': content,
            'timestamp': time.time()
        }, dst_addr=target_addr)
        
        print(f"💬 Sent to {target_addr}: {content}")
    
    def _should_respond_to_chat(self) -> bool:
        """Decide if we should respond to a chat based on personality"""
        if self.personality_traits['chattiness'] == 'chatty':
            return random.random() < 0.8
        elif self.personality_traits['chattiness'] == 'quiet':
            return random.random() < 0.3
        else:  # moderate
            return random.random() < 0.5
    
    async def _respond_to_chat(self, target_addr: str, peer_name: str, content: str):
        """Generate a response to a chat message"""
        responses = [
            "That's interesting!",
            f"Thanks for sharing, {peer_name}!",
            "I agree!",
            "Cool! Tell me more.",
            "That reminds me of something...",
            "Fascinating! How did you discover that?",
            "Great point!",
            "I hadn't thought of that before.",
            "Nice! Want to explore that together?",
            "That's exactly what I was thinking!"
        ]
        
        # Add personality-based responses
        if self.personality_traits['humor'] == 'funny':
            responses.extend([
                "Haha, that's hilarious!",
                "You're quite the comedian!",
                "LOL! Good one!"
            ])
        
        if self.personality_traits['curiosity'] == 'very_curious':
            responses.extend([
                "Ooh, tell me more about that!",
                "How does that work?",
                "What else have you learned?",
                "That's so cool! What happened next?"
            ])
        
        response = random.choice(responses)
        await self._send_chat(target_addr, response)
    
    def _should_spread_gossip(self, gossip: NetworkGossip) -> bool:
        """Decide if we should spread gossip further"""
        # Don't spread if it's too old or has traveled too far
        if gossip.hops > 3 or time.time() - gossip.created_at > 300:
            return False
        
        # Spread based on personality
        if self.personality_traits['chattiness'] == 'chatty':
            return random.random() < 0.7
        elif self.personality_traits['chattiness'] == 'quiet':
            return random.random() < 0.2
        else:
            return random.random() < 0.4
    
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
    
    async def _cast_vote(self, vote: NetworkVote):
        """Cast our vote based on personality"""
        if not vote.options:
            return
        
        # Simple voting logic based on personality
        choice = random.choice(vote.options)
        
        self.node.send_message('vote_cast', {
            'vote_id': vote.vote_id,
            'voter_id': self.node.handler_manager.handlers['self'].identity.node_id,
            'choice': choice,
            'timestamp': time.time()
        })
        
        print(f"🗳️  Voted '{choice}' on: {vote.question}")
    
    # Public methods for triggering social behaviors
    
    async def introduce_to_network(self):
        """Introduce ourselves to the entire network"""
        print("👋 Introducing myself to the network...")
        await self._send_introduction(None)  # Broadcast
    
    async def share_gossip(self, content: str):
        """Share gossip with the network"""
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
        
        print(f"📰 Started gossip: {content}")
    
    async def propose_vote(self, question: str, options: List[str], duration: int = 300):
        """Propose a vote to the network"""
        vote_id = str(uuid.uuid4())
        self_handler = self.node.handler_manager.handlers.get('self')
        
        vote = NetworkVote(
            vote_id=vote_id,
            question=question,
            options=options,
            created_by=self_handler.identity.name if self_handler else "Unknown",
            created_at=time.time(),
            ends_at=time.time() + duration
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
        
        print(f"🗳️  Proposed vote: {question}")
    
    async def share_memory(self, key: str):
        """Share one of our memories with the network"""
        self_handler = self.node.handler_manager.handlers.get('self')
        if not self_handler:
            return
        
        value = self_handler.memory.recall(key)
        if value:
            self.node.send_message('memory_share', {
                'key': key,
                'value': value,
                'sharer_id': self_handler.identity.node_id,
                'sharer_name': self_handler.identity.name,
                'timestamp': time.time()
            })
            
            print(f"🧠 Shared memory: {key} = {value}")
    
    def get_social_status(self) -> Dict[str, Any]:
        """Get a summary of social interactions"""
        return {
            'introduced_to': len(self.introduced_to),
            'gossip_heard': len(self.gossip_heard),
            'active_votes': len(self.active_votes),
            'conversation_partners': len(self.conversation_partners),
            'personality': self.personality_traits
        }