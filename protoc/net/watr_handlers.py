"""
WATR Dynamic Handler System
Provides pluggable message handlers and conversation accumulation
"""

import asyncio
import time
from typing import Callable, Optional, Dict, Any, List
from dataclasses import dataclass
from abc import ABC, abstractmethod

from watr_protocol import WATRMessage


class WATRHandler(ABC):
    """Abstract base class for dynamic WATR message handlers"""
    
    def __init__(self, node: 'WATRNode'):
        self.node = node
        self.is_active = False
    
    @abstractmethod
    def get_handled_message_types(self) -> List[str]:
        """Return list of message types this handler processes"""
        pass
    
    @abstractmethod
    async def handle_message(self, message: WATRMessage) -> None:
        """Handle an incoming message"""
        pass
    
    async def on_activate(self) -> None:
        """Called when handler is activated"""
        self.is_active = True
    
    async def on_deactivate(self) -> None:
        """Called when handler is deactivated"""
        self.is_active = False
    
    async def cleanup(self) -> None:
        """Cleanup resources before removal"""
        pass


@dataclass
class ConversationSegment:
    """Individual conversation segment"""
    cid: str
    seg: int
    text: Optional[str]
    src_addr: str
    timestamp: float


@dataclass
class AccumulatedConversation:
    """Complete accumulated conversation"""
    cid: str
    src_addr: str
    segments: List[ConversationSegment]
    complete_text: str
    start_time: float
    end_time: float


class ConversationAccumulatorHandler(WATRHandler):
    """Handler for accumulating streaming chat conversations"""
    
    def __init__(self, node: 'WATRNode', conversation_timeout: float = 420.0):  # 7 minutes
        super().__init__(node)
        self.conversation_timeout = conversation_timeout
        self.active_conversations: Dict[str, Dict[str, Any]] = {}
        self.timeout_tasks: Dict[str, asyncio.Task] = {}
        
        # Callbacks for complete conversations
        self.completion_handlers: List[Callable[[AccumulatedConversation], None]] = []
    
    def get_handled_message_types(self) -> List[str]:
        return ['chat']
    
    def add_completion_handler(self, handler: Callable[[AccumulatedConversation], None]):
        """Add a callback for when conversations complete"""
        self.completion_handlers.append(handler)
    
    def remove_completion_handler(self, handler: Callable[[AccumulatedConversation], None]):
        """Remove a completion callback"""
        if handler in self.completion_handlers:
            self.completion_handlers.remove(handler)
    
    async def handle_message(self, message: WATRMessage) -> None:
        """Handle incoming chat message segments"""
        if not self.is_active:
            return
            
        payload = message.payload
        cid = payload.get('cid')
        seg = payload.get('seg', 0)
        text = payload.get('text')
        
        if not cid:
            print(f"Chat message missing conversation ID: {payload}")
            return
        
        print(f"Received chat segment {seg} for conversation {cid[:8]}...")
        
        # Initialize conversation if new
        if cid not in self.active_conversations:
            self.active_conversations[cid] = {
                'segments': {},
                'src_addr': message.src_addr,
                'start_time': time.time(),
                'last_segment': -1
            }
            
            # Start timeout task
            self.timeout_tasks[cid] = asyncio.create_task(
                self._conversation_timeout(cid)
            )
        
        # Add segment
        conversation = self.active_conversations[cid]
        segment = ConversationSegment(
            cid=cid,
            seg=seg,
            text=text,
            src_addr=message.src_addr,
            timestamp=message.timestamp
        )
        
        conversation['segments'][seg] = segment
        conversation['last_segment'] = max(conversation['last_segment'], seg)
        
        # Check if conversation is complete (text is None)
        if text is None:
            await self._complete_conversation(cid)
    
    async def _conversation_timeout(self, cid: str):
        """Handle conversation timeout"""
        try:
            await asyncio.sleep(self.conversation_timeout)
            if cid in self.active_conversations:
                print(f"Conversation {cid[:8]}... timed out after {self.conversation_timeout}s")
                await self._complete_conversation(cid)
        except asyncio.CancelledError:
            pass  # Normal cancellation when conversation completes normally
    
    async def _complete_conversation(self, cid: str):
        """Complete and process a conversation"""
        if cid not in self.active_conversations:
            return
        
        conversation = self.active_conversations[cid]
        
        # Cancel timeout task
        if cid in self.timeout_tasks:
            self.timeout_tasks[cid].cancel()
            del self.timeout_tasks[cid]
        
        # Sort segments and build complete text
        segments = list(conversation['segments'].values())
        segments.sort(key=lambda x: x.seg)
        
        complete_text = ""
        for segment in segments:
            if segment.text is not None:  # Skip None terminator
                complete_text += segment.text
        
        # Create accumulated conversation
        accumulated = AccumulatedConversation(
            cid=cid,
            src_addr=conversation['src_addr'],
            segments=segments,
            complete_text=complete_text,
            start_time=conversation['start_time'],
            end_time=time.time()
        )
        
        # Remove from active conversations
        del self.active_conversations[cid]
        
        print(f"Conversation {cid[:8]}... completed with {len(segments)} segments")
        
        # Notify completion handlers
        for handler in self.completion_handlers:
            try:
                await asyncio.get_event_loop().run_in_executor(None, handler, accumulated)
            except Exception as e:
                print(f"Error in completion handler: {e}")
    
    async def cleanup(self):
        """Cleanup all active conversations and tasks"""
        # Cancel all timeout tasks
        for task in self.timeout_tasks.values():
            task.cancel()
        
        # Wait for cancellations
        if self.timeout_tasks:
            await asyncio.gather(*self.timeout_tasks.values(), return_exceptions=True)
        
        self.timeout_tasks.clear()
        self.active_conversations.clear()


class HandlerManager:
    """Manages dynamic loading/unloading of handlers"""
    
    def __init__(self, node: 'WATRNode'):
        self.node = node
        self.handlers: Dict[str, WATRHandler] = {}
        self.message_type_map: Dict[str, List[str]] = {}  # message_type -> handler_names
    
    async def load_handler(self, name: str, handler: WATRHandler) -> bool:
        """Load a new handler"""
        if name in self.handlers:
            print(f"Handler {name} already loaded")
            return False
        
        try:
            # Register handler
            self.handlers[name] = handler
            
            # Map message types to this handler
            for msg_type in handler.get_handled_message_types():
                if msg_type not in self.message_type_map:
                    self.message_type_map[msg_type] = []
                self.message_type_map[msg_type].append(name)
                
                # Register with protocol
                self.node.protocol.register_handler(msg_type, self._create_dispatcher(msg_type))
            
            # Activate handler
            await handler.on_activate()
            
            print(f"Handler {name} loaded for message types: {handler.get_handled_message_types()}")
            return True
            
        except Exception as e:
            print(f"Error loading handler {name}: {e}")
            return False
    
    async def unload_handler(self, name: str) -> bool:
        """Unload a handler"""
        if name not in self.handlers:
            print(f"Handler {name} not found")
            return False
        
        try:
            handler = self.handlers[name]
            
            # Deactivate handler
            await handler.on_deactivate()
            
            # Cleanup
            await handler.cleanup()
            
            # Remove from message type mapping
            for msg_type in handler.get_handled_message_types():
                if msg_type in self.message_type_map:
                    if name in self.message_type_map[msg_type]:
                        self.message_type_map[msg_type].remove(name)
                    
                    # If no more handlers for this message type, remove from protocol
                    if not self.message_type_map[msg_type]:
                        del self.message_type_map[msg_type]
                        # Note: We can't easily unregister from protocol, 
                        # but the dispatcher will handle no handlers gracefully
            
            # Remove handler
            del self.handlers[name]
            
            print(f"Handler {name} unloaded")
            return True
            
        except Exception as e:
            print(f"Error unloading handler {name}: {e}")
            return False
    
    def _create_dispatcher(self, message_type: str):
        """Create a dispatcher function for a message type"""
        async def dispatcher(message: WATRMessage):
            # Find all handlers for this message type
            handler_names = self.message_type_map.get(message_type, [])
            
            # Dispatch to all active handlers
            for handler_name in handler_names:
                if handler_name in self.handlers:
                    handler = self.handlers[handler_name]
                    try:
                        await handler.handle_message(message)
                    except Exception as e:
                        print(f"Error in handler {handler_name}: {e}")
        
        return lambda msg: asyncio.create_task(dispatcher(msg))
    
    def list_handlers(self) -> Dict[str, List[str]]:
        """List all loaded handlers and their message types"""
        return {
            name: handler.get_handled_message_types() 
            for name, handler in self.handlers.items()
        }


# Example completion handler for conversations
def handle_completed_conversation(conversation: AccumulatedConversation):
    """Default stub handler for completed conversations"""
    print(f"\n=== CONVERSATION COMPLETE ===")
    print(f"ID: {conversation.cid}")
    print(f"Source: {conversation.src_addr}")
    print(f"Segments: {len(conversation.segments)}")
    print(f"Duration: {conversation.end_time - conversation.start_time:.2f}s")
    print(f"Text length: {len(conversation.complete_text)} chars")
    print(f"Preview: {conversation.complete_text[:100]}...")
    print("============================\n")