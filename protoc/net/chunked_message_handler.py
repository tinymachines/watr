"""
Chunked Message Handler for WATR
Handles breaking large messages into chunks and reassembling them
"""

import json
import time
import uuid
import asyncio
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass

from watr_handlers import WATRHandler
from watr_protocol import WATRMessage
from watr_logging import WATRLoggerMixin


@dataclass 
class ChunkedMessage:
    """Represents a message being reassembled from chunks"""
    chunk_id: str
    message_type: str
    total_chunks: int
    chunks_received: Dict[int, str]  # chunk_num -> data
    src_addr: str
    timestamp: float
    
    def is_complete(self) -> bool:
        """Check if all chunks have been received"""
        return len(self.chunks_received) == self.total_chunks
    
    def reassemble(self) -> Dict[str, Any]:
        """Reassemble the complete message from chunks"""
        if not self.is_complete():
            raise ValueError("Message not complete")
        
        # Sort chunks by number and concatenate
        sorted_chunks = [self.chunks_received[i] for i in range(self.total_chunks)]
        complete_data = ''.join(sorted_chunks)
        
        # Parse JSON payload
        return json.loads(complete_data)


class ChunkedMessageHandler(WATRHandler, WATRLoggerMixin):
    """Handler for chunked message transmission and reception"""
    
    def __init__(self, node, chunk_size: int = 1000, timeout: float = 60.0):
        WATRLoggerMixin.__init__(self)
        WATRHandler.__init__(self, node)
        
        self.chunk_size = chunk_size  # Max bytes per chunk
        self.timeout = timeout
        
        # Track messages being reassembled
        self.pending_messages: Dict[str, ChunkedMessage] = {}
        self.timeout_tasks: Dict[str, asyncio.Task] = {}
        
        # Callbacks for completed messages
        self.message_handlers: Dict[str, List[Callable]] = {}
        
        self.logger.info(
            "Chunked Message Handler initialized",
            extra={
                **self.log_extra,
                'chunk_size': chunk_size,
                'timeout': timeout
            }
        )
    
    def get_handled_message_types(self) -> List[str]:
        return ['chunk']
    
    def register_message_handler(self, message_type: str, handler: Callable):
        """Register a handler for reassembled messages of a specific type"""
        if message_type not in self.message_handlers:
            self.message_handlers[message_type] = []
        self.message_handlers[message_type].append(handler)
    
    async def send_chunked_message(self, message_type: str, payload: Dict[str, Any], dst_addr: str = None):
        """Send a large message in chunks"""
        try:
            # Serialize payload to JSON
            payload_json = json.dumps(payload)
            payload_bytes = payload_json.encode('utf-8')
            
            # Calculate number of chunks needed
            total_chunks = (len(payload_bytes) + self.chunk_size - 1) // self.chunk_size
            
            if total_chunks == 1:
                # Small enough to send directly
                self.node.send_message(message_type, payload, dst_addr)
                return
            
            # Generate chunk ID
            chunk_id = str(uuid.uuid4())
            
            self.logger.info(
                f"Sending chunked message",
                extra={
                    **self.log_extra,
                    'message_type': message_type,
                    'chunk_id': chunk_id,
                    'total_chunks': total_chunks,
                    'payload_size': len(payload_bytes),
                    'dst_addr': dst_addr or 'broadcast'
                }
            )
            
            # Send chunks
            for i in range(total_chunks):
                start = i * self.chunk_size
                end = min(start + self.chunk_size, len(payload_bytes))
                chunk_data = payload_bytes[start:end].decode('utf-8')
                
                chunk_msg = {
                    'chunk_id': chunk_id,
                    'chunk_num': i,
                    'total_chunks': total_chunks,
                    'message_type': message_type,
                    'data': chunk_data
                }
                
                self.node.send_message('chunk', chunk_msg, dst_addr)
                
                # Small delay between chunks to avoid overwhelming the network
                await asyncio.sleep(0.01)
            
            self.logger.debug(
                f"All chunks sent for {chunk_id}",
                extra={
                    **self.log_extra,
                    'chunk_id': chunk_id,
                    'total_chunks': total_chunks
                }
            )
            
        except Exception as e:
            self.log_error(e, f"sending chunked message {message_type}")
    
    async def handle_message(self, message: WATRMessage) -> None:
        """Handle incoming chunk messages"""
        if not self.is_active or message.message_type != 'chunk':
            return
        
        try:
            payload = message.payload
            chunk_id = payload.get('chunk_id')
            chunk_num = payload.get('chunk_num', 0)
            total_chunks = payload.get('total_chunks', 1)
            msg_type = payload.get('message_type')
            data = payload.get('data', '')
            
            if not chunk_id or msg_type is None:
                self.logger.warning("Invalid chunk message", extra={'payload': payload})
                return
            
            # Initialize tracking for new chunked message
            if chunk_id not in self.pending_messages:
                self.pending_messages[chunk_id] = ChunkedMessage(
                    chunk_id=chunk_id,
                    message_type=msg_type,
                    total_chunks=total_chunks,
                    chunks_received={},
                    src_addr=message.src_addr,
                    timestamp=time.time()
                )
                
                # Start timeout
                self.timeout_tasks[chunk_id] = asyncio.create_task(
                    self._chunk_timeout(chunk_id)
                )
                
                self.logger.debug(
                    f"Started receiving chunked message",
                    extra={
                        **self.log_extra,
                        'chunk_id': chunk_id,
                        'message_type': msg_type,
                        'total_chunks': total_chunks,
                        'from': message.src_addr
                    }
                )
            
            # Store chunk
            pending = self.pending_messages[chunk_id]
            pending.chunks_received[chunk_num] = data
            
            # Check if complete
            if pending.is_complete():
                await self._complete_chunked_message(chunk_id)
                
        except Exception as e:
            self.log_error(e, "handling chunk message", {'chunk_id': chunk_id})
    
    async def _complete_chunked_message(self, chunk_id: str):
        """Complete and process a fully received chunked message"""
        if chunk_id not in self.pending_messages:
            return
        
        pending = self.pending_messages[chunk_id]
        
        try:
            # Cancel timeout
            if chunk_id in self.timeout_tasks:
                self.timeout_tasks[chunk_id].cancel()
                del self.timeout_tasks[chunk_id]
            
            # Reassemble message
            payload = pending.reassemble()
            
            self.logger.info(
                f"Chunked message complete",
                extra={
                    **self.log_extra,
                    'chunk_id': chunk_id,
                    'message_type': pending.message_type,
                    'total_chunks': pending.total_chunks,
                    'from': pending.src_addr
                }
            )
            
            # Create a synthetic message for handlers
            complete_msg = WATRMessage(
                message_type=pending.message_type,
                payload=payload,
                timestamp=pending.timestamp,
                src_addr=pending.src_addr,
                dst_addr=self.node.protocol.src_addr
            )
            
            # Notify handlers
            if pending.message_type in self.message_handlers:
                for handler in self.message_handlers[pending.message_type]:
                    try:
                        if asyncio.iscoroutinefunction(handler):
                            await handler(complete_msg)
                        else:
                            await asyncio.get_event_loop().run_in_executor(
                                None, handler, complete_msg
                            )
                    except Exception as e:
                        self.log_error(e, f"in handler for {pending.message_type}")
            
            # Cleanup
            del self.pending_messages[chunk_id]
            
        except Exception as e:
            self.log_error(e, f"completing chunked message {chunk_id}")
            
            # Cleanup on error
            if chunk_id in self.pending_messages:
                del self.pending_messages[chunk_id]
            if chunk_id in self.timeout_tasks:
                self.timeout_tasks[chunk_id].cancel()
                del self.timeout_tasks[chunk_id]
    
    async def _chunk_timeout(self, chunk_id: str):
        """Handle timeout for incomplete chunked messages"""
        try:
            await asyncio.sleep(self.timeout)
            
            if chunk_id in self.pending_messages:
                pending = self.pending_messages[chunk_id]
                received = len(pending.chunks_received)
                
                self.logger.warning(
                    f"Chunked message timeout",
                    extra={
                        **self.log_extra,
                        'chunk_id': chunk_id,
                        'message_type': pending.message_type,
                        'chunks_received': received,
                        'total_chunks': pending.total_chunks,
                        'from': pending.src_addr
                    }
                )
                
                # Cleanup
                del self.pending_messages[chunk_id]
                if chunk_id in self.timeout_tasks:
                    del self.timeout_tasks[chunk_id]
                    
        except asyncio.CancelledError:
            pass  # Normal cancellation
    
    async def cleanup(self):
        """Cleanup pending messages and tasks"""
        # Cancel all timeout tasks
        for task in self.timeout_tasks.values():
            task.cancel()
        
        # Wait for cancellations
        if self.timeout_tasks:
            await asyncio.gather(*self.timeout_tasks.values(), return_exceptions=True)
        
        self.timeout_tasks.clear()
        self.pending_messages.clear()


def create_chunked_handler(node, chunk_size: int = 1000) -> ChunkedMessageHandler:
    """Factory function to create and configure a chunked message handler"""
    return ChunkedMessageHandler(node, chunk_size=chunk_size)