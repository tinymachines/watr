"""
WATR Network Logging Configuration
Comprehensive logging for mesh network analysis and debugging
"""

import logging
import logging.handlers
import json
import time
import sys
from pathlib import Path
from typing import Dict, Any, Optional


class WATRFormatter(logging.Formatter):
    """Custom formatter for WATR network logs with structured data"""
    
    def format(self, record):
        # Standard timestamp and level
        formatted = super().format(record)
        
        # Add node context if available
        if hasattr(record, 'node_id'):
            formatted = f"[{record.node_id[:8]}] {formatted}"
        if hasattr(record, 'node_name'):
            formatted = f"[{record.node_name}] {formatted}"
            
        # Add message type context
        if hasattr(record, 'msg_type'):
            formatted = f"[{record.msg_type}] {formatted}"
            
        # Add peer context
        if hasattr(record, 'peer_addr'):
            formatted = f"[→{record.peer_addr}] {formatted}"
        if hasattr(record, 'src_addr'):
            formatted = f"[←{record.src_addr}] {formatted}"
            
        return formatted


class WATRJSONFormatter(logging.Formatter):
    """JSON formatter for machine-readable logs"""
    
    def format(self, record):
        log_entry = {
            'timestamp': time.time(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add all custom attributes
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 
                          'filename', 'module', 'lineno', 'funcName', 'created', 
                          'msecs', 'relativeCreated', 'thread', 'threadName', 
                          'processName', 'process', 'stack_info', 'exc_info', 'exc_text']:
                log_entry[key] = value
                
        return json.dumps(log_entry)


def setup_watr_logging(
    node_name: str = "watr_node",
    log_level: str = "INFO",
    log_dir: str = "logs",
    enable_console: bool = True,
    enable_file: bool = True,
    enable_json: bool = True,
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5
) -> Dict[str, logging.Logger]:
    """
    Setup comprehensive logging for WATR network
    
    Returns dict of specialized loggers for different components
    """
    
    # Create logs directory
    log_path = Path(log_dir)
    log_path.mkdir(exist_ok=True)
    
    # Clear any existing handlers
    logging.getLogger().handlers.clear()
    
    loggers = {}
    
    # Define logger categories with their purposes
    logger_configs = {
        'watr.protocol': {
            'level': log_level,
            'description': 'Protocol-level frame handling'
        },
        'watr.node': {
            'level': log_level, 
            'description': 'Node lifecycle and management'
        },
        'watr.handlers': {
            'level': log_level,
            'description': 'Message handler operations'
        },
        'watr.social': {
            'level': log_level,
            'description': 'Social interactions and behaviors'
        },
        'watr.llm': {
            'level': log_level,
            'description': 'LLM interactions and responses'
        },
        'watr.self': {
            'level': log_level,
            'description': 'Self-awareness and peer discovery'
        },
        'watr.conversation': {
            'level': log_level,
            'description': 'Conversation accumulation and analysis'
        },
        'watr.network': {
            'level': log_level,
            'description': 'Network-wide events and analysis'
        },
        'watr.performance': {
            'level': log_level,
            'description': 'Performance metrics and timing'
        }
    }
    
    # Create formatters
    console_formatter = WATRFormatter(
        '%(asctime)s | %(levelname)-8s | %(name)-15s | %(message)s',
        datefmt='%H:%M:%S'
    )
    
    file_formatter = WATRFormatter(
        '%(asctime)s | %(levelname)-8s | %(name)-20s | %(module)-15s:%(lineno)-4d | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    json_formatter = WATRJSONFormatter()
    
    # Setup each logger
    for logger_name, config in logger_configs.items():
        logger = logging.getLogger(logger_name)
        logger.setLevel(getattr(logging, config['level']))
        logger.propagate = False  # Don't propagate to root logger
        
        # Console handler
        if enable_console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(getattr(logging, log_level))
            console_handler.setFormatter(console_formatter)
            logger.addHandler(console_handler)
        
        # File handler (rotating)
        if enable_file:
            log_file = log_path / f"{node_name}_{logger_name.replace('.', '_')}.log"
            file_handler = logging.handlers.RotatingFileHandler(
                log_file, maxBytes=max_bytes, backupCount=backup_count
            )
            file_handler.setLevel(getattr(logging, log_level))
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
        
        # JSON file handler
        if enable_json:
            json_file = log_path / f"{node_name}_{logger_name.replace('.', '_')}.json"
            json_handler = logging.handlers.RotatingFileHandler(
                json_file, maxBytes=max_bytes, backupCount=backup_count
            )
            json_handler.setLevel(getattr(logging, log_level))
            json_handler.setFormatter(json_formatter)
            logger.addHandler(json_handler)
        
        loggers[logger_name] = logger
    
    # Create master network events logger
    network_logger = logging.getLogger('watr.network.events')
    network_logger.setLevel(logging.INFO)
    
    if enable_file:
        events_file = log_path / f"{node_name}_network_events.log"
        events_handler = logging.handlers.RotatingFileHandler(
            events_file, maxBytes=max_bytes, backupCount=backup_count
        )
        events_handler.setLevel(logging.INFO)
        events_handler.setFormatter(file_formatter)
        network_logger.addHandler(events_handler)
    
    loggers['watr.network.events'] = network_logger
    
    # Log the logging setup
    setup_logger = logging.getLogger('watr.logging')
    setup_logger.info(
        "WATR logging initialized",
        extra={
            'node_name': node_name,
            'log_level': log_level,
            'log_dir': str(log_path),
            'loggers_created': len(loggers),
            'console_enabled': enable_console,
            'file_enabled': enable_file,
            'json_enabled': enable_json
        }
    )
    
    return loggers


class WATRLoggerMixin:
    """Mixin class to add logging capabilities to WATR components"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._setup_component_logging()
    
    def _setup_component_logging(self):
        """Setup logging for this component"""
        component_name = self.__class__.__name__.lower()
        
        # Map component names to logger categories
        logger_map = {
            'watrprotocol': 'watr.protocol',
            'watrnode': 'watr.node', 
            'watrhandler': 'watr.handlers',
            'conversationaccumulatorhandler': 'watr.conversation',
            'socialhandler': 'watr.social',
            'llmsocialhandler': 'watr.llm',
            'selfhandler': 'watr.self',
            'handlermanager': 'watr.handlers'
        }
        
        logger_name = logger_map.get(component_name, 'watr.handlers')
        self.logger = logging.getLogger(logger_name)
        
        # Add node context if available
        if hasattr(self, 'node') and hasattr(self.node, 'get_node_addr'):
            self.node_addr = self.node.get_node_addr()
        elif hasattr(self, 'src_addr'):
            self.node_addr = self.src_addr
        else:
            self.node_addr = 'unknown'
            
        # Create extra context for all logs from this component
        self.log_extra = {
            'component': self.__class__.__name__,
            'node_addr': self.node_addr
        }
    
    def log_message_received(self, message, extra_context=None):
        """Log received message with full context"""
        context = {**self.log_extra, 'direction': 'received'}
        if extra_context:
            context.update(extra_context)
            
        context.update({
            'msg_type': message.message_type,
            'src_addr': message.src_addr,
            'dst_addr': message.dst_addr,
            'timestamp': message.timestamp,
            'payload_keys': list(message.payload.keys()) if message.payload else []
        })
        
        self.logger.info(
            f"Received {message.message_type} from {message.src_addr}",
            extra=context
        )
        
        # Log payload details at debug level
        self.logger.debug(
            f"Message payload: {message.payload}",
            extra=context
        )
    
    def log_message_sent(self, message_type, payload, dst_addr, extra_context=None):
        """Log sent message with full context"""
        context = {**self.log_extra, 'direction': 'sent'}
        if extra_context:
            context.update(extra_context)
            
        context.update({
            'msg_type': message_type,
            'dst_addr': dst_addr,
            'payload_keys': list(payload.keys()) if payload else []
        })
        
        self.logger.info(
            f"Sent {message_type} to {dst_addr or 'broadcast'}",
            extra=context
        )
        
        self.logger.debug(
            f"Sent payload: {payload}",
            extra=context
        )
    
    def log_state_change(self, old_state, new_state, reason="", extra_context=None):
        """Log state changes"""
        context = {**self.log_extra, 'event_type': 'state_change'}
        if extra_context:
            context.update(extra_context)
            
        context.update({
            'old_state': old_state,
            'new_state': new_state,
            'reason': reason
        })
        
        self.logger.info(
            f"State change: {old_state} → {new_state} ({reason})",
            extra=context
        )
    
    def log_performance(self, operation, duration, extra_context=None):
        """Log performance metrics"""
        perf_logger = logging.getLogger('watr.performance')
        context = {**self.log_extra, 'event_type': 'performance'}
        if extra_context:
            context.update(extra_context)
            
        context.update({
            'operation': operation,
            'duration_ms': duration * 1000,
            'duration_s': duration
        })
        
        perf_logger.info(
            f"Performance: {operation} took {duration*1000:.2f}ms",
            extra=context
        )
    
    def log_error(self, error, context_msg="", extra_context=None):
        """Log errors with full context"""
        context = {**self.log_extra, 'event_type': 'error'}
        if extra_context:
            context.update(extra_context)
            
        context.update({
            'error_type': type(error).__name__,
            'error_msg': str(error)
        })
        
        self.logger.error(
            f"Error {context_msg}: {error}",
            extra=context,
            exc_info=True
        )
    
    def log_llm_interaction(self, prompt, response, model, duration=None, extra_context=None):
        """Log LLM interactions"""
        llm_logger = logging.getLogger('watr.llm')
        context = {**self.log_extra, 'event_type': 'llm_interaction'}
        if extra_context:
            context.update(extra_context)
            
        context.update({
            'model': model,
            'prompt_length': len(prompt),
            'response_length': len(response),
            'prompt_preview': prompt[:100] + "..." if len(prompt) > 100 else prompt,
            'response_preview': response[:100] + "..." if len(response) > 100 else response
        })
        
        if duration:
            context['duration_s'] = duration
            
        llm_logger.info(
            f"LLM interaction: {model} responded in {duration:.2f}s" if duration else f"LLM interaction: {model}",
            extra=context
        )
    
    def log_network_event(self, event_type, description, extra_context=None):
        """Log network-wide events"""
        network_logger = logging.getLogger('watr.network.events')
        context = {**self.log_extra, 'event_type': event_type}
        if extra_context:
            context.update(extra_context)
            
        network_logger.info(
            f"Network event [{event_type}]: {description}",
            extra=context
        )


def get_logger(category: str) -> logging.Logger:
    """Get a logger for a specific category"""
    return logging.getLogger(f'watr.{category}')


def log_network_topology(nodes_discovered, total_capabilities, gossip_count, vote_count):
    """Log current network topology snapshot"""
    network_logger = logging.getLogger('watr.network.events')
    
    context = {
        'event_type': 'topology_snapshot',
        'nodes_discovered': nodes_discovered,
        'total_capabilities': total_capabilities,
        'active_gossip': gossip_count,
        'active_votes': vote_count,
        'snapshot_time': time.time()
    }
    
    network_logger.info(
        f"Network topology: {nodes_discovered} nodes, {total_capabilities} capabilities, {gossip_count} gossip, {vote_count} votes",
        extra=context
    )


def log_protocol_evolution(old_handlers, new_handlers, node_name):
    """Log protocol evolution events"""
    network_logger = logging.getLogger('watr.network.events')
    
    added = set(new_handlers) - set(old_handlers)
    removed = set(old_handlers) - set(new_handlers)
    
    context = {
        'event_type': 'protocol_evolution',
        'node_name': node_name,
        'handlers_added': list(added),
        'handlers_removed': list(removed),
        'total_handlers': len(new_handlers)
    }
    
    if added or removed:
        network_logger.info(
            f"Protocol evolution on {node_name}: +{len(added)} -{len(removed)} handlers",
            extra=context
        )