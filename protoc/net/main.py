#!/usr/bin/env python3
"""
WATR Node Application Entry Point
Main application for running a WATR node with conversation accumulation
"""

import asyncio
import sys
import signal
from typing import List

from watr_node import WATRNode
from watr_handlers import ConversationAccumulatorHandler, handle_completed_conversation


def show_usage():
    """Display usage information"""
    print("Usage: python main.py <interface> <node_address> [options]")
    print("\nArguments:")
    print("  interface     WiFi interface name (e.g., wlan0, wlp2s0)")
    print("  node_address  MAC address for this node (e.g., 00:11:22:33:44:55)")
    print("\nOptions:")
    print("  --heartbeat-interval SECONDS  Heartbeat interval (default: 60)")
    print("  --conversation-timeout SECONDS  Conversation timeout (default: 420)")
    print("  --help                        Show this help message")
    print("\nExamples:")
    print("  python main.py wlan0 00:11:22:33:44:55")
    print("  python main.py wlp2s0 aa:bb:cc:dd:ee:ff --heartbeat-interval 30")


def parse_arguments() -> dict:
    """Parse command line arguments"""
    args = sys.argv[1:]
    
    if not args or '--help' in args:
        show_usage()
        sys.exit(0)
    
    if len(args) < 2:
        print("Error: Missing required arguments")
        show_usage()
        sys.exit(1)
    
    config = {
        'interface': args[0],
        'node_addr': args[1],
        'heartbeat_interval': 60,
        'conversation_timeout': 420.0
    }
    
    # Parse optional arguments
    i = 2
    while i < len(args):
        if args[i] == '--heartbeat-interval' and i + 1 < len(args):
            try:
                config['heartbeat_interval'] = int(args[i + 1])
                i += 2
            except ValueError:
                print(f"Error: Invalid heartbeat interval: {args[i + 1]}")
                sys.exit(1)
        elif args[i] == '--conversation-timeout' and i + 1 < len(args):
            try:
                config['conversation_timeout'] = float(args[i + 1])
                i += 2
            except ValueError:
                print(f"Error: Invalid conversation timeout: {args[i + 1]}")
                sys.exit(1)
        else:
            print(f"Error: Unknown argument: {args[i]}")
            show_usage()
            sys.exit(1)
    
    return config


def validate_mac_address(mac_addr: str) -> bool:
    """Validate MAC address format"""
    parts = mac_addr.split(':')
    if len(parts) != 6:
        return False
    
    for part in parts:
        if len(part) != 2:
            return False
        try:
            int(part, 16)
        except ValueError:
            return False
    
    return True


async def setup_conversation_handler(node: WATRNode, timeout: float) -> ConversationAccumulatorHandler:
    """Setup and load the conversation accumulator handler"""
    conv_handler = ConversationAccumulatorHandler(node, conversation_timeout=timeout)
    
    # Add the default completion handler
    conv_handler.add_completion_handler(handle_completed_conversation)
    
    # Add custom completion handler for demonstration
    def custom_completion_handler(conversation):
        """Custom handler that could save to file, process with AI, etc."""
        print(f"Custom handler: Processing conversation from {conversation.src_addr}")
        print(f"  Word count: {len(conversation.complete_text.split())}")
        print(f"  Character count: {len(conversation.complete_text)}")
        # Here you could add custom logic like:
        # - Save to database
        # - Process with another AI model
        # - Forward to other nodes
        # - Analyze sentiment
        # - etc.
    
    conv_handler.add_completion_handler(custom_completion_handler)
    
    # Load the handler
    success = await node.load_handler("conversation_accumulator", conv_handler)
    if not success:
        raise Exception("Failed to load conversation accumulator handler")
    
    return conv_handler


async def interactive_commands(node: WATRNode):
    """Handle interactive commands from user"""
    print("\nInteractive commands:")
    print("  'chat <message>' - Send a chat message")
    print("  'handlers' - List loaded handlers")
    print("  'status' - Show node status")
    print("  'quit' - Exit the application")
    print("  'help' - Show this help\n")
    
    while node.is_running():
        try:
            # Simple input simulation - in a real app you might use aioconsole
            await asyncio.sleep(1)
            # For now, just keep the node running
            # In a full implementation, you'd add actual command input here
            
        except KeyboardInterrupt:
            break


def setup_signal_handlers(node: WATRNode):
    """Setup signal handlers for graceful shutdown"""
    def signal_handler(signum, frame):
        print(f"\nReceived signal {signum}, shutting down...")
        # Cancel all tasks to trigger cleanup
        for task in asyncio.all_tasks():
            task.cancel()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


async def main():
    """Main application entry point"""
    # Parse command line arguments
    config = parse_arguments()
    
    # Validate MAC address
    if not validate_mac_address(config['node_addr']):
        print(f"Error: Invalid MAC address format: {config['node_addr']}")
        print("Expected format: XX:XX:XX:XX:XX:XX (e.g., 00:11:22:33:44:55)")
        sys.exit(1)
    
    print(f"Starting WATR Node...")
    print(f"  Interface: {config['interface']}")
    print(f"  Node Address: {config['node_addr']}")
    print(f"  Heartbeat Interval: {config['heartbeat_interval']}s")
    print(f"  Conversation Timeout: {config['conversation_timeout']}s")
    
    # Create and configure node
    node = WATRNode(
        interface=config['interface'],
        node_addr=config['node_addr'],
        heartbeat_interval=config['heartbeat_interval']
    )
    
    try:
        # Setup signal handlers
        setup_signal_handlers(node)
        
        # Start the node
        await node.start()
        
        # Setup conversation handler
        await setup_conversation_handler(node, config['conversation_timeout'])
        
        print(f"\nWATR Node is running. Press Ctrl+C to stop.")
        print(f"Loaded handlers: {list(node.list_handlers().keys())}")
        
        # Send an initial chat message after startup
        print("\nSending initial test chat...")
        await asyncio.sleep(2)  # Give the system time to initialize
        await node.chat("Hello from WATR Node! This is a test message.")
        
        # Keep the node running
        await interactive_commands(node)
        
    except asyncio.CancelledError:
        print("Application cancelled")
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup
        print("Stopping node...")
        await node.stop()
        print("WATR Node stopped.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)