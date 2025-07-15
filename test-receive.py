#!/usr/bin/env python3
"""
Simple packet receive test for WATR
"""

import sys
import os
import signal
sys.path.insert(0, '/opt/watr/python')

from watr.packet_test import PacketReceiver, TestConfig, get_monitor_interface

def main():
    print("🚀 WATR Packet Receive Test")
    
    # Get monitor interface
    interface = get_monitor_interface()
    if not interface:
        print("❌ No monitor-capable interface found")
        return 1
    
    print(f"📡 Using interface: {interface}")
    
    # Create config
    config = TestConfig(
        interface=interface,
        channel=6,
        count=10,  # Not used for receive
        interval=1.0,  # Not used for receive
        payload=""  # Not used for receive
    )
    
    # Create receiver
    receiver = PacketReceiver(config)
    
    # Set up signal handler for clean shutdown
    def signal_handler(signum, frame):
        print("\n🛑 Stopping reception...")
        receiver.stop_sniffing()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start receiving
    success = receiver.start_sniffing()
    receiver.print_summary()
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())