#!/usr/bin/env python3
"""
Simple packet send test for WATR
"""

import sys
import os
sys.path.insert(0, '/opt/watr/python')

from watr.packet_test import PacketSender, TestConfig, get_monitor_interface

def main():
    print("🚀 WATR Packet Send Test")
    
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
        count=3,
        interval=1.0,
        payload="Hello from WATR!"
    )
    
    # Create sender and send packets
    sender = PacketSender(config)
    success = sender.send_packets()
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())