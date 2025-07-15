#!/usr/bin/env python3
"""
Simple WATR sender using the fixed implementation
"""
import sys
sys.path.insert(0, '/opt/watr/python')

from watr.packet_test_fixed import PacketSender, TestConfig

def main():
    print("🚀 WATR Packet Send Test (Fixed)")
    
    # Create config for sending
    config = TestConfig(
        interface="mon0",
        channel=1,
        count=10,
        interval=1.0,
        payload="Hello from WATR!",
        src_mac="00:11:22:33:44:55",
        dst_mac="66:77:88:99:AA:BB"
    )
    
    # Create sender and send packets
    sender = PacketSender(config)
    success = sender.send_packets()
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())