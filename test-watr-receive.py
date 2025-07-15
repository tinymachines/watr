#!/usr/bin/env python3
"""
Simple WATR receiver using the fixed implementation
"""
import sys
import signal
sys.path.insert(0, '/opt/watr/python')

from watr.packet_test_fixed import PacketReceiver, TestConfig

def main():
    print("🚀 WATR Packet Receive Test (Fixed)")
    
    # Create config for receiving
    config = TestConfig(
        interface="mon0",
        channel=1
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