#!/usr/bin/env python3
"""
Simple WATR Protocol Example

This example demonstrates basic usage of the WATR protocol library.
"""

import watr
from watr.scapy_layers import WATRHeader, WATRPayload

def basic_api_example():
    """Example using the basic Python API"""
    print("=== Basic API Example ===")
    
    # Create protocol instance
    protocol = watr.Protocol()
    
    # Set protocol type
    protocol.set_header_field('type', 0x5741)  # 'WA' in hex
    
    # Craft a packet
    message = b"Hello from WATR!"
    packet = protocol.craft_packet(message)
    print(f"Created packet: {packet.hex()}")
    
    # Parse the packet
    parsed = protocol.parse_packet(packet)
    print(f"Parsed packet:")
    print(f"  Type: 0x{parsed['type']:04x}")
    print(f"  Length: {parsed['length']}")
    print(f"  Payload: {parsed['payload']}")
    

def scapy_example():
    """Example using Scapy integration"""
    print("\n=== Scapy Integration Example ===")
    
    # Create WATR packet with Scapy
    packet = WATRHeader(type=0x5741, length=0) / WATRPayload(data="Scapy + WATR!")
    
    # Show packet structure
    print("Packet structure:")
    packet.show()
    
    # Convert to bytes
    packet_bytes = bytes(packet)
    print(f"\nPacket bytes ({len(packet_bytes)}): {packet_bytes.hex()}")
    
    # Parse back
    parsed = WATRHeader(packet_bytes)
    if parsed.haslayer(WATRPayload):
        print(f"Parsed payload: {parsed[WATRPayload].data}")


def bootstrap_example():
    """Example using the bootstrap utility"""
    print("\n=== Bootstrap Example ===")
    
    try:
        from watr.bootstrap import get_adapter_info
        
        # This would normally detect adapters, but we'll show the structure
        print("Bootstrap would detect:")
        print("- WiFi adapters (onboard and USB)")
        print("- Bluetooth adapters")
        print("- Monitor mode capabilities")
        print("- Saves to /tmp/watr_adapters.json")
        
    except ImportError:
        print("Bootstrap module not available in this context")


def packet_test_example():
    """Example of packet testing setup"""
    print("\n=== Packet Test Example ===")
    
    print("Packet testing configuration:")
    print("""
from watr.packet_test import PacketSender, PacketReceiver, TestConfig

# Sender configuration
send_config = TestConfig(
    interface="wlan1",        # Monitor-capable interface
    channel=6,                # WiFi channel
    count=10,                 # Number of packets
    interval=1.0,             # Seconds between packets
    payload="Test message"    # Payload content
)

# Create and run sender
sender = PacketSender(send_config)
sender.send_packets()      # Requires sudo

# Receiver configuration
recv_config = TestConfig(interface="wlan1", channel=6)
receiver = PacketReceiver(recv_config)
receiver.start_sniffing()  # Requires sudo
""")


def main():
    """Run all examples"""
    print("WATR Protocol Examples")
    print("=" * 50)
    
    basic_api_example()
    scapy_example()
    bootstrap_example()
    packet_test_example()
    
    print("\n" + "=" * 50)
    print("For more examples, see the documentation and test files.")


if __name__ == "__main__":
    main()