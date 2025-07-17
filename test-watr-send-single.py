#!/usr/bin/env python3
"""
Send a single WATR packet for debugging
"""
import sys
sys.path.insert(0, '/opt/watr/python')

from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, LLC, SNAP
from scapy.layers.l2 import Raw

# Custom protocol ID for WATR
WATR_PROTOCOL_ID = 0x8999

def send_single_watr_packet():
    """Send a single WATR packet and show its structure"""
    
    print("🚀 Sending single WATR packet for debugging")
    
    # Create WATR payload (simplified)
    # WATR header: type (2 bytes) + length (4 bytes)
    watr_type = 0x5741  # 'WA'
    payload_text = "Debug WATR packet"
    watr_length = len(payload_text)
    
    # Pack WATR header + payload
    import struct
    watr_data = struct.pack('>HI', watr_type, watr_length) + payload_text.encode('utf-8')
    
    print(f"\n📦 WATR data structure:")
    print(f"   Type: 0x{watr_type:04x}")
    print(f"   Length: {watr_length}")
    print(f"   Payload: {payload_text}")
    print(f"   Raw WATR data ({len(watr_data)} bytes): {watr_data.hex()}")
    
    # Create 802.11 data frame
    dot11 = Dot11(
        type=2,  # Data
        subtype=0,  # Data
        addr1="ff:ff:ff:ff:ff:ff",  # Broadcast
        addr2="00:11:22:33:44:55",  # Source
        addr3="00:11:22:33:44:55",  # BSSID
        FCfield='from-DS'
    )
    
    # Create LLC layer
    llc = LLC(
        dsap=0xAA,  # SNAP
        ssap=0xAA,  # SNAP
        ctrl=0x03   # UI
    )
    
    # Create SNAP header with WATR protocol ID
    snap = SNAP(
        OUI=0x000000,
        code=WATR_PROTOCOL_ID  # 0x8999
    )
    
    # Combine all layers
    packet = RadioTap() / dot11 / llc / snap / Raw(load=watr_data)
    
    print(f"\n📡 Packet structure:")
    packet.show()
    
    # Send packet
    try:
        sendp(packet, iface="mon0", verbose=True)
        print(f"\n✓ Packet sent successfully!")
        
        # Show hex dump of the packet
        print(f"\n🔍 Packet hex dump:")
        hexdump(packet)
        
    except Exception as e:
        print(f"\n❌ Error sending packet: {e}")
        return False
    
    return True

if __name__ == "__main__":
    success = send_single_watr_packet()
    sys.exit(0 if success else 1)