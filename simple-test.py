#!/usr/bin/env python3
"""
Simple test to verify WATR packet structure
"""

import sys
sys.path.insert(0, '/opt/watr/python')

from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt
from watr.scapy_layers import WATRHeader, WATRPayload

print("🧪 WATR Packet Structure Test")
print("=" * 40)

# Test 1: Create WATR packet
print("\nTest 1: Create WATR packet")
payload_text = "Hello WATR!"
watr = WATRHeader(type=0x5741, length=len(payload_text)) / WATRPayload(data=payload_text)
print(f"WATR packet: {watr.summary()}")

# Convert to bytes
watr_bytes = bytes(watr)
print(f"WATR bytes ({len(watr_bytes)}): {watr_bytes.hex()}")

# Test 2: Parse WATR packet from bytes
print("\nTest 2: Parse WATR packet from bytes")
try:
    parsed = WATRHeader(watr_bytes)
    print(f"Parsed type: 0x{parsed.type:04x}")
    print(f"Parsed length: {parsed.length}")
    if parsed.haslayer(WATRPayload):
        print(f"Parsed payload: '{parsed[WATRPayload].data}'")
    else:
        print("No payload layer found!")
except Exception as e:
    print(f"Error parsing: {e}")

# Test 3: Create beacon with WATR
print("\nTest 3: Create beacon with WATR")
dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="02:00:00:00:00:01", addr3="02:00:00:00:00:01")
beacon = Dot11Beacon()
ssid = Dot11Elt(ID=0, len=9, info=b"WATR-TEST")
vendor = Dot11Elt(ID=221, len=len(watr_bytes), info=watr_bytes)

packet = RadioTap() / dot11 / beacon / ssid / vendor
print(f"Full packet: {packet.summary()}")

# Test 4: Extract elements from beacon
print("\nTest 4: Extract elements from beacon")
# Remove RadioTap for parsing
beacon_frame = packet[Dot11]
if beacon_frame.haslayer(Dot11Elt):
    print("Elements found!")
    elt = beacon_frame[Dot11Elt]
    elt_count = 0
    while elt:
        elt_count += 1
        print(f"  Element {elt_count}: ID={elt.ID}, len={elt.len}")
        if elt.ID == 0:
            print(f"    SSID: {elt.info}")
        elif elt.ID == 221:
            print(f"    Vendor data ({len(elt.info)} bytes): {elt.info.hex()}")
            # Try parsing as WATR
            try:
                watr_parsed = WATRHeader(elt.info)
                print(f"    Parsed WATR: type=0x{watr_parsed.type:04x}, len={watr_parsed.length}")
                if watr_parsed.haslayer(WATRPayload):
                    print(f"    Payload: '{watr_parsed[WATRPayload].data}'")
            except Exception as e:
                print(f"    Error parsing WATR: {e}")
        
        # Get next element
        elt = elt.payload if hasattr(elt, 'payload') and elt.payload else None

print("\n✅ Test complete!")