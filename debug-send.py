#!/usr/bin/env python3
"""
Enhanced WATR packet sender with debugging
"""

import sys
import os
import time
sys.path.insert(0, '/opt/watr/python')

from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt
from watr.scapy_layers import WATRHeader, WATRPayload
from watr.packet_test import TestConfig, get_monitor_interface
import subprocess

class DebugSender:
    def __init__(self, interface):
        self.interface = interface
        self.channel = 6
        self.count = 5
        self.interval = 2.0
        
    def setup_monitor_mode(self):
        """Set up monitor mode with verification"""
        try:
            print(f"📡 Setting up monitor mode on {self.interface}...")
            
            # Take down
            subprocess.run(f"sudo ip link set {self.interface} down", shell=True, check=True)
            
            # Set monitor mode
            subprocess.run(f"sudo iw dev {self.interface} set type monitor", shell=True, check=True)
            
            # Bring up
            subprocess.run(f"sudo ip link set {self.interface} up", shell=True, check=True)
            
            # Set channel
            subprocess.run(f"sudo iw dev {self.interface} set channel {self.channel}", shell=True, check=True)
            
            # Verify
            result = subprocess.run(f"iw dev {self.interface} info", shell=True, capture_output=True, text=True)
            print(f"✓ Interface info:\n{result.stdout}")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to set monitor mode: {e}")
            return False
    
    def restore_managed_mode(self):
        """Restore managed mode"""
        try:
            subprocess.run(f"sudo ip link set {self.interface} down", shell=True, check=True)
            subprocess.run(f"sudo iw dev {self.interface} set type managed", shell=True, check=True)
            subprocess.run(f"sudo ip link set {self.interface} up", shell=True, check=True)
            print(f"✓ Restored managed mode")
        except:
            pass
    
    def create_debug_packet(self, sequence):
        """Create a debug WATR packet"""
        print(f"\n🔨 Creating packet #{sequence}")
        
        # Create WATR packet
        payload_text = f"Hello from tm10 #{sequence}"
        watr_header = WATRHeader(
            type=0x5741,  # 'WA'
            length=len(payload_text)
        )
        watr_payload = WATRPayload(data=payload_text)
        watr_packet = watr_header / watr_payload
        
        print(f"   WATR packet created:")
        print(f"   - Type: 0x{watr_header.type:04x}")
        print(f"   - Length: {watr_header.length}")
        print(f"   - Payload: '{payload_text}'")
        
        # Convert to bytes
        watr_bytes = bytes(watr_packet)
        print(f"   - Total WATR bytes: {len(watr_bytes)}")
        print(f"   - Hex: {watr_bytes.hex()}")
        
        # Create beacon frame
        dot11 = Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="02:00:00:00:00:01",
            addr3="02:00:00:00:00:01"
        )
        
        beacon = Dot11Beacon(timestamp=int(time.time() * 1000000))
        
        # SSID element
        ssid_element = Dot11Elt(ID=0, len=9, info=b"WATR-TEST")
        
        # Vendor element with WATR data
        vendor_element = Dot11Elt(ID=221, len=len(watr_bytes), info=watr_bytes)
        
        # Build complete packet
        packet = RadioTap() / dot11 / beacon / ssid_element / vendor_element
        
        print(f"   📦 Complete packet structure:")
        print(f"   - RadioTap header")
        print(f"   - Dot11 (beacon to ff:ff:ff:ff:ff:ff)")
        print(f"   - Beacon timestamp")
        print(f"   - SSID element: 'WATR-TEST'")
        print(f"   - Vendor element: {len(watr_bytes)} bytes")
        
        return packet
    
    def send_packets(self):
        """Send debug packets"""
        if not self.setup_monitor_mode():
            return False
        
        try:
            print(f"\n📤 Starting packet transmission...")
            print(f"   Interface: {self.interface}")
            print(f"   Channel: {self.channel}")
            print(f"   Count: {self.count}")
            print(f"   Interval: {self.interval}s")
            
            for i in range(self.count):
                packet = self.create_debug_packet(i + 1)
                
                print(f"\n📡 Sending packet #{i + 1}...")
                sendp(packet, iface=self.interface, verbose=False)
                print(f"   ✓ Sent!")
                
                if i < self.count - 1:
                    print(f"   ⏳ Waiting {self.interval}s...")
                    time.sleep(self.interval)
            
            print(f"\n✅ All {self.count} packets sent!")
            return True
            
        except KeyboardInterrupt:
            print(f"\n⚠️  Stopped by user")
            return False
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            self.restore_managed_mode()

def main():
    # Get monitor interface
    interface = get_monitor_interface()
    if not interface:
        # On tm10, the interface name is different
        interface = "wlx842096fbfd0b"
        print(f"⚠️  Using hardcoded interface for tm10: {interface}")
    
    print(f"🚀 WATR Debug Sender")
    print(f"📡 Using interface: {interface}")
    
    sender = DebugSender(interface)
    success = sender.send_packets()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())