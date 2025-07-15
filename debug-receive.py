#!/usr/bin/env python3
"""
Enhanced WATR packet receiver with debugging
"""

import sys
import os
import signal
import time
sys.path.insert(0, '/opt/watr/python')

from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt
from watr.scapy_layers import WATRHeader, WATRPayload
from watr.packet_test import TestConfig, get_monitor_interface
import subprocess

class DebugReceiver:
    def __init__(self, interface):
        self.interface = interface
        self.channel = 6
        self.running = False
        self.packet_count = 0
        self.beacon_count = 0
        self.watr_count = 0
        
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
    
    def packet_handler(self, packet):
        """Enhanced packet handler with debugging"""
        try:
            self.packet_count += 1
            
            # Check for beacon frames
            if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 8:
                self.beacon_count += 1
                
                # Check source MAC
                src_mac = packet[Dot11].addr2
                if src_mac == "02:00:00:00:00:01":
                    print(f"\n🎯 Found beacon from WATR sender! (packet #{self.packet_count})")
                    
                    # Look for elements
                    if packet.haslayer(Dot11Elt):
                        print(f"   Elements present in beacon")
                        
                        # Better element parsing
                        ssid_found = False
                        watr_data = None
                        
                        # Get first element
                        current_elt = packet[Dot11Elt]
                        element_count = 0
                        
                        while current_elt:
                            element_count += 1
                            print(f"   Element {element_count}: ID={current_elt.ID}, len={current_elt.len}")
                            
                            if current_elt.ID == 0:  # SSID
                                ssid = current_elt.info.decode('utf-8', errors='ignore')
                                print(f"     SSID: '{ssid}'")
                                if current_elt.info == b"WATR-TEST":
                                    ssid_found = True
                                    print(f"     ✓ WATR-TEST SSID found!")
                                    
                            elif current_elt.ID == 221:  # Vendor specific
                                print(f"     Vendor element found! Length: {len(current_elt.info)}")
                                print(f"     Raw data: {current_elt.info.hex()}")
                                watr_data = current_elt.info
                            
                            # Move to next element
                            if hasattr(current_elt, 'payload') and current_elt.payload:
                                try:
                                    # Try to get next Dot11Elt from payload
                                    next_payload = current_elt.payload
                                    if isinstance(next_payload, Dot11Elt):
                                        current_elt = next_payload
                                    elif hasattr(next_payload, 'getlayer') and next_payload.haslayer(Dot11Elt):
                                        current_elt = next_payload.getlayer(Dot11Elt)
                                    else:
                                        break
                                except:
                                    break
                            else:
                                break
                        
                        if ssid_found and watr_data:
                            print(f"\n🎉 WATR packet found!")
                            self.watr_count += 1
                            
                            # Try to parse WATR packet
                            try:
                                watr_packet = WATRHeader(watr_data)
                                print(f"   WATR Header: type=0x{watr_packet.type:04x}, length={watr_packet.length}")
                                
                                if watr_packet.haslayer(WATRPayload):
                                    payload = watr_packet[WATRPayload].data
                                    print(f"   WATR Payload: '{payload}'")
                                else:
                                    print(f"   No WATRPayload layer found")
                                    
                            except Exception as e:
                                print(f"   Error parsing WATR packet: {e}")
                                print(f"   Raw WATR data length: {len(watr_data)}")
                
                # Show periodic stats
                if self.beacon_count % 100 == 0:
                    print(f"📊 Stats: {self.packet_count} packets, {self.beacon_count} beacons, {self.watr_count} WATR")
                    
        except Exception as e:
            # Ignore parsing errors for non-relevant packets
            pass
    
    def start_receiving(self):
        """Start receiving packets"""
        if not self.setup_monitor_mode():
            return False
        
        try:
            print(f"\n📥 Starting packet reception...")
            print(f"   Interface: {self.interface}")
            print(f"   Channel: {self.channel}")
            print(f"   Looking for WATR beacons...")
            print(f"   Press Ctrl+C to stop\n")
            
            self.running = True
            
            # Sniff without filter to see all packets
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                stop_filter=lambda x: not self.running,
                store=False
            )
            
            return True
            
        except KeyboardInterrupt:
            print(f"\n⚠️  Stopped by user")
            return False
        except Exception as e:
            print(f"❌ Error: {e}")
            return False
        finally:
            self.running = False
            print(f"\n📊 Final stats: {self.packet_count} packets, {self.beacon_count} beacons, {self.watr_count} WATR")
            self.restore_managed_mode()

def main():
    # Get monitor interface
    interface = get_monitor_interface()
    if not interface:
        print("❌ No monitor-capable interface found")
        return 1
    
    print(f"🚀 WATR Debug Receiver")
    print(f"📡 Using interface: {interface}")
    
    receiver = DebugReceiver(interface)
    
    # Signal handler
    def signal_handler(signum, frame):
        print("\n🛑 Stopping...")
        receiver.running = False
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    success = receiver.start_receiving()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())