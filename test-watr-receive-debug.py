#!/usr/bin/env python3
"""
Debug version of WATR receiver to diagnose packet reception issues
"""
import sys
import signal
import time
sys.path.insert(0, '/opt/watr/python')

from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, LLC, SNAP
from scapy.layers.l2 import Raw

# Custom protocol ID for WATR
WATR_PROTOCOL_ID = 0x8999

class DebugReceiver:
    def __init__(self, interface="mon0"):
        self.interface = interface
        self.running = False
        self.packet_count = 0
        self.data_frame_count = 0
        self.llc_count = 0
        self.snap_count = 0
        self.watr_count = 0
        self.start_time = None
        
    def packet_handler(self, packet):
        """Debug packet handler with detailed logging"""
        self.packet_count += 1
        
        # Check if it's a Dot11 packet
        if packet.haslayer(Dot11):
            # Check if it's a data frame
            if packet[Dot11].type == 2:
                self.data_frame_count += 1
                
                # Show data frame info every 10 data frames
                if self.data_frame_count % 10 == 1:
                    print(f"\n🔍 Data frame #{self.data_frame_count}:")
                    print(f"   Type: {packet[Dot11].type}, Subtype: {packet[Dot11].subtype}")
                    print(f"   From: {packet[Dot11].addr2} -> {packet[Dot11].addr1}")
                
                # Check for LLC layer
                if packet.haslayer(LLC):
                    self.llc_count += 1
                    llc = packet[LLC]
                    
                    # Check for SNAP
                    if llc.dsap == 0xAA and llc.ssap == 0xAA and packet.haslayer(SNAP):
                        self.snap_count += 1
                        snap = packet[SNAP]
                        
                        # Show SNAP info for debugging
                        if self.snap_count <= 5 or snap.code == WATR_PROTOCOL_ID:
                            print(f"\n📦 SNAP packet found:")
                            print(f"   OUI: 0x{snap.OUI:06x}")
                            print(f"   Protocol ID: 0x{snap.code:04x} (looking for 0x{WATR_PROTOCOL_ID:04x})")
                        
                        # Check if it's WATR protocol
                        if snap.code == WATR_PROTOCOL_ID:
                            self.watr_count += 1
                            print(f"\n🎯 WATR PACKET RECEIVED! #{self.watr_count}")
                            
                            # Extract and show raw data
                            if packet.haslayer(Raw):
                                raw_data = packet[Raw].load
                                print(f"   Raw data ({len(raw_data)} bytes): {raw_data.hex()[:64]}...")
                                
                                # Try to parse as text if possible
                                try:
                                    # Skip WATR header (first 6 bytes) and show payload
                                    if len(raw_data) > 6:
                                        payload = raw_data[6:].decode('utf-8', errors='replace')
                                        print(f"   Payload text: {payload}")
                                except:
                                    pass
                            
                            packet.show()
        
        # Show status every 100 packets
        if self.packet_count % 100 == 0:
            elapsed = time.time() - self.start_time
            print(f"\n📊 Status after {self.packet_count} packets ({elapsed:.1f}s):")
            print(f"   Data frames: {self.data_frame_count}")
            print(f"   LLC frames: {self.llc_count}")
            print(f"   SNAP frames: {self.snap_count}")
            print(f"   WATR packets: {self.watr_count}")
            print(f"   Packets/sec: {self.packet_count / elapsed:.1f}")
    
    def start_sniffing(self):
        """Start packet sniffing with debug output"""
        try:
            print(f"🔍 WATR Debug Receiver")
            print(f"   Interface: {self.interface}")
            print(f"   Looking for protocol ID: 0x{WATR_PROTOCOL_ID:04x}")
            print(f"   Press Ctrl+C to stop")
            print()
            
            self.running = True
            self.start_time = time.time()
            
            # Use broader filter to catch all data frames
            filter_str = "type data"
            
            # Start sniffing
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                filter=filter_str,
                stop_filter=lambda x: not self.running
            )
            
            return True
            
        except KeyboardInterrupt:
            print(f"\n⚠️  Reception interrupted by user")
            return False
        except Exception as e:
            print(f"❌ Error during reception: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            self.running = False
            self.print_summary()
    
    def stop_sniffing(self):
        """Stop packet sniffing"""
        self.running = False
    
    def print_summary(self):
        """Print detailed reception summary"""
        if self.start_time:
            elapsed = time.time() - self.start_time
        else:
            elapsed = 0
            
        print(f"\n📊 FINAL RECEPTION SUMMARY")
        print(f"   Duration: {elapsed:.1f} seconds")
        print(f"   Total packets seen: {self.packet_count}")
        print(f"   Data frames: {self.data_frame_count}")
        print(f"   LLC frames: {self.llc_count}")
        print(f"   SNAP frames: {self.snap_count}")
        print(f"   WATR packets: {self.watr_count}")
        
        if elapsed > 0:
            print(f"   Packets/sec: {self.packet_count / elapsed:.1f}")
            print(f"   Data frames/sec: {self.data_frame_count / elapsed:.1f}")

def main():
    # Create receiver
    receiver = DebugReceiver("mon0")
    
    # Set up signal handler for clean shutdown
    def signal_handler(signum, frame):
        print("\n🛑 Stopping reception...")
        receiver.stop_sniffing()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start receiving
    success = receiver.start_sniffing()
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())