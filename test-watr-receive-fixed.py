#!/usr/bin/env python3
"""
Fixed WATR receiver that properly handles packet structure
"""
import sys
import signal
import struct
sys.path.insert(0, '/opt/watr/python')

from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, LLC, SNAP
from scapy.layers.l2 import Raw

# Custom protocol ID for WATR
WATR_PROTOCOL_ID = 0x8999

class FixedReceiver:
    def __init__(self, interface="mon0"):
        self.interface = interface
        self.running = False
        self.received_count = 0
        self.watr_packets = []
        
    def packet_handler(self, packet):
        """Handle received packets"""
        try:
            # Check for data frames with our custom protocol
            if (packet.haslayer(Dot11) and 
                packet[Dot11].type == 2 and 
                packet[Dot11].subtype == 0 and
                packet.haslayer(SNAP) and
                packet[SNAP].code == WATR_PROTOCOL_ID):
                
                # Extract raw data after SNAP
                if packet.haslayer(Raw):
                    raw_data = packet[Raw].load
                    
                    # Parse WATR packet manually
                    # Expected format: type (2 bytes) + length (4 bytes) + payload
                    if len(raw_data) >= 6:
                        # Unpack header
                        watr_type, watr_length = struct.unpack('>HI', raw_data[:6])
                        
                        # Check if it's a valid WATR packet
                        if watr_type == 0x5741:  # 'WA'
                            self.received_count += 1
                            
                            # Extract payload
                            payload_data = raw_data[6:]
                            if isinstance(payload_data, bytes):
                                payload_text = payload_data.decode('utf-8', errors='replace')
                            else:
                                payload_text = str(payload_data)
                            
                            self.watr_packets.append({
                                'sequence': self.received_count,
                                'type': watr_type,
                                'length': watr_length,
                                'payload': payload_text,
                                'src_mac': packet[Dot11].addr2,
                                'dst_mac': packet[Dot11].addr1
                            })
                            
                            print(f"📥 Received WATR packet #{self.received_count}: {payload_text}")
                            print(f"   From: {packet[Dot11].addr2} -> {packet[Dot11].addr1}")
                            print(f"   Type: 0x{watr_type:04x}, Length: {watr_length}")
                        else:
                            print(f"⚠️  Invalid WATR type: 0x{watr_type:04x}")
                            
        except Exception as e:
            # Ignore parsing errors for non-WATR packets
            pass
    
    def start_sniffing(self):
        """Start packet sniffing"""
        try:
            print(f"📥 Starting WATR packet reception (fixed)")
            print(f"   Interface: {self.interface}")
            print(f"   Protocol ID: 0x{WATR_PROTOCOL_ID:04x}")
            print(f"   Press Ctrl+C to stop")
            print()
            
            self.running = True
            
            # Build filter for data frames
            filter_str = "type data"
            
            # Start sniffing
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                filter=filter_str,
                stop_filter=lambda x: not self.running
            )
            
            print(f"\n✓ Reception complete! Received {self.received_count} WATR packets")
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
    
    def stop_sniffing(self):
        """Stop packet sniffing"""
        self.running = False
        
    def print_summary(self):
        """Print reception summary"""
        print(f"\n📊 RECEPTION SUMMARY")
        print(f"   Total WATR packets received: {self.received_count}")
        
        if self.watr_packets:
            print(f"   WATR packets:")
            for pkt in self.watr_packets:
                print(f"     #{pkt['sequence']}: {pkt['payload']} (from {pkt['src_mac']})")

def main():
    # Create receiver
    receiver = FixedReceiver("mon0")
    
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