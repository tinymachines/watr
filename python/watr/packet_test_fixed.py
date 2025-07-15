#!/usr/bin/env python3
"""
WATR Packet Test - Fixed Implementation using Data Frames

This module provides the working implementation for WATR protocol packets
using 802.11 data frames with LLC/SNAP encapsulation.
"""

import json
import subprocess
import time
import sys
import signal
from typing import Optional, Dict, List
from dataclasses import dataclass
from pathlib import Path

try:
    from scapy.all import *
    from scapy.layers.dot11 import RadioTap, Dot11, LLC, SNAP
    from scapy.layers.l2 import Raw
    # Try relative import first, then absolute
    try:
        from .scapy_layers import WATRHeader, WATRPayload
    except ImportError:
        from watr.scapy_layers import WATRHeader, WATRPayload
    SCAPY_AVAILABLE = True
except ImportError:
    print("⚠️  Scapy not available. Install scapy for packet testing.")
    SCAPY_AVAILABLE = False

# Custom protocol ID to distinguish WATR traffic
WATR_PROTOCOL_ID = 0x8999

@dataclass
class TestConfig:
    """Configuration for packet testing"""
    interface: str = "mon0"  # Use dedicated monitor interface
    channel: int = 1  # Channel 1 (2412 MHz)
    count: int = 10
    interval: float = 1.0
    payload: str = "Hello WATR!"
    src_mac: str = "00:11:22:33:44:55"
    dst_mac: str = "66:77:88:99:AA:BB"
    
class PacketSender:
    """Sends custom WATR packets using data frames"""
    
    def __init__(self, config: TestConfig):
        self.config = config
        self.running = False
        self.sent_count = 0
        
    def create_watr_data_frame(self, sequence: int) -> bytes:
        """Create a custom WATR packet embedded in 802.11 data frame"""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not available for packet creation")
        
        # Create WATR protocol packet
        watr_packet = WATRHeader(
            type=0x5741,  # 'WA' in hex
            length=len(self.config.payload)
        ) / WATRPayload(
            data=f"{self.config.payload} #{sequence}"
        )
        
        # Create 802.11 data frame
        dot11 = Dot11(
            type=2,  # Type 2 is Data
            subtype=0,  # Subtype 0 is Data
            addr1=self.config.dst_mac,  # Destination
            addr2=self.config.src_mac,  # Source
            addr3=self.config.src_mac,  # BSSID
            FCfield='from-DS'  # Set appropriate flags
        )
        
        # Create LLC layer with custom protocol
        llc = LLC(
            dsap=0xAA,  # SNAP
            ssap=0xAA,  # SNAP
            ctrl=0x03   # Unnumbered Information
        )
        
        # Create SNAP header with custom protocol ID
        snap = SNAP(
            OUI=0x000000,  # Organizationally unique identifier
            code=WATR_PROTOCOL_ID  # Custom protocol ID for WATR
        )
        
        # Combine all layers
        watr_data = bytes(watr_packet)
        packet = RadioTap() / dot11 / llc / snap / Raw(load=watr_data)
        
        return packet
    
    def send_packets(self):
        """Send test packets"""
        try:
            print(f"📤 Starting packet transmission...")
            print(f"   Interface: {self.config.interface}")
            print(f"   Channel: {self.config.channel}")
            print(f"   Count: {self.config.count}")
            print(f"   Interval: {self.config.interval}s")
            print(f"   Payload: {self.config.payload}")
            print(f"   Source MAC: {self.config.src_mac}")
            print(f"   Dest MAC: {self.config.dst_mac}")
            print()
            
            self.running = True
            
            for i in range(self.config.count):
                if not self.running:
                    break
                
                try:
                    # Create packet
                    packet = self.create_watr_data_frame(i + 1)
                    
                    # Send packet
                    sendp(packet, iface=self.config.interface, verbose=False)
                    
                    self.sent_count += 1
                    print(f"📡 Sent packet #{i + 1}: {self.config.payload} #{i + 1}")
                    
                    # Wait before next packet
                    if i < self.config.count - 1:
                        time.sleep(self.config.interval)
                        
                except Exception as e:
                    print(f"❌ Error sending packet #{i + 1}: {e}")
            
            print(f"\n✓ Transmission complete! Sent {self.sent_count} packets")
            return True
            
        except KeyboardInterrupt:
            print(f"\n⚠️  Transmission interrupted by user")
            return False
        except Exception as e:
            print(f"❌ Error during transmission: {e}")
            return False
        finally:
            self.running = False

class PacketReceiver:
    """Receives and processes WATR packets using data frames"""
    
    def __init__(self, config: TestConfig):
        self.config = config
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
                    
                    # Try to parse WATR packet
                    try:
                        watr_packet = WATRHeader(raw_data)
                        self.received_count += 1
                        
                        # Extract payload
                        payload_data = "unknown"
                        if watr_packet.haslayer(WATRPayload):
                            payload_data = watr_packet[WATRPayload].data
                            if isinstance(payload_data, bytes):
                                payload_data = payload_data.decode('utf-8', errors='replace')
                        
                        self.watr_packets.append({
                            'sequence': self.received_count,
                            'timestamp': time.time(),
                            'type': watr_packet.type,
                            'length': watr_packet.length,
                            'payload': payload_data,
                            'src_mac': packet[Dot11].addr2,
                            'dst_mac': packet[Dot11].addr1
                        })
                        
                        print(f"📥 Received WATR packet #{self.received_count}: {payload_data}")
                        print(f"   From: {packet[Dot11].addr2} -> {packet[Dot11].addr1}")
                        
                    except Exception as e:
                        print(f"⚠️  Error parsing WATR packet: {e}")
                        print(f"    Raw data ({len(raw_data)} bytes): {raw_data.hex()}")
                        
        except Exception as e:
            # Ignore parsing errors for non-WATR packets
            pass
    
    def start_sniffing(self):
        """Start packet sniffing"""
        try:
            print(f"📥 Starting packet reception...")
            print(f"   Interface: {self.config.interface}")
            print(f"   Channel: {self.config.channel}")
            print(f"   Listening for WATR data frames...")
            print(f"   Press Ctrl+C to stop")
            print()
            
            self.running = True
            
            # Build filter for data frames
            filter_str = "type data"
            
            # Start sniffing
            sniff(
                iface=self.config.interface,
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
        print(f"   Total packets received: {self.received_count}")
        
        if self.watr_packets:
            print(f"   WATR packets:")
            for pkt in self.watr_packets:
                print(f"     #{pkt['sequence']}: {pkt['payload']} (from {pkt['src_mac']})")

def check_monitor_interface(interface: str = "mon0") -> bool:
    """Check if monitor interface exists"""
    try:
        result = subprocess.run(
            f"ip link show {interface}",
            shell=True,
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except:
        return False

def setup_monitor_interface(phy: str = "phy0", interface: str = "mon0") -> bool:
    """Setup monitor interface using iw commands"""
    try:
        # Delete existing interface if it exists
        subprocess.run(f"sudo iw dev {interface} del", shell=True, capture_output=True)
        time.sleep(0.5)
        
        # Create monitor interface
        result = subprocess.run(
            f"sudo iw phy {phy} interface add {interface} type monitor",
            shell=True,
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"❌ Failed to create monitor interface: {result.stderr}")
            return False
        
        # Set frequency (channel 1 = 2412 MHz)
        subprocess.run(f"sudo iw dev {interface} set freq 2412", shell=True)
        
        # Bring interface up
        subprocess.run(f"sudo ip link set {interface} up", shell=True)
        
        time.sleep(1)
        print(f"✓ Monitor interface {interface} created on {phy}")
        return True
        
    except Exception as e:
        print(f"❌ Error setting up monitor interface: {e}")
        return False

def main():
    """Main function for packet testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description='WATR Packet Test - Send/Receive Custom Protocol Packets')
    parser.add_argument('mode', choices=['send', 'receive'], help='Operation mode')
    parser.add_argument('--interface', '-i', default='mon0', help='Monitor interface (default: mon0)')
    parser.add_argument('--phy', '-p', default='phy0', help='PHY device for monitor setup (default: phy0)')
    parser.add_argument('--channel', '-c', type=int, default=1, help='WiFi channel (default: 1)')
    parser.add_argument('--count', '-n', type=int, default=10, help='Number of packets to send (default: 10)')
    parser.add_argument('--interval', '-t', type=float, default=1.0, help='Interval between packets (default: 1.0s)')
    parser.add_argument('--payload', default='Hello WATR!', help='Payload message')
    parser.add_argument('--src-mac', default='00:11:22:33:44:55', help='Source MAC address')
    parser.add_argument('--dst-mac', default='66:77:88:99:AA:BB', help='Destination MAC address')
    parser.add_argument('--setup-monitor', action='store_true', help='Setup monitor interface before testing')
    
    args = parser.parse_args()
    
    if not SCAPY_AVAILABLE:
        print("❌ Scapy is required for packet testing. Install with: pip install scapy")
        return 1
    
    # Check if we need to setup monitor interface
    if args.setup_monitor or not check_monitor_interface(args.interface):
        print(f"🔧 Setting up monitor interface {args.interface}...")
        if not setup_monitor_interface(args.phy, args.interface):
            print("❌ Failed to setup monitor interface")
            return 1
    
    # Create configuration
    config = TestConfig(
        interface=args.interface,
        channel=args.channel,
        count=args.count,
        interval=args.interval,
        payload=args.payload,
        src_mac=args.src_mac,
        dst_mac=args.dst_mac
    )
    
    # Run test
    if args.mode == 'send':
        sender = PacketSender(config)
        success = sender.send_packets()
        return 0 if success else 1
    else:  # receive
        receiver = PacketReceiver(config)
        
        # Set up signal handler for clean shutdown
        def signal_handler(signum, frame):
            print("\n🛑 Stopping reception...")
            receiver.stop_sniffing()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        success = receiver.start_sniffing()
        receiver.print_summary()
        return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())