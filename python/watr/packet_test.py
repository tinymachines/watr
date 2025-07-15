#!/usr/bin/env python3
"""
WATR Packet Test - Send and Receive Custom Protocol Packets

This module provides functionality to test custom WATR protocol packets
by sending them over WiFi in monitor mode and receiving them on another device.
"""

import json
import subprocess
import time
import sys
import signal
import threading
from typing import Optional, Dict, List
from dataclasses import dataclass
from pathlib import Path

try:
    from scapy.all import *
    from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt
    # Try relative import first, then absolute
    try:
        from .scapy_layers import WATRHeader, WATRPayload
    except ImportError:
        from watr.scapy_layers import WATRHeader, WATRPayload
    SCAPY_AVAILABLE = True
except ImportError:
    print("⚠️  Scapy not available. Install scapy for packet testing.")
    SCAPY_AVAILABLE = False

@dataclass
class TestConfig:
    """Configuration for packet testing"""
    interface: str
    channel: int = 6
    count: int = 10
    interval: float = 1.0
    payload: str = "Hello WATR!"
    
class PacketSender:
    """Sends custom WATR packets in monitor mode"""
    
    def __init__(self, config: TestConfig):
        self.config = config
        self.running = False
        self.sent_count = 0
        
    def setup_monitor_mode(self) -> bool:
        """Set up monitor mode on the interface"""
        try:
            print(f"📡 Setting up monitor mode on {self.config.interface}...")
            
            # Take interface down
            subprocess.run(f"sudo ip link set {self.config.interface} down", shell=True, check=True)
            
            # Set monitor mode
            subprocess.run(f"sudo iw dev {self.config.interface} set type monitor", shell=True, check=True)
            
            # Bring interface up
            subprocess.run(f"sudo ip link set {self.config.interface} up", shell=True, check=True)
            
            # Wait for interface to be ready
            print("⏳ Waiting for interface to initialize...")
            time.sleep(2)
            
            # Verify interface is up
            result = subprocess.run(f"ip link show {self.config.interface}", shell=True, capture_output=True, text=True)
            if "UP" not in result.stdout:
                print(f"⚠️  Interface {self.config.interface} is not up after monitor mode setup")
                # Try to bring it up again
                subprocess.run(f"sudo ip link set {self.config.interface} up", shell=True, check=True)
                time.sleep(1)
            
            # Set channel
            subprocess.run(f"sudo iw dev {self.config.interface} set channel {self.config.channel}", shell=True, check=True)
            
            # Final verification
            result = subprocess.run(f"iw dev {self.config.interface} info", shell=True, capture_output=True, text=True)
            if "type monitor" in result.stdout:
                print(f"✓ Monitor mode active on {self.config.interface}, channel {self.config.channel}")
                return True
            else:
                print(f"❌ Monitor mode verification failed")
                return False
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to set up monitor mode: {e}")
            return False
    
    def restore_managed_mode(self) -> bool:
        """Restore managed mode on the interface"""
        try:
            print(f"🔄 Restoring managed mode on {self.config.interface}...")
            
            # Take interface down
            subprocess.run(f"sudo ip link set {self.config.interface} down", shell=True, check=True)
            
            # Set managed mode
            subprocess.run(f"sudo iw dev {self.config.interface} set type managed", shell=True, check=True)
            
            # Bring interface up
            subprocess.run(f"sudo ip link set {self.config.interface} up", shell=True, check=True)
            
            print(f"✓ Managed mode restored on {self.config.interface}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to restore managed mode: {e}")
            return False
    
    def create_watr_packet(self, sequence: int) -> bytes:
        """Create a custom WATR packet embedded in a WiFi frame"""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not available for packet creation")
        
        # Create WATR protocol packet
        watr_packet = WATRHeader(
            type=0x5741,  # 'WA' in hex
            length=len(self.config.payload)
        ) / WATRPayload(
            data=f"{self.config.payload} #{sequence}"
        )
        
        # Create a custom beacon frame to carry our WATR data
        # This is a hack to get our data transmitted - normally you'd use data frames
        dot11 = Dot11(
            type=0,  # Management frame
            subtype=8,  # Beacon
            addr1="ff:ff:ff:ff:ff:ff",  # Broadcast
            addr2="02:00:00:00:00:01",  # Fake source MAC
            addr3="02:00:00:00:00:01"   # BSSID
        )
        
        # Create beacon with our WATR data as a vendor-specific element
        beacon = Dot11Beacon(timestamp=int(time.time() * 1000000))
        
        # Add SSID element
        ssid_element = Dot11Elt(ID=0, len=len("WATR-TEST"), info=b"WATR-TEST")
        
        # Add our WATR data as a vendor-specific element
        watr_data = bytes(watr_packet)
        vendor_element = Dot11Elt(ID=221, len=len(watr_data), info=watr_data)
        
        # Combine all elements
        packet = RadioTap() / dot11 / beacon / ssid_element / vendor_element
        
        return packet
    
    def send_packets(self):
        """Send test packets"""
        if not self.setup_monitor_mode():
            return False
        
        try:
            print(f"📤 Starting packet transmission...")
            print(f"   Interface: {self.config.interface}")
            print(f"   Channel: {self.config.channel}")
            print(f"   Count: {self.config.count}")
            print(f"   Interval: {self.config.interval}s")
            print(f"   Payload: {self.config.payload}")
            print()
            
            self.running = True
            
            for i in range(self.config.count):
                if not self.running:
                    break
                
                try:
                    # Create packet
                    packet = self.create_watr_packet(i + 1)
                    
                    # Send packet (requires root privileges)
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
            self.restore_managed_mode()

class PacketReceiver:
    """Receives and processes WATR packets in monitor mode"""
    
    def __init__(self, config: TestConfig):
        self.config = config
        self.running = False
        self.received_count = 0
        self.watr_packets = []
        
    def setup_monitor_mode(self) -> bool:
        """Set up monitor mode on the interface"""
        try:
            print(f"📡 Setting up monitor mode on {self.config.interface}...")
            
            # Take interface down
            subprocess.run(f"sudo ip link set {self.config.interface} down", shell=True, check=True)
            
            # Set monitor mode
            subprocess.run(f"sudo iw dev {self.config.interface} set type monitor", shell=True, check=True)
            
            # Bring interface up
            subprocess.run(f"sudo ip link set {self.config.interface} up", shell=True, check=True)
            
            # Wait for interface to be ready
            print("⏳ Waiting for interface to initialize...")
            time.sleep(2)
            
            # Verify interface is up
            result = subprocess.run(f"ip link show {self.config.interface}", shell=True, capture_output=True, text=True)
            if "UP" not in result.stdout:
                print(f"⚠️  Interface {self.config.interface} is not up after monitor mode setup")
                # Try to bring it up again
                subprocess.run(f"sudo ip link set {self.config.interface} up", shell=True, check=True)
                time.sleep(1)
            
            # Set channel
            subprocess.run(f"sudo iw dev {self.config.interface} set channel {self.config.channel}", shell=True, check=True)
            
            # Final verification
            result = subprocess.run(f"iw dev {self.config.interface} info", shell=True, capture_output=True, text=True)
            if "type monitor" in result.stdout:
                print(f"✓ Monitor mode active on {self.config.interface}, channel {self.config.channel}")
                return True
            else:
                print(f"❌ Monitor mode verification failed")
                return False
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to set up monitor mode: {e}")
            return False
    
    def restore_managed_mode(self) -> bool:
        """Restore managed mode on the interface"""
        try:
            print(f"🔄 Restoring managed mode on {self.config.interface}...")
            
            # Take interface down
            subprocess.run(f"sudo ip link set {self.config.interface} down", shell=True, check=True)
            
            # Set managed mode
            subprocess.run(f"sudo iw dev {self.config.interface} set type managed", shell=True, check=True)
            
            # Bring interface up
            subprocess.run(f"sudo ip link set {self.config.interface} up", shell=True, check=True)
            
            print(f"✓ Managed mode restored on {self.config.interface}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to restore managed mode: {e}")
            return False
    
    def packet_handler(self, packet):
        """Handle received packets"""
        try:
            # Check if this is a beacon frame with our SSID
            if packet.haslayer(Dot11Beacon) and packet.haslayer(Dot11Elt):
                # Look for SSID element with "WATR-TEST"
                ssid_found = False
                watr_data = None
                
                # Parse 802.11 elements - fixed iteration
                elt = packet[Dot11Elt]
                while elt:
                    if elt.ID == 0 and elt.info == b"WATR-TEST":
                        ssid_found = True
                    elif elt.ID == 221:  # Vendor-specific element
                        watr_data = elt.info
                    
                    # Move to next element properly
                    elt = elt.payload if hasattr(elt, 'payload') and isinstance(elt.payload, Dot11Elt) else None
                
                if ssid_found and watr_data:
                    # Try to parse WATR packet
                    try:
                        watr_packet = WATRHeader(watr_data)
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
                            'payload': payload_data
                        })
                        
                        print(f"📥 Received WATR packet #{self.received_count}: {payload_data}")
                        
                    except Exception as e:
                        print(f"⚠️  Error parsing WATR packet: {e}")
                        print(f"    Raw data ({len(watr_data)} bytes): {watr_data.hex()}")
                        
        except Exception as e:
            # Ignore parsing errors for non-WATR packets
            pass
    
    def start_sniffing(self):
        """Start packet sniffing"""
        if not self.setup_monitor_mode():
            return False
        
        try:
            print(f"📥 Starting packet reception...")
            print(f"   Interface: {self.config.interface}")
            print(f"   Channel: {self.config.channel}")
            print(f"   Listening for WATR packets...")
            print(f"   Press Ctrl+C to stop")
            print()
            
            self.running = True
            
            # Start sniffing with error handling
            try:
                sniff(
                    iface=self.config.interface,
                    prn=self.packet_handler,
                    stop_filter=lambda x: not self.running,
                    store=False  # Don't store packets in memory to prevent memory issues
                )
            except OSError as e:
                if e.errno == 100:  # Network is down
                    print(f"❌ Network interface error: {e}")
                    print(f"   The interface may not be ready. Trying alternative method...")
                    
                    # Try continuous sniffing with timeout loop
                    print("   Using timeout-based sniffing loop...")
                    while self.running:
                        try:
                            # Sniff in 1-second intervals
                            sniff(
                                iface=self.config.interface,
                                prn=self.packet_handler,
                                timeout=1,
                                store=False
                            )
                        except OSError as e2:
                            if e2.errno == 100:
                                print(f"   Still having network issues, waiting...")
                                time.sleep(1)
                            else:
                                raise
                        except KeyboardInterrupt:
                            break
                else:
                    raise
            
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
            self.restore_managed_mode()
    
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
                print(f"     #{pkt['sequence']}: {pkt['payload']}")

def load_adapter_config() -> Optional[Dict]:
    """Load adapter configuration from bootstrap"""
    try:
        with open('/tmp/watr_adapters.json', 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None

def get_monitor_interface() -> Optional[str]:
    """Get the monitor-capable interface from bootstrap config"""
    config = load_adapter_config()
    if not config:
        return None
    
    for adapter in config.get('wifi_adapters', []):
        if adapter.get('supports_monitor', False):
            return adapter['interface']
    
    return None

def main():
    """Main function for packet testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description='WATR Packet Test - Send/Receive Custom Protocol Packets')
    parser.add_argument('mode', choices=['send', 'receive'], help='Operation mode')
    parser.add_argument('--interface', '-i', help='WiFi interface (auto-detected if not specified)')
    parser.add_argument('--channel', '-c', type=int, default=6, help='WiFi channel (default: 6)')
    parser.add_argument('--count', '-n', type=int, default=10, help='Number of packets to send (default: 10)')
    parser.add_argument('--interval', '-t', type=float, default=1.0, help='Interval between packets (default: 1.0s)')
    parser.add_argument('--payload', '-p', default='Hello WATR!', help='Payload message (default: "Hello WATR!")')
    
    args = parser.parse_args()
    
    if not SCAPY_AVAILABLE:
        print("❌ Scapy is required for packet testing. Install with: pip install scapy")
        return 1
    
    # Get interface
    interface = args.interface
    if not interface:
        interface = get_monitor_interface()
        if not interface:
            print("❌ No monitor-capable interface found. Run bootstrap first: python bootstrap.py")
            return 1
        print(f"🔍 Auto-detected monitor interface: {interface}")
    
    # Create configuration
    config = TestConfig(
        interface=interface,
        channel=args.channel,
        count=args.count,
        interval=args.interval,
        payload=args.payload
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