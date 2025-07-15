#!/usr/bin/env python3
"""
Direct Scapy sniffing test for WATR packets
"""
import sys
sys.path.insert(0, '/opt/watr/python')

from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt
import subprocess
import time
import signal

def check_interface_mode(interface):
    """Check current interface mode"""
    result = subprocess.run(f"iw dev {interface} info", shell=True, capture_output=True, text=True)
    if "type monitor" in result.stdout:
        return "monitor"
    elif "type managed" in result.stdout:
        return "managed"
    else:
        return "unknown"

def ensure_monitor_mode(interface, channel=6):
    """Ensure interface is in monitor mode"""
    current_mode = check_interface_mode(interface)
    print(f"Current mode: {current_mode}")
    
    if current_mode != "monitor":
        print("Setting monitor mode...")
        subprocess.run(f"sudo ip link set {interface} down", shell=True, check=True)
        subprocess.run(f"sudo iw dev {interface} set type monitor", shell=True, check=True)
        subprocess.run(f"sudo ip link set {interface} up", shell=True, check=True)
        time.sleep(2)
    
    # Try to set channel
    print(f"Setting channel {channel}...")
    result = subprocess.run(f"sudo iw dev {interface} set channel {channel}", shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Warning: Could not set channel: {result.stderr}")
    
    # Verify
    result = subprocess.run(f"iw dev {interface} info", shell=True, capture_output=True, text=True)
    print(f"Interface info:\n{result.stdout}")
    
    return check_interface_mode(interface) == "monitor"

def packet_handler(packet):
    """Simple packet handler that looks for WATR beacons"""
    global packet_count, watr_count
    packet_count += 1
    
    # Look for beacons with specific MAC
    if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 8:
        src_mac = packet[Dot11].addr2
        if src_mac == "02:00:00:00:00:01":
            print(f"\n🎯 WATR beacon from {src_mac}")
            
            # Look for WATR-TEST SSID
            if packet.haslayer(Dot11Elt):
                elt = packet[Dot11Elt]
                while elt:
                    if elt.ID == 0 and elt.info == b"WATR-TEST":
                        watr_count += 1
                        print(f"✅ WATR packet #{watr_count} found!")
                        
                        # Look for vendor element
                        elt2 = packet[Dot11Elt]
                        while elt2:
                            if elt2.ID == 221:
                                print(f"   Vendor data: {elt2.info.hex()}")
                            elt2 = elt2.payload if hasattr(elt2, 'payload') and isinstance(elt2.payload, Dot11Elt) else None
                        break
                    
                    elt = elt.payload if hasattr(elt, 'payload') and isinstance(elt.payload, Dot11Elt) else None
    
    # Show progress
    if packet_count % 100 == 0:
        print(f".", end="", flush=True)

# Global counters
packet_count = 0
watr_count = 0
running = True

def signal_handler(sig, frame):
    global running
    running = False
    print("\n\nStopping...")

def main():
    global running
    
    interface = sys.argv[1] if len(sys.argv) > 1 else "wlan1"
    print(f"🚀 WATR Sniffer Test on {interface}")
    
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Ensure monitor mode
    if not ensure_monitor_mode(interface):
        print("❌ Failed to set monitor mode")
        return 1
    
    print(f"\n📡 Sniffing on {interface}...")
    print("Looking for WATR beacons from 02:00:00:00:00:01")
    print("Press Ctrl+C to stop\n")
    
    try:
        # Sniff with timeout approach
        while running:
            try:
                sniff(iface=interface, prn=packet_handler, timeout=1, store=False)
            except Exception as e:
                if "Network is down" in str(e):
                    print(f"\n⚠️  Network down, retrying...")
                    time.sleep(1)
                else:
                    raise
    except KeyboardInterrupt:
        pass
    
    print(f"\n\n📊 Results:")
    print(f"   Total packets: {packet_count}")
    print(f"   WATR packets: {watr_count}")
    
    # Restore managed mode
    print("\nRestoring managed mode...")
    subprocess.run(f"sudo ip link set {interface} down", shell=True, check=False)
    subprocess.run(f"sudo iw dev {interface} set type managed", shell=True, check=False)
    subprocess.run(f"sudo ip link set {interface} up", shell=True, check=False)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())