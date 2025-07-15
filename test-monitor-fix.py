#!/usr/bin/env python3
"""
Test script to verify monitor mode fix for "Network is down" error
"""

import subprocess
import time
import sys

def test_monitor_mode(interface="wlan1"):
    """Test monitor mode setup with proper delays"""
    
    print(f"Testing monitor mode setup on {interface}")
    
    try:
        # Take interface down
        print("1. Taking interface down...")
        subprocess.run(f"sudo ip link set {interface} down", shell=True, check=True)
        
        # Set monitor mode
        print("2. Setting monitor mode...")
        subprocess.run(f"sudo iw dev {interface} set type monitor", shell=True, check=True)
        
        # Bring interface up
        print("3. Bringing interface up...")
        subprocess.run(f"sudo ip link set {interface} up", shell=True, check=True)
        
        # Wait for interface
        print("4. Waiting for interface to initialize...")
        time.sleep(2)
        
        # Check status
        print("5. Checking interface status...")
        result = subprocess.run(f"ip link show {interface}", shell=True, capture_output=True, text=True)
        print(f"   Status: {'UP' if 'UP' in result.stdout else 'DOWN'}")
        
        # Verify monitor mode
        result = subprocess.run(f"iw dev {interface} info", shell=True, capture_output=True, text=True)
        if "type monitor" in result.stdout:
            print("✓ Monitor mode confirmed")
        else:
            print("❌ Monitor mode not confirmed")
            
        # Try to use with scapy
        print("\n6. Testing with Scapy...")
        try:
            from scapy.all import sniff
            
            def packet_handler(pkt):
                print(f"   Received packet: {pkt.summary()}")
            
            # Sniff for 3 seconds
            print("   Sniffing for 3 seconds...")
            sniff(iface=interface, prn=packet_handler, timeout=3, store=False)
            print("✓ Scapy sniffing successful!")
            
        except Exception as e:
            print(f"❌ Scapy error: {e}")
            
        # Restore managed mode
        print("\n7. Restoring managed mode...")
        subprocess.run(f"sudo ip link set {interface} down", shell=True, check=True)
        subprocess.run(f"sudo iw dev {interface} set type managed", shell=True, check=True)
        subprocess.run(f"sudo ip link set {interface} up", shell=True, check=True)
        print("✓ Managed mode restored")
        
    except Exception as e:
        print(f"Error: {e}")
        return False
        
    return True

if __name__ == "__main__":
    interface = sys.argv[1] if len(sys.argv) > 1 else "wlan1"
    test_monitor_mode(interface)