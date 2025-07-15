#!/usr/bin/env python3
"""
Verify monitor mode works by looking for ANY packets
"""
import subprocess
import time
import sys

def test_interface(iface, duration=10):
    """Test if interface can capture packets"""
    print(f"\n🧪 Testing {iface}")
    
    # Set monitor mode
    print("Setting monitor mode...")
    subprocess.run(f"sudo ip link set {iface} down", shell=True)
    subprocess.run(f"sudo iw dev {iface} set type monitor", shell=True)
    subprocess.run(f"sudo ip link set {iface} up", shell=True)
    time.sleep(2)
    subprocess.run(f"sudo iw dev {iface} set channel 6", shell=True)
    
    # Check status
    result = subprocess.run(f"iw dev {iface} info", shell=True, capture_output=True, text=True)
    print(result.stdout)
    
    # Try tcpdump
    print(f"\nCapturing packets for {duration} seconds...")
    result = subprocess.run(
        f"sudo timeout {duration} tcpdump -i {iface} -c 20 'type mgt subtype beacon'",
        shell=True, capture_output=True, text=True
    )
    
    lines = result.stdout.strip().split('\n')
    beacon_count = len([l for l in lines if 'Beacon' in l])
    
    print(f"✅ Captured {beacon_count} beacon frames")
    
    if beacon_count > 0:
        print("\nSample beacons:")
        for line in lines[:5]:
            if 'Beacon' in line:
                print(f"  {line}")
    
    # Restore
    subprocess.run(f"sudo ip link set {iface} down", shell=True)
    subprocess.run(f"sudo iw dev {iface} set type managed", shell=True)
    subprocess.run(f"sudo ip link set {iface} up", shell=True)
    
    return beacon_count > 0

def main():
    if len(sys.argv) > 1:
        iface = sys.argv[1]
        test_interface(iface)
    else:
        print("Usage: verify-monitor.py <interface>")

if __name__ == "__main__":
    main()