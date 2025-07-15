#!/usr/bin/env python3
"""
Simple monitor mode test
"""
import subprocess
import sys
import time

def test_monitor_mode(interface):
    """Test monitor mode setup"""
    print(f"🧪 Testing monitor mode on {interface}")
    
    try:
        # Get initial state
        result = subprocess.run(f"iw dev {interface} info", shell=True, capture_output=True, text=True)
        print(f"Initial state:\n{result.stdout}")
        
        # Take down
        print("\n1. Taking interface down...")
        subprocess.run(f"sudo ip link set {interface} down", shell=True, check=True)
        
        # Set monitor mode
        print("2. Setting monitor mode...")
        subprocess.run(f"sudo iw dev {interface} set type monitor", shell=True, check=True)
        
        # Bring up
        print("3. Bringing interface up...")
        subprocess.run(f"sudo ip link set {interface} up", shell=True, check=True)
        
        # Wait a bit
        print("4. Waiting 2 seconds...")
        time.sleep(2)
        
        # Check state
        result = subprocess.run(f"iw dev {interface} info", shell=True, capture_output=True, text=True)
        print(f"\nFinal state:\n{result.stdout}")
        
        # Set channel
        print("\n5. Setting channel 6...")
        subprocess.run(f"sudo iw dev {interface} set channel 6", shell=True, check=True)
        
        # Check if interface is really up
        result = subprocess.run(f"ip link show {interface}", shell=True, capture_output=True, text=True)
        if "UP" in result.stdout:
            print("✅ Interface is UP")
        else:
            print("❌ Interface is not UP")
            print(result.stdout)
        
        # Try a simple tcpdump to test packet capture
        print("\n6. Testing packet capture with tcpdump...")
        result = subprocess.run(f"sudo timeout 3 tcpdump -i {interface} -c 5", shell=True, capture_output=True, text=True)
        print(f"tcpdump output:\n{result.stdout}")
        if result.stderr:
            print(f"tcpdump errors:\n{result.stderr}")
        
        # Restore managed mode
        print("\n7. Restoring managed mode...")
        subprocess.run(f"sudo ip link set {interface} down", shell=True, check=True)
        subprocess.run(f"sudo iw dev {interface} set type managed", shell=True, check=True)
        subprocess.run(f"sudo ip link set {interface} up", shell=True, check=True)
        
        print("\n✅ Monitor mode test complete!")
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Error: {e}")
        # Try to restore
        subprocess.run(f"sudo ip link set {interface} down", shell=True, check=False)
        subprocess.run(f"sudo iw dev {interface} set type managed", shell=True, check=False)
        subprocess.run(f"sudo ip link set {interface} up", shell=True, check=False)

if __name__ == "__main__":
    interface = sys.argv[1] if len(sys.argv) > 1 else "wlan1"
    test_monitor_mode(interface)