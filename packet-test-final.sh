#!/bin/bash
# Final coordinated packet test

echo "🚀 WATR Packet Transmission Test"
echo "================================"
echo

# First, ensure both interfaces are in managed mode
echo "🔧 Resetting interfaces..."
ssh tm11.local "sudo ip link set wlan1 down; sudo iw dev wlan1 set type managed; sudo ip link set wlan1 up" 2>/dev/null
ssh tm10.local "sudo ip link set wlx842096fbfd0b down; sudo iw dev wlx842096fbfd0b set type managed; sudo ip link set wlx842096fbfd0b up" 2>/dev/null
echo "✓ Interfaces reset"

# Create simple sender script
cat > /tmp/simple-send.py << 'EOF'
#!/usr/bin/env python3
import subprocess
import time

# Set monitor mode
print("Setting monitor mode...")
subprocess.run("sudo ip link set wlx842096fbfd0b down", shell=True)
subprocess.run("sudo iw dev wlx842096fbfd0b set type monitor", shell=True)
subprocess.run("sudo ip link set wlx842096fbfd0b up", shell=True)
time.sleep(2)
subprocess.run("sudo iw dev wlx842096fbfd0b set channel 6", shell=True)

print("Importing scapy...")
from scapy.all import *

# Send 5 beacons
for i in range(5):
    print(f"Sending beacon {i+1}...")
    pkt = RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="02:00:00:00:00:01", addr3="02:00:00:00:00:01") / Dot11Beacon() / Dot11Elt(ID=0, info=b"WATR-TEST")
    sendp(pkt, iface="wlx842096fbfd0b", verbose=False)
    time.sleep(1)

print("Done sending")

# Restore
subprocess.run("sudo ip link set wlx842096fbfd0b down", shell=True)
subprocess.run("sudo iw dev wlx842096fbfd0b set type managed", shell=True)
subprocess.run("sudo ip link set wlx842096fbfd0b up", shell=True)
EOF

# Create simple receiver script
cat > /tmp/simple-recv.py << 'EOF'
#!/usr/bin/env python3
import subprocess
import time
import sys

# Set monitor mode
print("Setting monitor mode on wlan1...")
subprocess.run("sudo ip link set wlan1 down", shell=True)
subprocess.run("sudo iw dev wlan1 set type monitor", shell=True)
subprocess.run("sudo ip link set wlan1 up", shell=True)
time.sleep(2)
subprocess.run("sudo iw dev wlan1 set channel 6", shell=True)

print("Importing scapy...")
from scapy.all import *

count = 0
def handler(pkt):
    global count
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
        if pkt[Dot11].addr2 == "02:00:00:00:00:01":
            count += 1
            print(f"✅ WATR beacon #{count} received!")
            if pkt.haslayer(Dot11Elt):
                elt = pkt[Dot11Elt]
                if elt.ID == 0 and elt.info == b"WATR-TEST":
                    print("   SSID: WATR-TEST")

print("Starting sniffer...")
try:
    # Sniff for 20 seconds
    sniff(iface="wlan1", prn=handler, timeout=20)
except Exception as e:
    print(f"Sniff error: {e}")

print(f"\nTotal WATR beacons received: {count}")

# Restore
subprocess.run("sudo ip link set wlan1 down", shell=True)
subprocess.run("sudo iw dev wlan1 set type managed", shell=True)
subprocess.run("sudo ip link set wlan1 up", shell=True)
EOF

# Deploy scripts
echo "📦 Deploying scripts..."
scp /tmp/simple-recv.py tm11.local:/tmp/
scp /tmp/simple-send.py tm10.local:/tmp/
echo "✓ Scripts deployed"

# Start receiver
echo
echo "📡 Starting receiver on tm11.local..."
ssh tm11.local "sudo /opt/watr/venv/bin/python /tmp/simple-recv.py" &
RECV_PID=$!

# Wait for receiver to initialize
echo "⏳ Waiting 5 seconds for receiver..."
sleep 5

# Start sender
echo
echo "📤 Starting sender on tm10.local..."
ssh tm10.local "sudo /opt/watr/venv/bin/python /tmp/simple-send.py"

# Wait for receiver to finish
echo
echo "⏳ Waiting for receiver to complete..."
wait $RECV_PID

echo
echo "✅ Test complete!"

# Cleanup
rm -f /tmp/simple-send.py /tmp/simple-recv.py