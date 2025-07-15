#!/bin/bash
# Run WATR packet test between tm11 (receiver) and tm10 (sender)

echo "🚀 WATR Packet Transmission Test"
echo "================================"
echo
echo "This test will:"
echo "1. Start receiver on tm11.local (interface: wlan1)"
echo "2. Start sender on tm10.local (interface: wlx842096fbfd0b)"
echo "3. Send 5 WATR packets embedded in WiFi beacons"
echo
echo "Make sure both devices are ready!"
echo

# Check connectivity
echo "🔍 Checking connectivity..."
if ! ping -c 1 tm11.local > /dev/null 2>&1; then
    echo "❌ Cannot reach tm11.local"
    exit 1
fi
if ! ping -c 1 tm10.local > /dev/null 2>&1; then
    echo "❌ Cannot reach tm10.local"
    exit 1
fi
echo "✓ Both devices reachable"
echo

# Deploy updated packet_test.py to both machines
echo "📦 Deploying updated code..."
scp python/watr/packet_test.py tm11.local:/opt/watr/python/watr/
scp python/watr/packet_test.py tm10.local:/opt/watr/python/watr/
echo "✓ Code deployed"
echo

echo "Starting test in 3 seconds..."
echo "Press Ctrl+C to stop"
sleep 3

# Create a simple Python script to run on tm10 for sending
cat > /tmp/send-watr.py << 'EOF'
#!/usr/bin/env python3
import sys
sys.path.insert(0, '/opt/watr/python')

from watr.packet_test import PacketSender, TestConfig

# For tm10, use the specific interface name
config = TestConfig(
    interface="wlx842096fbfd0b",
    channel=6,
    count=5,
    interval=2.0,
    payload="Hello from tm10.local!"
)

print("🚀 WATR Sender on tm10.local")
sender = PacketSender(config)
sender.send_packets()
EOF

# Run receiver in background
echo
echo "📥 Starting receiver on tm11.local..."
ssh tm11.local "cd /opt/watr && timeout 30s sudo /opt/watr/venv/bin/python test-receive.py 2>&1" &
RECEIVER_PID=$!

# Wait for receiver to initialize
echo "⏳ Waiting 5 seconds for receiver to initialize..."
sleep 5

# Run sender
echo
echo "📤 Starting sender on tm10.local..."
scp /tmp/send-watr.py tm10.local:/tmp/
ssh tm10.local "sudo /opt/watr/venv/bin/python /tmp/send-watr.py"

# Wait for receiver to complete
echo
echo "⏳ Waiting for receiver to complete..."
wait $RECEIVER_PID

echo
echo "✅ Test complete!"
echo "Check the output above to see if packets were received."

# Cleanup
rm -f /tmp/send-watr.py
ssh tm10.local "rm -f /tmp/send-watr.py" 2>/dev/null || true