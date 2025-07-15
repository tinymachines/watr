#!/bin/bash
# Working WATR packet test

echo "🚀 WATR Working Packet Test"
echo "==========================="
echo

# Deploy debug script
echo "📦 Deploying debug script..."
scp debug-both.py tm11.local:/tmp/
scp debug-both.py tm10.local:/tmp/
echo "✓ Deployed"

echo
echo "📡 To test packet transmission:"
echo
echo "1. Open Terminal 1 and run:"
echo "   ssh tm11.local"
echo "   sudo /opt/watr/venv/bin/python /tmp/debug-both.py receive"
echo
echo "2. Open Terminal 2 and run:"
echo "   ssh tm10.local"  
echo "   sudo /opt/watr/venv/bin/python /tmp/debug-both.py send"
echo
echo "The sender will transmit 10 beacons with WATR-TEST SSID."
echo "The receiver should detect them if everything is working."
echo

echo "Running automated test..."
echo "========================="

# Run receiver in background with output to file
ssh tm11.local "sudo /opt/watr/venv/bin/python /tmp/debug-both.py receive 2>&1" > receiver.out &
RECV_PID=$!

# Wait for receiver
sleep 5

# Run sender
echo "Starting sender..."
ssh tm10.local "sudo /opt/watr/venv/bin/python /tmp/debug-both.py send 2>&1" | tee sender.out

# Wait a bit more
sleep 5

# Kill receiver if still running
kill $RECV_PID 2>/dev/null || true

echo
echo "📊 Results:"
echo "=========="
echo
echo "Sender output:"
grep "Sent packet" sender.out | tail -5

echo
echo "Receiver output:"
grep -E "(Received|Total received)" receiver.out || echo "No packets received"

# Check for any errors
if grep -q "error" receiver.out; then
    echo
    echo "⚠️  Receiver errors:"
    grep -i "error" receiver.out
fi

rm -f sender.out receiver.out