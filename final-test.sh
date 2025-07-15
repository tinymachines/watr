#!/bin/bash
# Final WATR packet test

echo "🚀 WATR Packet Test (tm11 receives, tm10 sends)"
echo "=============================================="
echo

# Deploy test scripts
echo "📦 Deploying test scripts..."
scp watr-sniff-test.py tm11.local:/tmp/
scp debug-send.py tm10.local:/tmp/
echo "✓ Scripts deployed"
echo

echo "Instructions:"
echo "1. Open two terminals"
echo "2. In Terminal 1 (Receiver on tm11):"
echo "   ssh tm11.local"
echo "   sudo /opt/watr/venv/bin/python /tmp/watr-sniff-test.py wlan1"
echo
echo "3. In Terminal 2 (Sender on tm10):"
echo "   ssh tm10.local" 
echo "   sudo /opt/watr/venv/bin/python /tmp/debug-send.py"
echo
echo "The sender will transmit 5 WATR packets as WiFi beacons."
echo "The receiver should detect and display them."
echo

# Alternative: run in background
read -p "Press Enter to run automated test (or Ctrl+C to run manually)..."

echo
echo "📡 Starting automated test..."
echo

# Start receiver in background
echo "Starting receiver on tm11.local..."
ssh tm11.local "sudo /opt/watr/venv/bin/python /tmp/watr-sniff-test.py wlan1 2>&1" > receiver.log &
RECEIVER_PID=$!

# Wait for receiver to initialize
echo "Waiting 5 seconds for receiver to initialize..."
sleep 5

# Check if receiver is running
if ! ps -p $RECEIVER_PID > /dev/null; then
    echo "❌ Receiver failed to start. Check receiver.log"
    cat receiver.log
    exit 1
fi

# Start sender
echo "Starting sender on tm10.local..."
ssh tm10.local "sudo /opt/watr/venv/bin/python /tmp/debug-send.py" | tee sender.log

# Give receiver a few more seconds
sleep 3

# Stop receiver
echo "Stopping receiver..."
kill -TERM $RECEIVER_PID 2>/dev/null || true
wait $RECEIVER_PID 2>/dev/null || true

echo
echo "📊 Results:"
echo "=========="
echo
echo "Receiver output:"
cat receiver.log
echo
echo "Sender output:"
grep -E "(Sent|packet)" sender.log || echo "See sender.log for details"

# Cleanup
rm -f receiver.log sender.log