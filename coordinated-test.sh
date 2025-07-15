#!/bin/bash
# Coordinated multi-device WATR packet test

echo "🚀 WATR Multi-Device Packet Test"
echo "=================================="
echo

# Check if both devices are reachable
echo "🔍 Checking device connectivity..."
if ! ssh tm10.local "echo 'tm10.local OK'" > /dev/null 2>&1; then
    echo "❌ tm10.local not reachable"
    exit 1
fi

if ! ssh tm11.local "echo 'tm11.local OK'" > /dev/null 2>&1; then
    echo "❌ tm11.local not reachable"
    exit 1
fi

echo "✓ Both devices reachable"
echo

# Function to start receiver with timeout
start_receiver() {
    echo "📥 Starting receiver on tm10.local..."
    ssh tm10.local "cd /opt/watr && timeout 30s sudo /opt/watr/venv/bin/python test-receive.py" &
    RECEIVER_PID=$!
    echo "   Receiver PID: $RECEIVER_PID"
    return $RECEIVER_PID
}

# Function to start sender
start_sender() {
    echo "📤 Starting sender on tm11.local..."
    ssh tm11.local "cd /opt/watr && sudo /opt/watr/venv/bin/python test-send.py"
}

# Start receiver in background
echo "📡 Setting up receiver on tm10.local (interface: wlx842096fbfd0b)..."
start_receiver

# Give receiver time to set up
echo "⏳ Waiting 5 seconds for receiver to initialize..."
sleep 5

# Start sender
echo "📡 Setting up sender on tm11.local (interface: wlan1)..."
start_sender

# Wait for receiver to finish
echo "⏳ Waiting for receiver to complete..."
wait $RECEIVER_PID

echo
echo "🎯 Multi-device test completed!"
echo "   Check logs above for transmission results"