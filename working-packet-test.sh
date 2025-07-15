#!/bin/bash
# Working WATR packet test using data frames

echo "🚀 WATR Working Packet Test"
echo "==========================="
echo
echo "This test uses the working implementation with:"
echo "- 802.11 Data frames (type=2)"
echo "- LLC/SNAP encapsulation" 
echo "- Custom protocol ID (0x8999)"
echo "- Dedicated monitor interface (mon0)"
echo

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root (use sudo)"
   exit 1
fi

# Deploy working implementation
echo "📦 Deploying working implementation..."
scp python/watr/packet_test_fixed.py tm11.local:/opt/watr/python/watr/
scp python/watr/packet_test_fixed.py tm10.local:/opt/watr/python/watr/
scp test-watr-send.py test-watr-receive.py setup-monitor.sh tm11.local:/opt/watr/
scp test-watr-send.py test-watr-receive.py setup-monitor.sh tm10.local:/opt/watr/
echo "✓ Deployed"

echo
echo "📡 Setup Instructions:"
echo
echo "1. On BOTH devices, setup monitor interface:"
echo "   ssh tm11.local 'cd /opt/watr && sudo ./setup-monitor.sh auto'"
echo "   ssh tm10.local 'cd /opt/watr && sudo ./setup-monitor.sh auto'"
echo
echo "2. Start receiver on tm11:"
echo "   ssh tm11.local 'cd /opt/watr && sudo /opt/watr/venv/bin/python test-watr-receive.py'"
echo
echo "3. Start sender on tm10:"
echo "   ssh tm10.local 'cd /opt/watr && sudo /opt/watr/venv/bin/python test-watr-send.py'"
echo
echo "The sender will transmit 10 WATR packets using data frames."
echo "The receiver should successfully capture and display them."
echo

read -p "Press Enter to setup monitor interfaces on both devices..."

# Setup monitor interfaces
echo
echo "🔧 Setting up monitor interfaces..."
ssh tm11.local "cd /opt/watr && sudo ./setup-monitor.sh auto" &
ssh tm10.local "cd /opt/watr && sudo ./setup-monitor.sh auto" &
wait

echo
echo "✅ Monitor interfaces ready!"
echo
echo "Now run the receiver and sender commands shown above in separate terminals."