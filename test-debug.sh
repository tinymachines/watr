#!/bin/bash
# Debug test for WATR packet transmission

echo "🚀 WATR Debug Test"
echo "=================="
echo

# Terminal 1: Start receiver on tm11
echo "📥 Starting receiver on tm11.local..."
echo "Run this in terminal 1:"
echo "ssh tm11.local 'cd /opt/watr && sudo /opt/watr/venv/bin/python debug-receive.py'"
echo

# Terminal 2: Start sender on tm10  
echo "📤 Starting sender on tm10.local..."
echo "Run this in terminal 2 (after receiver is ready):"
echo "ssh tm10.local 'cd /opt/watr && sudo /opt/watr/venv/bin/python debug-send.py'"
echo

echo "Or use tmux:"
echo "tmux new-session -d -s watr-test"
echo "tmux send-keys -t watr-test:0 \"ssh tm11.local 'cd /opt/watr && sudo /opt/watr/venv/bin/python debug-receive.py'\" C-m"
echo "tmux split-window -t watr-test:0 -h"
echo "tmux send-keys -t watr-test:0.1 \"sleep 5 && ssh tm10.local 'cd /opt/watr && sudo /opt/watr/venv/bin/python debug-send.py'\" C-m"
echo "tmux attach -t watr-test"