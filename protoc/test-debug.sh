#!/bin/bash

# Test script to demonstrate hex dump and exit count features

echo "WATR Protocol Debug Test"
echo "========================"
echo ""
echo "This test will:"
echo "1. Run the receiver with exit count of 3 packets"
echo "2. Show hex dumps of frames with incorrect WATR magic"
echo "3. Display full packet details for valid WATR packets"
echo ""
echo "Usage: sudo ./test-debug.sh [interface]"
echo ""

INTERFACE=${1:-mon0}

echo "Using interface: $INTERFACE"
echo ""
echo "Starting receiver (will exit after 3 WATR packets)..."
echo ""

sudo ./receive-test $INTERFACE 3