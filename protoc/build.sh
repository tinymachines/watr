#!/bin/bash
# Build script for WATR protocol tools

set -e

echo "Building WATR protocol tools..."

# Clean previous build
make clean

# Build
make -j$(nproc)

# Check build results
if [ -f send-test ] && [ -f receive-test ]; then
    echo "Build successful!"
    echo "Programs built:"
    ls -la send-test receive-test
    
    # Make sure they're executable
    chmod +x send-test receive-test
    
    echo ""
    echo "To test on tm10.local and tm11.local:"
    echo "  1. Copy to devices: scp {send,receive}-test user@tm11.local:/tmp/"
    echo "  2. On tm10.local: sudo /tmp/receive-test mon0"
    echo "  3. On tm11.local: sudo /tmp/send-test mon0"
else
    echo "Build failed!"
    exit 1
fi