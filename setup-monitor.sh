#!/bin/bash
# Setup monitor interface for WATR packet testing

INTERFACE="mon0"
PHY="${1:-phy0}"  # Default to phy0 if not specified

echo "🔧 Setting up monitor interface ${INTERFACE} on ${PHY}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root (use sudo)"
   exit 1
fi

# Function to find suitable PHY
find_monitor_capable_phy() {
    echo "🔍 Searching for monitor-capable PHY..."
    
    for phy in /sys/class/ieee80211/phy*; do
        phy_name=$(basename $phy)
        
        # Check if PHY supports monitor mode
        if iw phy $phy_name info | grep -q "monitor"; then
            echo "✓ Found monitor-capable PHY: $phy_name"
            
            # Check if PHY is not in use by managed interface
            interfaces=$(ls $phy/device/net 2>/dev/null || true)
            if [[ -z "$interfaces" ]] || [[ "$interfaces" == "$INTERFACE" ]]; then
                echo "$phy_name"
                return 0
            else
                echo "  PHY $phy_name is in use by: $interfaces"
            fi
        fi
    done
    
    return 1
}

# If PHY not specified or doesn't exist, find one
if [[ "$PHY" == "auto" ]] || [[ ! -d "/sys/class/ieee80211/$PHY" ]]; then
    PHY=$(find_monitor_capable_phy)
    if [[ -z "$PHY" ]]; then
        echo "❌ No suitable PHY found for monitor mode"
        exit 1
    fi
fi

# Remove existing monitor interface
if ip link show $INTERFACE &>/dev/null; then
    echo "🗑️  Removing existing $INTERFACE..."
    ip link set $INTERFACE down 2>/dev/null || true
    iw dev $INTERFACE del 2>/dev/null || true
fi

# Create monitor interface
echo "📡 Creating monitor interface on $PHY..."
if ! iw phy $PHY interface add $INTERFACE type monitor; then
    echo "❌ Failed to create monitor interface"
    exit 1
fi

# Configure interface
echo "⚙️  Configuring interface..."

# Set channel 1 (2412 MHz)
iw dev $INTERFACE set freq 2412

# Bring interface up
ip link set $INTERFACE up

# Verify
if ip link show $INTERFACE | grep -q "UP"; then
    echo "✅ Monitor interface $INTERFACE is ready!"
    
    # Show interface info
    echo
    echo "📊 Interface information:"
    iw dev $INTERFACE info
else
    echo "❌ Failed to bring up interface"
    exit 1
fi

echo
echo "🎯 Ready for WATR packet testing!"
echo "   Send packets: sudo python -m watr.packet_test_fixed send"
echo "   Receive packets: sudo python -m watr.packet_test_fixed receive"