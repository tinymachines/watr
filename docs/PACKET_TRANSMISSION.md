# WATR Packet Transmission Guide

## Overview

WATR implements a custom protocol for WiFi packet transmission using 802.11 data frames with LLC/SNAP encapsulation. This approach provides reliable packet delivery between devices in monitor mode.

## Key Concepts

### Frame Structure

The working implementation uses the following packet structure:

```
RadioTap Header
    ↓
Dot11 Data Frame (type=2, subtype=0)
    ↓
LLC Header (DSAP=0xAA, SSAP=0xAA)
    ↓
SNAP Header (OUI=0x000000, Protocol=0x8999)
    ↓
WATR Protocol Data
```

### Why Data Frames Work

1. **Driver Compatibility**: Data frames are less likely to be filtered by WiFi drivers
2. **Standard Compliance**: LLC/SNAP encapsulation follows 802.11 standards
3. **Custom Protocol ID**: 0x8999 uniquely identifies WATR traffic
4. **Monitor Mode**: Dedicated interface ensures proper injection/capture

## Quick Start

### 1. Setup Monitor Interface

Both sender and receiver need a monitor interface:

```bash
# Automatic setup (finds best PHY)
sudo ./setup-monitor.sh auto

# Manual setup with specific PHY
sudo ./setup-monitor.sh phy0
```

This creates a `mon0` interface on channel 1 (2412 MHz).

### 2. Test Packet Transmission

#### Simple Method

**Receiver** (Device 1):
```bash
cd /opt/watr
sudo /opt/watr/venv/bin/python test-watr-receive.py
```

**Sender** (Device 2):
```bash
cd /opt/watr
sudo /opt/watr/venv/bin/python test-watr-send.py
```

#### Advanced Method

**Receiver**:
```bash
sudo python -m watr.packet_test_fixed receive \
    --interface mon0 \
    --channel 1
```

**Sender**:
```bash
sudo python -m watr.packet_test_fixed send \
    --interface mon0 \
    --channel 1 \
    --count 10 \
    --payload "Hello WATR!"
```

## Detailed Implementation

### Creating WATR Data Frames

```python
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, LLC, SNAP

# Create 802.11 data frame
dot11 = Dot11(
    type=2,      # Data frame
    subtype=0,   # Data
    addr1=dst_mac,
    addr2=src_mac,
    addr3=src_mac,
    FCfield='from-DS'
)

# Add LLC layer
llc = LLC(
    dsap=0xAA,   # SNAP
    ssap=0xAA,   # SNAP
    ctrl=0x03    # UI
)

# Add SNAP with custom protocol
snap = SNAP(
    OUI=0x000000,
    code=0x8999  # WATR protocol ID
)

# Combine with payload
frame = RadioTap() / dot11 / llc / snap / Raw(load=watr_data)
```

### Receiving WATR Packets

```python
def packet_filter(pkt):
    return (
        pkt.haslayer(Dot11) and
        pkt[Dot11].type == 2 and
        pkt[Dot11].subtype == 0 and
        pkt.haslayer(SNAP) and
        pkt[SNAP].code == 0x8999
    )

# Sniff for WATR packets
sniff(iface="mon0", lfilter=packet_filter, prn=handle_watr_packet)
```

## Multi-Device Testing

### Test Between Raspberry Pi Devices

1. **Prepare Both Devices**:
```bash
# On both tm10.local and tm11.local
cd /opt/watr
sudo ./setup-monitor.sh auto
```

2. **Start Receiver** (tm11.local):
```bash
ssh tm11.local
cd /opt/watr
sudo /opt/watr/venv/bin/python test-watr-receive.py
```

3. **Start Sender** (tm10.local):
```bash
ssh tm10.local
cd /opt/watr
sudo /opt/watr/venv/bin/python test-watr-send.py
```

### Expected Output

**Sender**:
```
📤 Starting packet transmission...
   Interface: mon0
   Channel: 1
   Count: 10
   Payload: Hello from WATR!
📡 Sent packet #1: Hello from WATR! #1
📡 Sent packet #2: Hello from WATR! #2
...
✓ Transmission complete! Sent 10 packets
```

**Receiver**:
```
📥 Starting packet reception...
   Interface: mon0
   Channel: 1
📥 Received WATR packet #1: Hello from WATR! #1
   From: 00:11:22:33:44:55 -> 66:77:88:99:AA:BB
📥 Received WATR packet #2: Hello from WATR! #2
   From: 00:11:22:33:44:55 -> 66:77:88:99:AA:BB
...
✓ Reception complete! Received 10 WATR packets
```

## Advanced Configuration

### Custom MAC Addresses

```bash
# Sender with custom MACs
sudo python -m watr.packet_test_fixed send \
    --src-mac "AA:BB:CC:DD:EE:FF" \
    --dst-mac "11:22:33:44:55:66"
```

### Different Channels

```bash
# Use channel 6 (2437 MHz)
sudo iw dev mon0 set freq 2437

# Or channel 11 (2462 MHz)
sudo iw dev mon0 set freq 2462
```

### Broadcast Packets

```bash
# Send to broadcast address
sudo python -m watr.packet_test_fixed send \
    --dst-mac "FF:FF:FF:FF:FF:FF"
```

## Integration with WATR Protocol

The packet transmission system integrates with WATR's protocol layer:

```python
from watr import Protocol
from watr.packet_test_fixed import PacketSender, TestConfig

# Create WATR protocol instance
protocol = Protocol()
protocol.set_header_field('type', 0x5741)

# Craft WATR packet
watr_data = protocol.craft_packet(b"Custom protocol data")

# Configure sender
config = TestConfig(
    interface="mon0",
    payload=watr_data.decode('latin-1')  # Convert bytes for transmission
)

# Send packet
sender = PacketSender(config)
sender.send_packets()
```

## Performance Considerations

### Transmission Rate

- Default: 1 packet per second
- Adjust with `--interval` parameter
- Minimum recommended: 0.1 seconds between packets

### Packet Size

- Maximum payload: ~1500 bytes (Ethernet MTU)
- Recommended: Keep under 1000 bytes for reliability
- WATR header adds 8 bytes overhead

### Channel Selection

- Channel 1 (2412 MHz): Default, less congested
- Channel 6 (2437 MHz): Common AP channel
- Channel 11 (2462 MHz): Alternative option
- Avoid DFS channels (52-140) for simplicity

## Debugging

### Verify Monitor Mode

```bash
# Check interface status
iw dev mon0 info

# Should show:
# Interface mon0
#     type monitor
#     channel 1 (2412 MHz)
```

### Monitor All Traffic

```bash
# See all packets on the interface
sudo tcpdump -i mon0 -n -e

# Filter for data frames
sudo tcpdump -i mon0 -n -e "type data"
```

### Check for WATR Packets

```bash
# Look for custom protocol ID in hex dump
sudo tcpdump -i mon0 -XX | grep -A2 -B2 "89 99"
```

## Security Notes

1. **Monitor Mode**: Requires root privileges
2. **Packet Injection**: Only use on networks you own
3. **MAC Addresses**: Can use any MAC for testing
4. **Encryption**: Packets are sent unencrypted
5. **Channel Usage**: Respect local regulations

## References

- Original implementation: `protoc/custom.py`
- Fixed implementation: `python/watr/packet_test_fixed.py`
- Monitor setup: `setup-monitor.sh`
- C utilities: `protoc/wifi-monitor-setup.c`