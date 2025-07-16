# WATR Quick Start Guide

Get WATR packet transmission working in 5 minutes!

## Prerequisites

- 2 devices with WiFi adapters that support monitor mode
- Root/sudo access
- WATR installed at `/opt/watr`

## Step 1: Setup Monitor Interface (Both Devices)

### Option A: Using Bootstrap (Recommended)
```bash
cd /opt/watr
python bootstrap.py --setup-monitor
```

### Option B: Using Setup Script
```bash
cd /opt/watr
sudo ./setup-monitor.sh auto
```

Either method creates a `mon0` interface for packet injection/capture.

## Step 2: Start Receiver (Device 1)

```bash
sudo /opt/watr/venv/bin/python test-watr-receive.py
```

You'll see:
```
🚀 WATR Packet Receive Test (Fixed)
📥 Starting packet reception...
   Interface: mon0
   Channel: 1
   Listening for WATR data frames...
   Press Ctrl+C to stop
```

## Step 3: Start Sender (Device 2)

```bash
sudo /opt/watr/venv/bin/python test-watr-send.py
```

You'll see:
```
🚀 WATR Packet Send Test (Fixed)
📤 Starting packet transmission...
   Interface: mon0
   Channel: 1
📡 Sent packet #1: Hello from WATR! #1
📡 Sent packet #2: Hello from WATR! #2
...
```

## Step 4: Verify Reception

On the receiver, you should see:
```
📥 Received WATR packet #1: Hello from WATR! #1
   From: 00:11:22:33:44:55 -> 66:77:88:99:AA:BB
📥 Received WATR packet #2: Hello from WATR! #2
   From: 00:11:22:33:44:55 -> 66:77:88:99:AA:BB
...
```

## Success! 🎉

You've successfully transmitted WATR packets between devices!

## What's Next?

### Custom Payloads
```bash
sudo python -m watr.packet_test_fixed send --payload "Custom message!"
```

### Different Channels
```bash
# Use channel 6
sudo python -m watr.packet_test_fixed send --channel 6
sudo python -m watr.packet_test_fixed receive --channel 6
```

### Python API
```python
from watr.packet_test_fixed import PacketSender, TestConfig

config = TestConfig(
    interface="mon0",
    payload="Hello from Python!"
)
sender = PacketSender(config)
sender.send_packets()
```

## Troubleshooting

### No Monitor Mode Support?
```bash
# Check available PHYs
iw phy
```

### Permission Denied?
Make sure to use `sudo` - monitor mode requires root privileges.

### No Packets Received?
1. Verify both devices are on the same channel
2. Check monitor interface is up: `iw dev mon0 info`
3. Try broadcast MAC: `--dst-mac FF:FF:FF:FF:FF:FF`

## Learn More

- [Packet Transmission Guide](docs/PACKET_TRANSMISSION.md)
- [API Documentation](docs/API.md)
- [Deployment Guide](docs/DEPLOYMENT.md)