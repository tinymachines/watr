# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WATR is a custom protocol development project that combines C/C++ high-performance components with Python bindings and Scapy integration for packet crafting and analysis. The project is specifically optimized for ARM64/Raspberry Pi 4 deployment and includes WiFi monitor mode capabilities for packet injection and capture.

## Architecture

- **C++ Core (`src/`, `include/`)**: High-performance protocol implementation
- **Python Bindings (`src/bindings.cpp`)**: pybind11 bridge between C++ and Python
- **Python Package (`python/watr/`)**: Python API and Scapy integration
- **Scapy Submodule (`scapy/`)**: Git submodule for packet manipulation
- **Bootstrap System (`python/watr/bootstrap.py`)**: Adapter detection and configuration
- **Packet Testing (`python/watr/packet_test.py`)**: Monitor mode packet transmission
- **Tests (`tests/`)**: Test suite for both C++ and Python components
- **Deployment Scripts**: Automated deployment and distribution building

## Development Setup

### Environment Setup
```bash
# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Update submodules
git submodule update --init --recursive
```

### Building the Project
```bash
# Create build directory
mkdir -p build && cd build

# Configure with cmake
cmake ..

# Build C++ components and Python bindings
make -j$(nproc)

# Install Python package in development mode
cd .. && pip install -e .
```

### Running Tests
```bash
# Python tests
pytest tests/ -v --cov=watr

# C++ tests (if available)
cd build && ctest

# Scapy integration tests
python -m pytest tests/test_scapy_integration.py
```

## Key Components

### Protocol Class (`watr::Protocol`)
Core C++ class for packet operations:
- `craft_packet()`: Create packets from data
- `parse_packet()`: Parse incoming packets
- `set_header_field()`/`get_header_field()`: Header manipulation

### Scapy Integration (`python/watr/scapy_layers.py`)
Custom Scapy layers:
- `WATRHeader`: Protocol header definition
- `WATRPayload`: Payload handling
- Layer binding for automatic packet assembly

### Python API (`python/watr/__init__.py`)
High-level Python interface exposing C++ functionality through pybind11.

## Development Guidelines

### Adding New Protocol Features
1. Implement C++ functionality in `src/protocol.cpp`
2. Add corresponding header declarations in `include/watr/protocol.h`
3. Expose to Python via `src/bindings.cpp`
4. Create Scapy layer definitions in `python/watr/scapy_layers.py`
5. Add comprehensive tests

### Scapy Submodule Management
```bash
# Update scapy to latest version
cd scapy && git pull origin main && cd ..
git add scapy && git commit -m "Update scapy submodule"

# Initialize scapy submodule in fresh clone
git submodule update --init --recursive
```

### Testing Strategy
- Unit tests for C++ components using Google Test (if added)
- Python unit tests with pytest
- Integration tests for C++/Python bindings
- Scapy layer validation tests
- Performance benchmarks for packet processing

## Common Commands

```bash
# Full development cycle
source venv/bin/activate
mkdir -p build && cd build && cmake .. && make -j$(nproc) && cd ..
pip install -e .
pytest tests/ -v

# Quick Python-only development
source venv/bin/activate
python -c "import watr; print(watr.__version__)"

# Interactive Scapy with WATR layers
source venv/bin/activate
python -c "from scapy.all import *; from watr.scapy_layers import *"
```

## ARM64/Raspberry Pi 4 Deployment

WATR is optimized for deployment on Raspberry Pi 4 running Debian Bookworm (ARM64).

### Quick Deployment
```bash
# Deploy to a Raspberry Pi
./deploy_to_rpi.sh <hostname>

# Example: Deploy to tm11.local
./deploy_to_rpi.sh tm11.local
```

### Platform-Specific Notes
- Target platform: ARM64/aarch64 architecture
- OS: Debian Bookworm or compatible
- C++ optimizations: `-march=armv8-a+crc+crypto`
- Installation directory: `/opt/watr`
- No cross-compilation needed - builds natively on target

### Distribution Build
```bash
# Create distribution package
./build_dist.sh

# Deploy manually
scp dist/watr-dist-*.tar.gz user@rpi:/tmp/
ssh user@rpi
tar -xzf /tmp/watr-dist-*.tar.gz
cd watr-dist-*/scripts
./setup.sh
```

## Wireless Adapter Bootstrap

WATR includes a bootstrap utility to detect and configure WiFi and Bluetooth adapters for protocol development.

### Bootstrap Command
```bash
# Basic adapter detection
python bootstrap.py

# Detection + automatic monitor interface setup
python bootstrap.py --setup-monitor

# Setup monitor with custom interface name
python bootstrap.py --setup-monitor --monitor-interface mon1

# Use specific adapter for monitor mode
python bootstrap.py --setup-monitor --adapter wlan1
```

### Adapter Detection Features
- **WiFi Adapters**: Detects onboard and USB WiFi adapters
- **Monitor Mode Testing**: Practical testing of monitor mode capabilities
- **Monitor Interface Setup**: Automatic creation of monitor interface
- **Bluetooth Detection**: Identifies Bluetooth adapters
- **RFKill Management**: Automatically unblocks wireless adapters
- **Configuration Export**: Saves adapter info to JSON for other tools

### Typical RPi4 Setup
```
🔌 WiFi Adapters (2 found):
  🔴 wlan0 (phy0) - Onboard brcmfmac - Monitor: NO
  🟢 wlan1 (phy3) - USB rtl8xxxu - Monitor: YES

📱 Bluetooth Adapters (1 found):
  🔵 hci0 - Onboard Bluetooth
```

### Monitor Mode Operations
```bash
# Set monitor mode (requires sudo)
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up

# Check monitor mode status
iw dev wlan1 info

# Return to managed mode
sudo ip link set wlan1 down
sudo iw dev wlan1 set type managed
sudo ip link set wlan1 up
```

### Using with Scapy
```python
# Example: Use monitor-capable adapter for packet sniffing
from scapy.all import *

# Monitor mode should be set first
# Interface wlan1 (USB adapter) supports monitor mode
sniff(iface="wlan1", prn=lambda x: x.summary())
```

## Packet Testing

WATR includes a comprehensive packet testing system for validating custom protocol transmission between devices.

### Quick Test Commands
```bash
# Simple packet transmission test
sudo /opt/watr/venv/bin/python test-send.py

# Packet reception test
sudo /opt/watr/venv/bin/python test-receive.py

# Full coordinator (when working)
sudo ./test-packets send
sudo ./test-packets receive
```

### Test Features
- **Monitor Mode Integration**: Uses bootstrap-detected monitor-capable adapters
- **Custom Protocol Packets**: Transmits WATR protocol packets over WiFi
- **Beacon Frame Embedding**: Embeds WATR data in WiFi beacon frames
- **Multi-device Testing**: Send on one device, receive on another
- **Root Privilege Handling**: Properly manages sudo requirements

### Tested Configuration
```
📡 Successfully tested on tm11.local:
   Interface: wlan1 (USB rtl8xxxu)
   Channel: 6
   Mode: Monitor
   Packets: 3 sent successfully
   
✓ WATR protocol packets transmitted over WiFi
✓ Monitor mode setup/teardown working
✓ Bootstrap integration functional
```

### Multi-Device Testing Procedure
1. **Setup both devices**: Run `python bootstrap.py` on each device
2. **Start receiver**: `sudo /opt/watr/venv/bin/python test-receive.py` on device 1
3. **Start sender**: `sudo /opt/watr/venv/bin/python test-send.py` on device 2
4. **Verify transmission**: Check packet counters on both devices

## Working Packet Transmission Solution

### Key Implementation Details
The working solution uses **802.11 Data frames** instead of beacon/management frames:

1. **Frame Type**: Use type=2 (Data), subtype=0 for reliable transmission
2. **Encapsulation**: LLC/SNAP headers with custom protocol ID (0x8999)
3. **Monitor Interface**: Dedicated `mon0` interface for packet injection/capture
4. **Frame Structure**: RadioTap / Dot11 / LLC / SNAP / Raw(WATR payload)

### Setup Monitor Interface
```bash
# Automatic setup (finds suitable PHY)
sudo ./setup-monitor.sh auto

# Manual setup with specific PHY
sudo ./setup-monitor.sh phy0

# Or using iw directly
sudo iw phy phy0 interface add mon0 type monitor
sudo iw dev mon0 set freq 2412  # Channel 1
sudo ip link set mon0 up
```

### Working Test Commands
```bash
# Fixed implementation that works
sudo python -m watr.packet_test_fixed send
sudo python -m watr.packet_test_fixed receive

# Or use simple test scripts
sudo /opt/watr/venv/bin/python test-watr-send.py
sudo /opt/watr/venv/bin/python test-watr-receive.py
```

### Why This Works
1. **Data frames** are less filtered by drivers than management frames
2. **LLC/SNAP encapsulation** provides proper protocol identification
3. **Custom protocol ID** (0x8999) avoids conflicts with standard protocols
4. **Dedicated monitor interface** ensures proper injection capabilities

### Original Working Code Reference
The solution is based on working code from `protoc/custom.py` which successfully transmits packets between devices using this approach.