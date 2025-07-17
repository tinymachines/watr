# WATR - Custom Protocol Development Framework

WATR is a custom network protocol development framework that combines high-performance C++ implementation with Python bindings and Scapy integration for packet crafting and analysis.

## Features

- **High-Performance C++ Core**: Fast packet processing and protocol implementation
- **Python Bindings**: Easy-to-use Python API via pybind11
- **Scapy Integration**: Custom Scapy layers for packet manipulation
- **ARM64 Optimized**: Specifically optimized for Raspberry Pi 4 deployment
- **Monitor Mode Support**: WiFi packet injection and capture capabilities
- **Bootstrap Utility**: Automatic detection of WiFi and Bluetooth adapters

## Quick Start

### Prerequisites

- Python 3.8+
- CMake 3.12+ (for main project)
- C++17 compatible compiler
- Git (for submodules)
- libnl3 development libraries (for WiFi monitor utilities)

### Installation

1. Clone the repository with submodules:
```bash
git clone --recursive https://github.com/tinymachines/watr.git
cd watr
```

2. Set up Python virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3. Build the WiFi monitor utilities:
```bash
# Install dependencies and build WiFi monitor tools
./build_protoc.sh --install-deps

# Or just build if dependencies already installed
./build_protoc.sh
```

4. Build the main project:
```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
cd ..
pip install -e .
```

### Basic Usage

#### Python API
```python
import watr

# Create protocol instance
protocol = watr.Protocol()

# Craft a packet
packet = protocol.craft_packet(b"Hello WATR!")

# Parse a packet
parsed = protocol.parse_packet(packet)
print(f"Type: {parsed['type']}, Length: {parsed['length']}")
```

#### Scapy Integration
```python
from scapy.all import *
from watr.scapy_layers import WATRHeader, WATRPayload

# Create WATR packet
packet = WATRHeader(type=0x5741, length=12) / WATRPayload(data="Hello World!")

# Send packet
sendp(packet, iface="eth0")
```

## Deployment

### Raspberry Pi 4 (ARM64)

Deploy to a Raspberry Pi running Debian Bookworm:

```bash
./deploy_to_rpi.sh <hostname>

# Example
./deploy_to_rpi.sh tm11.local
```

The deployment script will:
- Install all dependencies
- Build the project on the target device
- Set up the virtual environment
- Configure the installation in `/opt/watr`

### Distribution Build

Create a distribution package:

```bash
./build_dist.sh
```

This creates a tarball in the `dist/` directory containing all necessary files for deployment.

## Bootstrap Utility

The bootstrap utility detects and configures wireless adapters:

```bash
# Basic detection
python bootstrap.py

# Detect adapters and setup monitor interface
python bootstrap.py --setup-monitor
```

Features:
- Automatic adapter detection
- Monitor mode capability testing
- **NEW**: Automatic monitor interface setup
- Best adapter selection (prefers USB over onboard)

Output example:
```
🔌 WiFi Adapters (2 found):
  🔴 wlan0 (phy0) - Onboard brcmfmac - Monitor: NO
  🟢 wlan1 (phy3) - USB rtl8xxxu - Monitor: YES

📱 Bluetooth Adapters (1 found):
  🔵 hci0 - Onboard Bluetooth

🔧 MONITOR INTERFACE SETUP
📡 Using adapter: wlan1 (phy3)
✅ Monitor interface mon0 successfully created!
  📡 Interface: mon0
  📻 Physical device: phy3
  📶 Channel: 1 (2412 MHz)
  🎯 Ready for packet injection/capture
```

## Packet Testing

Test packet transmission between devices using the working implementation:

### Setup Monitor Interface
First, create a dedicated monitor interface:
```bash
sudo ./setup-monitor.sh auto
```

### Working Implementation
The fixed implementation uses 802.11 data frames with LLC/SNAP encapsulation:

```bash
# Sender (on device 1)
sudo python -m watr.packet_test_fixed send

# Receiver (on device 2)
sudo python -m watr.packet_test_fixed receive
```

### Simple Test Scripts
```bash
# On device 1 (receiver)
sudo /opt/watr/venv/bin/python test-watr-receive.py

# On device 2 (sender)
sudo /opt/watr/venv/bin/python test-watr-send.py
```

### Why This Works
- Uses data frames (type=2) instead of management frames
- Includes proper LLC/SNAP headers with custom protocol ID
- Uses dedicated monitor interface (mon0) for reliable injection

## WiFi Monitor Utilities

### Building the Monitor Tools

The project includes two rock-solid C programs for WiFi monitor mode operations:

- `wifi-monitor-check` - Detect adapters and their monitor mode capabilities
- `wifi-monitor-setup` - Create and configure monitor interfaces

```bash
# Build with automatic dependency installation
./build_protoc.sh --install-deps

# Quick build (dependencies already installed)
./build_protoc.sh

# Clean build artifacts
./build_protoc.sh --clean
```

### Cross-Platform Support

The build script automatically detects your platform and optimizes compilation:

- **ARM64/Raspberry Pi 4**: `-march=armv8-a+crc+crypto`
- **x86_64**: `-march=x86-64 -mtune=generic`
- **Linux distributions**: Ubuntu/Debian, Fedora/RHEL/CentOS, Arch, Alpine
- **macOS**: Homebrew-based dependency installation

### Usage

```bash
# Check which adapters support monitor mode
./wifi-monitor-check

# Create monitor interface on specific PHY
sudo ./wifi-monitor-setup phy3
```

### Manual Monitor Mode Operations

Set WiFi adapter to monitor mode manually:

```bash
# Enable monitor mode
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up
sudo iw dev wlan1 set channel 6

# Disable monitor mode
sudo ip link set wlan1 down
sudo iw dev wlan1 set type managed
sudo ip link set wlan1 up
```

## Project Structure

```
watr/
├── include/watr/       # C++ headers
├── src/               # C++ implementation
│   ├── protocol.cpp   # Core protocol logic
│   └── bindings.cpp   # Python bindings
├── protoc/            # WiFi monitor utilities
│   ├── wifi-monitor-check.c   # Adapter detection
│   └── wifi-monitor-setup.c   # Monitor interface setup
├── python/watr/       # Python package
│   ├── __init__.py   # Python API
│   ├── scapy_layers.py # Scapy integration
│   ├── bootstrap.py   # Adapter detection
│   └── packet_test.py # Packet testing
├── tests/            # Test suite
├── build_protoc.sh   # Cross-platform build script
├── scapy/           # Scapy submodule
└── CMakeLists.txt   # Build configuration
```

## API Reference

### C++ API

```cpp
namespace watr {
    class Protocol {
        std::vector<uint8_t> craft_packet(const std::vector<uint8_t>& data);
        std::map<std::string, uint32_t> parse_packet(const std::vector<uint8_t>& packet);
        void set_header_field(const std::string& field, uint32_t value);
        uint32_t get_header_field(const std::string& field) const;
    };
}
```

### Python API

```python
class Protocol:
    def craft_packet(self, data: bytes) -> bytes:
        """Create a WATR protocol packet"""
    
    def parse_packet(self, packet: bytes) -> dict:
        """Parse a WATR protocol packet"""
    
    def set_header_field(self, field: str, value: int) -> None:
        """Set protocol header field"""
    
    def get_header_field(self, field: str) -> int:
        """Get protocol header field value"""
```

### Scapy Layers

```python
class WATRHeader(Packet):
    fields_desc = [
        XIntField("type", 0),
        XIntField("length", 0),
    ]

class WATRPayload(Packet):
    fields_desc = [
        StrField("data", "")
    ]
```

## Testing

Run the test suite:

```bash
# Python tests
pytest tests/ -v

# C++ tests (if available)
cd build && ctest
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Documentation

- [Quick Start Guide](QUICKSTART.md) - Get started in 5 minutes
- [Packet Transmission Guide](docs/PACKET_TRANSMISSION.md) - Detailed transmission documentation
- [API Reference](docs/API.md) - Complete API documentation
- [Deployment Guide](docs/DEPLOYMENT.md) - Installation and deployment
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Common issues and solutions

## Acknowledgments

- Built with [pybind11](https://github.com/pybind/pybind11) for Python bindings
- Uses [Scapy](https://scapy.net/) for packet manipulation
- Optimized for Raspberry Pi 4 ARM64 architecture
- Based on working implementation from [protoc/custom.py](protoc/custom.py)