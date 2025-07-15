# WATR Deployment Guide

## Target Platform

WATR is optimized for deployment on:
- **Hardware**: Raspberry Pi 4
- **Architecture**: ARM64/aarch64
- **OS**: Debian Bookworm or compatible
- **Python**: 3.9+

## Quick Deployment

### Using Deploy Script

The fastest way to deploy WATR to a Raspberry Pi:

```bash
./deploy_to_rpi.sh <hostname>

# Example
./deploy_to_rpi.sh tm11.local
```

This script will:
1. Check SSH connectivity
2. Install system dependencies
3. Clone the repository to `/opt/watr`
4. Build the project on the target device
5. Set up Python virtual environment
6. Run initial tests

### Prerequisites on Target

The target Raspberry Pi should have:
- SSH access enabled
- `sudo` privileges for the user
- Internet connectivity for package installation
- At least 1GB free disk space

## Manual Deployment

### 1. System Dependencies

Install required packages on the target:

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    python3-dev \
    python3-pip \
    python3-venv \
    git \
    libpcap-dev \
    wireless-tools \
    iw \
    rfkill
```

### 2. Clone Repository

```bash
sudo mkdir -p /opt/watr
sudo chown $USER:$USER /opt/watr
cd /opt
git clone --recursive https://github.com/tinymachines/watr.git
cd watr
```

### 3. Build Project

```bash
# Create build directory
mkdir -p build && cd build

# Configure with CMake
cmake ..

# Build (using all cores)
make -j$(nproc)

# Return to project root
cd ..
```

### 4. Python Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate environment
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Install WATR package in development mode
pip install -e .
```

### 5. Verify Installation

```bash
# Test Python import
python -c "import watr; print(watr.__version__)"

# Run bootstrap to detect adapters
python bootstrap.py

# Run tests
pytest tests/ -v
```

## Distribution Build

### Creating a Distribution Package

To create a portable distribution:

```bash
./build_dist.sh
```

This creates a tarball in `dist/` containing:
- Compiled binaries
- Python package
- Dependencies
- Setup scripts

### Deploying Distribution

1. Copy distribution to target:
```bash
scp dist/watr-dist-*.tar.gz user@raspberry:/tmp/
```

2. Extract and install:
```bash
ssh user@raspberry
cd /tmp
tar -xzf watr-dist-*.tar.gz
cd watr-dist-*
sudo ./scripts/setup.sh
```

## Network Configuration

### WiFi Adapter Setup

1. Identify monitor-capable adapter:
```bash
python /opt/watr/bootstrap.py
```

2. Configure adapter for packet injection:
```bash
# Disable NetworkManager for the interface
sudo nmcli device set wlan1 managed no

# Enable monitor mode
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up
```

### Permissions

WATR requires root privileges for:
- Monitor mode configuration
- Packet injection
- Raw socket access

Add user to necessary groups:
```bash
sudo usermod -a -G netdev $USER
```

## Service Installation

### Systemd Service

Create a service file for automatic startup:

```bash
sudo tee /etc/systemd/system/watr.service << EOF
[Unit]
Description=WATR Protocol Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/watr
Environment="PATH=/opt/watr/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/opt/watr/venv/bin/python /opt/watr/your_service.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable watr.service
```

## Troubleshooting

### Common Issues

1. **Monitor mode not supported**
   - Check adapter compatibility with `iw list`
   - Try different USB WiFi adapter
   - Update firmware: `sudo apt-get install firmware-misc-nonfree`

2. **Permission denied errors**
   - Ensure running with `sudo`
   - Check user groups: `groups`
   - Verify capabilities: `getcap /usr/bin/python3`

3. **Build failures**
   - Check CMake version: `cmake --version` (need 3.12+)
   - Verify compiler: `g++ --version` (need C++17 support)
   - Install missing dev packages

4. **Import errors**
   - Activate virtual environment: `source /opt/watr/venv/bin/activate`
   - Rebuild bindings: `cd build && make clean && make`
   - Check Python path: `python -c "import sys; print(sys.path)"`

### Logs and Debugging

Enable debug output:
```bash
export WATR_DEBUG=1
python test-send.py
```

Check system logs:
```bash
# WiFi driver messages
sudo dmesg | grep -i wifi

# Monitor mode issues
sudo journalctl -u NetworkManager | grep wlan1
```

## Performance Tuning

### ARM64 Optimizations

The build system automatically detects ARM64 and applies optimizations:
- Compiler flags: `-march=armv8-a+crc+crypto`
- NEON SIMD instructions enabled
- Link-time optimization (LTO) for release builds

### Network Performance

1. Disable power management:
```bash
sudo iw dev wlan1 set power_save off
```

2. Increase TX power (if allowed):
```bash
sudo iw dev wlan1 set txpower fixed 3000
```

3. Set CPU governor:
```bash
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

## Security Considerations

1. **Packet Injection**: Only use on networks you own or have permission to test
2. **Monitor Mode**: May disrupt normal WiFi operation on the interface
3. **Root Access**: Required for raw socket operations - use with caution
4. **Firewall**: May need to adjust rules for packet capture/injection

## Updating

To update an existing installation:

```bash
cd /opt/watr
git pull
git submodule update --init --recursive
cd build
make clean
cmake ..
make -j$(nproc)
cd ..
source venv/bin/activate
pip install -e . --upgrade
```