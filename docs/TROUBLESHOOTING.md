# WATR Troubleshooting Guide

## Common Issues and Solutions

### Monitor Mode Issues

#### "Operation not supported" when creating monitor interface

**Cause**: WiFi adapter doesn't support monitor mode

**Solution**:
1. Check adapter capabilities:
```bash
iw phy phy0 info | grep -A8 "Supported interface modes"
```

2. Use a different adapter (USB adapters often work better)

3. Update firmware:
```bash
sudo apt-get update
sudo apt-get install firmware-misc-nonfree
```

#### Monitor interface exists but packets won't send

**Cause**: Interface not properly configured

**Solution**:
```bash
# Remove and recreate
sudo iw dev mon0 del
sudo ./setup-monitor.sh auto
```

### Packet Transmission Issues

#### Sender reports success but receiver gets nothing

**Cause**: Channel mismatch or driver filtering

**Solutions**:

1. **Verify same channel**:
```bash
# On both devices
iw dev mon0 info | grep channel
```

2. **Use broadcast MAC**:
```bash
sudo python -m watr.packet_test_fixed send --dst-mac FF:FF:FF:FF:FF:FF
```

3. **Check for actual transmission**:
```bash
# On sender, run tcpdump while sending
sudo tcpdump -i mon0 -n -e -X
```

#### "Network is down" error

**Cause**: Monitor interface not up

**Solution**:
```bash
sudo ip link set mon0 up
```

#### Permission denied errors

**Cause**: Packet injection requires root

**Solution**: Always use `sudo` when running packet tests

### Scapy Issues

#### "No module named 'scapy'"

**Solution**:
```bash
source /opt/watr/venv/bin/activate
pip install scapy
```

#### Scapy import errors with VERSION

**Solution**: Update scapy
```bash
pip install --upgrade scapy
```

### Device-Specific Issues

#### Raspberry Pi 4 onboard WiFi

**Issue**: Onboard WiFi (brcmfmac) doesn't support monitor mode

**Solution**: Use USB WiFi adapter that supports monitor mode:
- RTL8812AU
- RTL8814AU
- ALFA AWUS036ACH

#### USB adapter not detected

**Solutions**:

1. **Check USB power**:
```bash
# May need powered hub for some adapters
dmesg | tail -20
```

2. **Reload driver**:
```bash
sudo modprobe -r rtl8xxxu
sudo modprobe rtl8xxxu
```

3. **Reset USB device**:
```bash
sudo usbreset $(lsusb | grep -i wireless | cut -d' ' -f6)
```

### Debugging Tools

#### Monitor all WiFi traffic

```bash
# See all packets on monitor interface
sudo tcpdump -i mon0 -n -e

# Filter for data frames only
sudo tcpdump -i mon0 -n -e "type data"

# Look for WATR protocol ID
sudo tcpdump -i mon0 -XX | grep "89 99"
```

#### Check adapter status

```bash
# Physical layer info
iw phy

# Interface info
iw dev

# Regulatory domain
iw reg get
```

#### Test basic monitor mode

```bash
# Simple injection test
sudo aireplay-ng --test mon0
```

### Performance Issues

#### Slow packet transmission

**Causes**: Power saving, regulatory restrictions

**Solutions**:

1. **Disable power save**:
```bash
sudo iw dev mon0 set power_save off
```

2. **Increase TX power** (if allowed):
```bash
sudo iw dev mon0 set txpower fixed 2000  # 20 dBm
```

3. **Check CPU frequency**:
```bash
# Set performance mode
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

### Advanced Debugging

#### Packet not parsed correctly

Enable debug output:
```python
# In packet_handler function
print(f"Raw packet: {packet.summary()}")
print(f"Layers: {[layer.name for layer in packet.layers()]}")
if packet.haslayer(Raw):
    print(f"Raw data: {packet[Raw].load.hex()}")
```

#### Monitor mode capabilities by driver

Common drivers and their support:

| Driver | Monitor | Injection | Notes |
|--------|---------|-----------|-------|
| rtl8xxxu | Yes | Yes | Good for USB adapters |
| rtl88xxau | Yes | Yes | Requires external driver |
| ath9k_htc | Yes | Yes | Atheros USB |
| rt2800usb | Yes | Limited | Ralink USB |
| brcmfmac | No | No | RPi onboard |

### Getting Help

1. **Check logs**:
```bash
# System logs
sudo journalctl -xe

# Kernel messages
dmesg | grep -i wifi

# Network manager logs
sudo journalctl -u NetworkManager
```

2. **Diagnostic info**:
```bash
# Collect system info
uname -a
lsb_release -a
iw --version
python --version
pip show scapy
```

3. **Test with known working tools**:
```bash
# If WATR doesn't work, try:
sudo apt-get install aircrack-ng
sudo airmon-ng start wlan1
sudo airodump-ng wlan1mon
```

### Still Having Issues?

1. Try the original working code:
```bash
cd /opt/watr/protoc
sudo python custom.py send  # or receive
```

2. Report issues with:
- Device model and WiFi adapter details
- Output of diagnostic commands
- Exact error messages
- Steps to reproduce