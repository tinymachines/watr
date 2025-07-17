# WATR Protocol C/C++ Implementation

Lightweight C++ implementation of WATR protocol for embedded systems and OpenWRT routers.

## Features

- **Minimal dependencies**: Only standard C/C++ libraries
- **Raw socket implementation**: Direct 802.11 packet injection/capture
- **OpenWRT compatible**: Designed for resource-constrained routers
- **Monitor mode support**: Works with mon0 interface
- **IEEE 802.11 Data frames**: Reliable packet transmission
- **LLC/SNAP encapsulation**: Proper protocol identification

## Building

### Native Build
```bash
cd protoc
make clean
make
```

### Cross-Compile for OpenWRT
```bash
export CROSS_COMPILE=mipsel-openwrt-linux-
export TARGET_ARCH=mips32r2
make clean
make
```

## Usage

### Sender (tm11.local)
```bash
sudo ./send-test mon0                        # Broadcast
sudo ./send-test mon0 02:00:00:00:00:02     # Unicast
```

### Receiver (tm10.local)
```bash
sudo ./receive-test mon0
```

## Packet Structure

```
[Radiotap Header] - 8 bytes
[IEEE 802.11 Data] - 24 bytes
[LLC Header] - 3 bytes
[SNAP Header] - 5 bytes
[WATR Header] - 16 bytes
[Payload] - Variable (max 1024)
```

## WATR Protocol Header

- **Magic**: 0x57415452 ("WATR")
- **Version**: 1
- **Message Type**: User-defined
- **Sequence**: 32-bit counter
- **Length**: Payload length
- **Checksum**: 16-bit checksum

## OpenWRT Package

Create OpenWRT package:
```bash
make openwrt-package > watr-protoc.control
```

## Performance

- Minimal memory footprint (~50KB)
- Low CPU usage
- Suitable for router deployment
- No dynamic memory allocation