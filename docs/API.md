# WATR API Documentation

## Python API

### Core Protocol Class

```python
import watr

protocol = watr.Protocol()
```

#### Methods

##### `craft_packet(data: bytes) -> bytes`
Creates a WATR protocol packet with the given data.

**Parameters:**
- `data`: Raw bytes to encapsulate in WATR packet

**Returns:**
- Complete WATR packet as bytes

**Example:**
```python
packet = protocol.craft_packet(b"Hello World!")
# Returns: b'\x00\x00WA\x00\x00\x00\x0cHello World!'
```

##### `parse_packet(packet: bytes) -> dict`
Parses a WATR protocol packet and extracts header fields and payload.

**Parameters:**
- `packet`: Complete WATR packet as bytes

**Returns:**
- Dictionary with parsed fields:
  - `type`: Protocol type identifier
  - `length`: Payload length
  - `payload`: Raw payload data

**Example:**
```python
result = protocol.parse_packet(packet)
# Returns: {'type': 0x5741, 'length': 12, 'payload': b'Hello World!'}
```

##### `set_header_field(field: str, value: int) -> None`
Sets a protocol header field value.

**Parameters:**
- `field`: Field name ('type' or 'length')
- `value`: Integer value to set

**Example:**
```python
protocol.set_header_field('type', 0x5741)
```

##### `get_header_field(field: str) -> int`
Gets a protocol header field value.

**Parameters:**
- `field`: Field name to retrieve

**Returns:**
- Integer value of the field

**Example:**
```python
ptype = protocol.get_header_field('type')
# Returns: 0x5741
```

## Scapy Layers

### WATRHeader

The main protocol header containing type and length fields.

```python
from watr.scapy_layers import WATRHeader, WATRPayload

# Create header
header = WATRHeader(type=0x5741, length=0)
```

**Fields:**
- `type` (XIntField): 4-byte protocol type identifier
- `length` (XIntField): 4-byte payload length (auto-calculated if 0)

### WATRPayload

The protocol payload container.

```python
# Create payload
payload = WATRPayload(data="Hello WATR!")

# Combine with header
packet = WATRHeader() / WATRPayload(data="Test")
```

**Fields:**
- `data` (StrField): Variable-length payload data

### Layer Binding

Layers are automatically bound, so you can stack them:

```python
# Create complete packet
watr_packet = WATRHeader(type=0x5741) / WATRPayload(data="Hello!")

# Access layers
print(watr_packet[WATRHeader].type)  # 0x5741
print(watr_packet[WATRPayload].data)  # "Hello!"
```

## Bootstrap API

### Adapter Detection

```python
from watr.bootstrap import WifiAdapter, Bootstrap

# Run bootstrap
bootstrap = Bootstrap()
bootstrap.run()

# Access detected adapters
for adapter in bootstrap.wifi_adapters:
    print(f"{adapter.interface}: {adapter.driver}")
    if adapter.supports_monitor:
        print("  Supports monitor mode!")
```

### WifiAdapter Class

**Attributes:**
- `interface`: Interface name (e.g., 'wlan0')
- `phy`: Physical interface name (e.g., 'phy0')
- `driver`: Driver name (e.g., 'rtl8xxxu')
- `supports_monitor`: Boolean indicating monitor mode support
- `is_onboard`: Boolean indicating if adapter is built-in
- `mac_address`: Hardware MAC address

## Packet Testing API

### Working Implementation (packet_test_fixed)

The fixed implementation uses 802.11 data frames with LLC/SNAP encapsulation for reliable transmission.

#### PacketSender

Sends WATR packets using data frames.

```python
from watr.packet_test_fixed import PacketSender, TestConfig

config = TestConfig(
    interface="mon0",      # Monitor interface
    channel=1,             # Channel 1 (2412 MHz)
    count=10,             # Number of packets
    interval=1.0,         # Seconds between packets
    payload="Test message",
    src_mac="00:11:22:33:44:55",
    dst_mac="66:77:88:99:AA:BB"
)

sender = PacketSender(config)
sender.send_packets()
```

**Methods:**
- `create_watr_data_frame(sequence)`: Creates 802.11 data frame with WATR payload
- `send_packets()`: Sends configured number of packets

#### PacketReceiver

Receives WATR packets using data frame filtering.

```python
from watr.packet_test_fixed import PacketReceiver, TestConfig

config = TestConfig(interface="mon0", channel=1)
receiver = PacketReceiver(config)
receiver.start_sniffing()
```

**Methods:**
- `packet_handler(packet)`: Processes received packets
- `start_sniffing()`: Begins packet capture
- `stop_sniffing()`: Stops packet capture
- `print_summary()`: Displays reception statistics

#### TestConfig

Enhanced configuration for packet testing.

**Parameters:**
- `interface`: Monitor interface (default: "mon0")
- `channel`: WiFi channel (default: 1)
- `count`: Number of packets to send
- `interval`: Seconds between packets
- `payload`: Message payload
- `src_mac`: Source MAC address
- `dst_mac`: Destination MAC address

### Monitor Interface Setup

```python
from watr.packet_test_fixed import setup_monitor_interface, check_monitor_interface

# Check if monitor interface exists
if not check_monitor_interface("mon0"):
    # Create monitor interface
    setup_monitor_interface(phy="phy0", interface="mon0")
```

### Frame Structure

The working implementation creates packets with this structure:

```python
# 802.11 Data Frame
frame = RadioTap() / \
        Dot11(type=2, subtype=0, addr1=dst, addr2=src, addr3=src) / \
        LLC(dsap=0xAA, ssap=0xAA, ctrl=0x03) / \
        SNAP(OUI=0x000000, code=0x8999) / \
        Raw(load=watr_packet_bytes)
```

## C++ API

### Protocol Class

```cpp
#include <watr/protocol.h>

watr::Protocol protocol;
```

#### Methods

##### `craft_packet`
```cpp
std::vector<uint8_t> craft_packet(const std::vector<uint8_t>& data);
```

Creates a WATR packet from raw data.

##### `parse_packet`
```cpp
std::map<std::string, uint32_t> parse_packet(const std::vector<uint8_t>& packet);
```

Parses a WATR packet and returns header fields.

##### `set_header_field`
```cpp
void set_header_field(const std::string& field, uint32_t value);
```

Sets a protocol header field.

##### `get_header_field`
```cpp
uint32_t get_header_field(const std::string& field) const;
```

Gets a protocol header field value.

## Error Handling

All API methods may raise exceptions:

- `ValueError`: Invalid parameters or data
- `RuntimeError`: System-level errors (e.g., monitor mode setup)
- `PermissionError`: Insufficient privileges (need root for packet injection)

Example:
```python
try:
    sender.send_packets()
except PermissionError:
    print("Need root privileges for packet injection")
except RuntimeError as e:
    print(f"Runtime error: {e}")
```