# WATR Packet Reception Fix

## Issue Description
The WATR packet counter was not incrementing during packet reception, even though packets were being transmitted and received at the WiFi layer.

## Root Cause
The issue was caused by a packet structure mismatch between the sender and receiver:

### Sender Format
The sender was creating packets with:
```
Type:    2 bytes (uint16, big-endian)  = 0x5741 ('WA')
Length:  4 bytes (uint32, big-endian)
Payload: Variable length UTF-8 text
```

### Receiver Expectation
The receiver was expecting Scapy `WATRHeader` format:
```
Type:    4 bytes (XIntField)
Length:  4 bytes (XIntField)
Payload: StrField
```

This mismatch caused the `WATRHeader(raw_data)` parsing to fail, preventing the counter from incrementing.

## Solution
Modified the packet reception logic to manually parse the packet structure using Python's `struct` module:

```python
# Parse WATR packet manually
if len(raw_data) >= 6:
    import struct
    # Unpack header: type (2 bytes) + length (4 bytes)
    watr_type, watr_length = struct.unpack('>HI', raw_data[:6])
    
    # Check if it's a valid WATR packet
    if watr_type == 0x5741:  # 'WA'
        self.received_count += 1
        # Extract payload starting at byte 6
        payload_data = raw_data[6:].decode('utf-8', errors='replace')
```

## Files Modified
1. **`python/watr/packet_test_fixed.py`**
   - Updated `PacketReceiver.packet_handler()` to manually parse packets
   - Modified `PacketSender.create_watr_data_frame()` to use consistent structure

## New Debug Tools
Created additional debugging utilities:

1. **`test-watr-receive-debug.py`**
   - Shows detailed packet statistics
   - Displays SNAP protocol IDs for debugging
   - Tracks data frames, LLC frames, and WATR packets separately

2. **`test-watr-receive-fixed.py`**
   - Standalone fixed receiver implementation
   - Manual packet parsing without Scapy layers

3. **`test-watr-send-single.py`**
   - Sends a single WATR packet for testing
   - Shows packet structure and hex dump

## Testing
To verify the fix:

```bash
# Terminal 1 - Start receiver
sudo python test-watr-receive.py

# Terminal 2 - Send packets
sudo python test-watr-send.py

# Expected output on receiver:
📥 Received WATR packet #1: Hello WATR! #1
   From: 00:11:22:33:44:55 -> 66:77:88:99:AA:BB
   Type: 0x5741, Length: 15
```

## Protocol Details
The working WATR protocol uses:
- 802.11 Data frames (type=2, subtype=0)
- LLC/SNAP encapsulation
- Custom protocol ID: 0x8999
- WATR header: type (0x5741) + length + payload

This structure is compatible with both Python and C++ implementations.