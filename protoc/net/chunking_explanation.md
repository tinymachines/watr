# WiFi Scan Chunking Solution

## Problem
When scanning WiFi in dense areas, you might see 50+ networks. Each network has multiple fields (SSID, BSSID, signal, frequency, channel, security), resulting in large JSON payloads that exceed the 802.11 frame size limit (~1500 bytes).

## Solution
We've implemented a chunking mechanism that:

1. **Automatically detects** when WiFi scan data exceeds 1000 bytes
2. **Splits the data** into multiple chunks that fit within frame limits
3. **Sends chunks** with metadata (chunk_id, chunk_num, total_chunks)
4. **Reassembles** chunks on the receiving end
5. **Handles timeouts** for incomplete transmissions

## How It Works

### Sending Side
```python
# In WiFiGeometryHandler._broadcast_scan()
if payload_size > 1000:
    # Large scan - use chunking
    await chunk_handler.send_chunked_message('wifi_scan', payload)
else:
    # Small scan - send directly  
    node.send_message('wifi_scan', payload)
```

### Receiving Side
```python
# ChunkedMessageHandler automatically:
1. Receives 'chunk' messages
2. Groups them by chunk_id
3. Waits for all chunks (with timeout)
4. Reassembles the original message
5. Delivers to registered handlers
```

## Example Flow

**Dense WiFi Area (60 networks)**:
```
Node A scans → 60 networks found → ~5KB payload
↓
ChunkedMessageHandler splits into 5 chunks
↓
Sends: chunk 0/5, chunk 1/5, ..., chunk 4/5
↓
Node B receives all chunks
↓
Reassembles → delivers complete wifi_scan message
```

**Sparse WiFi Area (5 networks)**:
```
Node A scans → 5 networks found → ~500 bytes payload
↓
Sends directly as single 'wifi_scan' message
↓
Node B receives normally
```

## Benefits

1. **Transparent**: Handlers don't need to know about chunking
2. **Automatic**: Switches between direct/chunked based on size
3. **Reliable**: Handles missing chunks with timeouts
4. **Efficient**: Only chunks when necessary

## Configuration

- **Chunk Size**: 1000 bytes (configurable)
- **Timeout**: 60 seconds for incomplete messages
- **Delay**: 10ms between chunks to avoid congestion

This ensures WiFi geometry discovery works reliably in all environments, from rural areas with few networks to dense urban areas with hundreds of visible access points.