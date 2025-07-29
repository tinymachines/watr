# Quick Fix for "Message too long" Error

## What Changed

1. **Added `chunked_message_handler.py`**: A generic handler that breaks large messages into chunks
2. **Updated `wifi_geometry_handler.py`**: Now uses chunking for large WiFi scans
3. **Updated `logged_wifi_geometry_main.py`**: Loads the chunk handler and wires everything together

## The Fix

When WiFi scan data exceeds ~1000 bytes (happens with many networks), the system now:
- Automatically splits it into smaller chunks
- Sends each chunk as a separate frame
- Reassembles on the receiving end
- Delivers the complete scan to handlers

## No Changes Needed To

- Your existing launch scripts (`watr-geometry.sh`)
- The core protocol
- Any other handlers

## Test It

The same command still works:
```bash
./watr-geometry.sh
```

But now it handles dense WiFi environments without the "Message too long" error.

## What You'll See

In the logs, you might see:
```
Using chunked transmission for large scan
```

This is normal and shows the chunking is working properly.

## Frame Size Note

802.11 frames are limited to ~1500 bytes payload (Ethernet MTU). The chunking system respects this limit while allowing arbitrarily large messages through automatic segmentation and reassembly.