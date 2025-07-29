#!/usr/bin/env python3
"""
Test script for chunked WiFi scan transmission
Creates artificial large WiFi scan data to test chunking
"""

import asyncio
import sys
from watr_node import WATRNode
from chunked_message_handler import ChunkedMessageHandler
from wifi_geometry_handler import WiFiNetwork, NodeScanResult
import time


def create_test_networks(count: int) -> list:
    """Create fake WiFi networks for testing"""
    networks = []
    for i in range(count):
        net = WiFiNetwork(
            ssid=f"TestNetwork_{i:03d}",
            bssid=f"aa:bb:cc:{i//255:02x}:{i%255:02x}:00",
            signal_strength=-30 - (i % 60),  # -30 to -90 dBm
            frequency=2412 + (i % 13) * 5,   # 2.4GHz channels
            channel=(i % 13) + 1,
            security="WPA2" if i % 2 else "Open",
            timestamp=time.time()
        )
        networks.append(net)
    return networks


async def test_chunking(interface: str, node_addr: str):
    """Test chunked message transmission"""
    
    print("🧪 Testing WiFi Scan Chunking...")
    
    # Create node
    node = WATRNode(interface, node_addr)
    await node.start()
    
    # Create chunk handler
    chunk_handler = ChunkedMessageHandler(node, chunk_size=1000)
    await node.load_handler("chunk_handler", chunk_handler)
    
    # Test different scan sizes
    test_cases = [
        (5, "Small scan (no chunking)"),
        (20, "Medium scan (maybe chunked)"),
        (60, "Large scan (definitely chunked)"),
        (100, "Very large scan (many chunks)")
    ]
    
    for network_count, description in test_cases:
        print(f"\n📡 Test: {description}")
        print(f"   Creating {network_count} fake networks...")
        
        # Create test networks
        networks = create_test_networks(network_count)
        
        # Create scan result
        scan_result = NodeScanResult(
            node_id=node_addr,
            timestamp=time.time(),
            networks=networks,
            location_hint="Test Location"
        )
        
        # Prepare payload (same as WiFiGeometryHandler)
        payload = {
            'timestamp': scan_result.timestamp,
            'location_hint': scan_result.location_hint,
            'networks': [net.__dict__ for net in scan_result.networks]
        }
        
        # Check payload size
        import json
        payload_size = len(json.dumps(payload).encode('utf-8'))
        
        print(f"   Payload size: {payload_size} bytes")
        
        if payload_size > 1000:
            print(f"   Will be chunked into ~{(payload_size + 999) // 1000} chunks")
            await chunk_handler.send_chunked_message('wifi_scan', payload)
            print("   ✅ Chunked transmission complete")
        else:
            print("   Will be sent as single message")
            node.send_message('wifi_scan', payload)
            print("   ✅ Direct transmission complete")
        
        await asyncio.sleep(1)
    
    print("\n✨ All tests complete!")
    
    # Show chunk handler stats
    print(f"\n📊 Chunk Handler Statistics:")
    print(f"   Pending messages: {len(chunk_handler.pending_messages)}")
    print(f"   Active timeouts: {len(chunk_handler.timeout_tasks)}")
    
    await node.stop()


async def main():
    if len(sys.argv) < 3:
        print("Usage: python test_chunking.py <interface> <node_address>")
        print("Example: python test_chunking.py wlan0 aa:bb:cc:dd:ee:ff")
        return
    
    interface = sys.argv[1]
    node_addr = sys.argv[2]
    
    await test_chunking(interface, node_addr)


if __name__ == "__main__":
    asyncio.run(main())