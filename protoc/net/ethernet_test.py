#!/usr/bin/env python3
"""
Simple test script for WATR Ethernet protocol
Tests basic connectivity without full node features
"""

import asyncio
import sys
import time

from watr_ethernet_protocol import WATREthernetProtocol, WATRMessage


async def test_receiver(interface: str):
    """Simple receiver for testing"""
    # Get MAC address
    from scapy.arch import get_if_hwaddr
    mac_addr = get_if_hwaddr(interface)
    
    print(f"Starting receiver on {interface} (MAC: {mac_addr})")
    
    protocol = WATREthernetProtocol(interface, mac_addr)
    
    # Message counter
    msg_count = 0
    
    def message_handler(message: WATRMessage):
        nonlocal msg_count
        msg_count += 1
        print(f"[{msg_count}] Received {message.message_type} from {message.src_addr}")
        print(f"    Payload: {message.payload}")
    
    protocol.set_default_handler(message_handler)
    
    await protocol.start()
    
    print("Receiver ready. Press Ctrl+C to stop.")
    
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print(f"\nReceived {msg_count} messages total")
        await protocol.stop()


async def test_sender(interface: str, dst_addr: str = "ff:ff:ff:ff:ff:ff"):
    """Simple sender for testing"""
    # Get MAC address
    from scapy.arch import get_if_hwaddr
    mac_addr = get_if_hwaddr(interface)
    
    print(f"Starting sender on {interface} (MAC: {mac_addr})")
    print(f"Sending to: {dst_addr}")
    
    protocol = WATREthernetProtocol(interface, mac_addr, dst_addr)
    
    await protocol.start()
    
    # Send test messages
    message_types = ['test', 'ping', 'hello', 'data']
    
    try:
        for i in range(10):
            msg_type = message_types[i % len(message_types)]
            
            message = WATRMessage(
                message_type=msg_type,
                payload={
                    'sequence': i,
                    'test_data': f'Test message {i}',
                    'timestamp': time.time()
                },
                timestamp=time.time(),
                src_addr=mac_addr,
                dst_addr=dst_addr
            )
            
            protocol.send_message(message)
            print(f"Sent {msg_type} message {i}")
            
            await asyncio.sleep(2)
            
    except KeyboardInterrupt:
        print("\nSender stopped")
    
    await protocol.stop()


async def test_bidirectional(interface: str):
    """Test bidirectional communication"""
    from scapy.arch import get_if_hwaddr
    mac_addr = get_if_hwaddr(interface)
    
    print(f"Starting bidirectional test on {interface} (MAC: {mac_addr})")
    
    protocol = WATREthernetProtocol(interface, mac_addr)
    
    # Track messages
    sent = 0
    received = 0
    
    def message_handler(message: WATRMessage):
        nonlocal received
        received += 1
        print(f"← Received {message.message_type} from {message.src_addr}: {message.payload.get('text', '')}")
        
        # Echo back
        if message.message_type == 'ping':
            reply = WATRMessage(
                message_type='pong',
                payload={'reply_to': message.payload.get('sequence', 0)},
                timestamp=time.time(),
                src_addr=mac_addr,
                dst_addr=message.src_addr
            )
            protocol.send_message(reply)
            print(f"→ Sent pong reply to {message.src_addr}")
    
    protocol.set_default_handler(message_handler)
    await protocol.start()
    
    # Send periodic messages
    try:
        for i in range(20):
            # Send ping
            ping = WATRMessage(
                message_type='ping',
                payload={'sequence': i, 'text': f'Ping #{i}'},
                timestamp=time.time(),
                src_addr=mac_addr,
                dst_addr="ff:ff:ff:ff:ff:ff"  # Broadcast
            )
            protocol.send_message(ping)
            sent += 1
            print(f"→ Broadcast ping {i}")
            
            await asyncio.sleep(3)
            
    except KeyboardInterrupt:
        print(f"\nStats: Sent {sent}, Received {received}")
    
    await protocol.stop()


def main():
    if len(sys.argv) < 3:
        print("WATR Ethernet Protocol Test")
        print("\nUsage:")
        print("  Receiver:      python ethernet_test.py recv <interface>")
        print("  Sender:        python ethernet_test.py send <interface> [dst_mac]")
        print("  Bidirectional: python ethernet_test.py bidi <interface>")
        print("\nExamples:")
        print("  python ethernet_test.py recv eth0")
        print("  python ethernet_test.py send eth0 aa:bb:cc:dd:ee:ff")
        print("  python ethernet_test.py bidi eth0")
        return
    
    mode = sys.argv[1]
    interface = sys.argv[2]
    
    if mode == 'recv':
        asyncio.run(test_receiver(interface))
    elif mode == 'send':
        dst = sys.argv[3] if len(sys.argv) > 3 else "ff:ff:ff:ff:ff:ff"
        asyncio.run(test_sender(interface, dst))
    elif mode == 'bidi':
        asyncio.run(test_bidirectional(interface))
    else:
        print(f"Unknown mode: {mode}")


if __name__ == "__main__":
    main()
