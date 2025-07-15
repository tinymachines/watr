#!/usr/bin/env python3
"""
Debug both send and receive operations
"""
import sys
import subprocess
import time
import threading

sys.path.insert(0, '/opt/watr/python')

def run_cmd(cmd):
    """Run command and return output"""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout, result.stderr, result.returncode

def setup_monitor(interface, channel=6):
    """Setup monitor mode"""
    print(f"Setting up monitor mode on {interface}...")
    run_cmd(f"sudo ip link set {interface} down")
    run_cmd(f"sudo iw dev {interface} set type monitor")
    run_cmd(f"sudo ip link set {interface} up")
    time.sleep(2)
    run_cmd(f"sudo iw dev {interface} set channel {channel}")
    
    # Verify
    out, _, _ = run_cmd(f"iw dev {interface} info")
    print(out)

def receiver_thread():
    """Receiver thread"""
    print("\n=== RECEIVER (tm11) ===")
    setup_monitor("wlan1")
    
    # Import at top level
    import scapy.all as scapy
    from scapy.layers.dot11 import Dot11, Dot11Elt
    
    received = []
    def handler(pkt):
        # Look for any beacon
        if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
            src = pkt[Dot11].addr2
            if src == "02:00:00:00:00:01":
                received.append(pkt)
                print(f"✅ Received WATR beacon! Total: {len(received)}")
                if pkt.haslayer(Dot11Elt):
                    elt = pkt[Dot11Elt]
                    while elt:
                        if elt.ID == 0:
                            print(f"   SSID: {elt.info}")
                        elt = elt.payload if hasattr(elt, 'payload') and isinstance(elt.payload, Dot11Elt) else None
    
    print("Starting sniff...")
    try:
        # Sniff for 15 seconds
        scapy.sniff(iface="wlan1", prn=handler, timeout=15, store=False)
    except Exception as e:
        print(f"Sniff error: {e}")
    
    print(f"\nTotal received: {len(received)}")
    
    # Restore
    run_cmd("sudo ip link set wlan1 down")
    run_cmd("sudo iw dev wlan1 set type managed")
    run_cmd("sudo ip link set wlan1 up")

def sender_func():
    """Sender function"""
    print("\n=== SENDER (tm10) ===")
    setup_monitor("wlx842096fbfd0b")
    
    # Import at top level
    import scapy.all as scapy
    from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt
    
    print("\nSending packets...")
    for i in range(10):
        # Create beacon
        pkt = RadioTap() / \
              Dot11(type=0, subtype=8, 
                    addr1="ff:ff:ff:ff:ff:ff",
                    addr2="02:00:00:00:00:01", 
                    addr3="02:00:00:00:00:01") / \
              Dot11Beacon() / \
              Dot11Elt(ID=0, info=b"WATR-TEST") / \
              Dot11Elt(ID=221, info=b"WATR-DATA-" + str(i).encode())
        
        scapy.sendp(pkt, iface="wlx842096fbfd0b", verbose=False)
        print(f"📡 Sent packet {i+1}")
        time.sleep(1)
    
    print("\nDone sending")
    
    # Restore
    run_cmd("sudo ip link set wlx842096fbfd0b down")
    run_cmd("sudo iw dev wlx842096fbfd0b set type managed")
    run_cmd("sudo ip link set wlx842096fbfd0b up")

def main():
    """Main function"""
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['send', 'receive', 'both'])
    args = parser.parse_args()
    
    if args.mode == 'receive':
        receiver_thread()
    elif args.mode == 'send':
        sender_func()
    else:  # both
        # Start receiver in thread
        recv_thread = threading.Thread(target=receiver_thread)
        recv_thread.start()
        
        # Wait a bit
        time.sleep(5)
        
        # Run sender
        sender_func()
        
        # Wait for receiver
        recv_thread.join()

if __name__ == "__main__":
    main()