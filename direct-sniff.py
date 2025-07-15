#!/usr/bin/env python3
"""Direct sniffing test"""
print("Starting...")

import subprocess
print("Setting monitor mode...")
subprocess.run("sudo ip link set wlan1 down", shell=True)
subprocess.run("sudo iw dev wlan1 set type monitor", shell=True)
subprocess.run("sudo ip link set wlan1 up", shell=True)
subprocess.run("sudo iw dev wlan1 set channel 6", shell=True)

print("Importing scapy...")
from scapy.all import *

def handler(pkt):
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
        if pkt[Dot11].addr2 == "02:00:00:00:00:01":
            print(f"WATR beacon found!")

print("Sniffing...")
try:
    sniff(iface="wlan1", prn=handler, count=100)
except Exception as e:
    print(f"Error: {e}")

print("Done")