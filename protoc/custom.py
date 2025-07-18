from scapy.all import *
from scapy.layers.dot11 import *
import os
import sys

def create_custom_frame(payload, src_addr, dst_addr):
    """
    Creates a custom 802.11 data frame optimized for LLM node communication
    Using type=2 (Data) and subtype=0 (Data) to avoid control/management frame interference
    """
    # Create the 802.11 frame
    dot11 = Dot11(
        type=2,  # Type 2 is Data
        subtype=0,  # Subtype 0 is Data
        addr1=dst_addr,  # Destination address
        addr2=src_addr,  # Source address
        addr3=src_addr,  # BSSID (using source address as we're not associated with an AP)
        FCfield='from-DS'  # Set appropriate flags
    )
    
    # Create the LLC layer
    # Using custom protocol ID to distinguish from regular traffic
    llc = LLC(
        dsap=0xAA,  # Individual LLC SAP
        ssap=0xAA,  # Individual LLC SAP
        ctrl=0x03   # Unnumbered Information
    )
    
    # Create SNAP header with custom protocol ID
    snap = SNAP(
        OUI=0x000000,  # Organization Code
        code=0x8999    # Custom protocol ID (avoid common ones like 0x0800 for IP)
    )
    
    # Combine layers with payload
    frame = RadioTap()/dot11/llc/snap/Raw(load=payload)
    return frame

def send_custom_frame(frame, iface="wlx4c0fc74a9773", count=10):
    """
    Sends custom frame on specified interface
    """
    sendp(frame, iface=iface, count=count, verbose=True)

# Example usage
if __name__ == "__main__":

    # Example addresses (use your actual node addresses)
    src = "00:11:22:33:44:55"
    dst = "66:77:88:99:AA:BB"

    #src = "00:00:00:00:00:00"
    #dst = "00:00:00:00:00:00"

    # For sniffing custom frames
    def frame_filter(pkt):
        return (
            Dot11 in pkt and
            pkt[Dot11].type == 2 and
            pkt[Dot11].subtype == 0 and
            SNAP in pkt and
            pkt[SNAP].code == 0x8999  # Match our custom protocol ID
        )

    if len(sys.argv) > 1:

        if sys.argv[1] == 'send':
            count = 100
            data = f"Meatball Data {count}"
            payload = data.encode ('utf-8')
            frame = create_custom_frame(payload, src, dst)
            send_custom_frame(frame, count=count)

        elif sys.argv[1] == 'receive':
            # Sniff for responses
            sniff(iface="wlan1", lfilter=frame_filter, prn=lambda x: x.json())
            #sniff(iface="mon0",  prn=lambda x: x.json())

    else:
        print ('Usage: python ./custom.py [send|receive]')
