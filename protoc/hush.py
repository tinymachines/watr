from scapy.all import *

def send_80211_frame():

    # Define the source MAC address (you can change this to any valid MAC address)
    src_mac = "00:11:22:33:44:55"
    
    # Define the destination MAC address (change this to your neighbor's MAC address or a broadcast address)
    dst_mac = "FF:FF:FF:FF:FF:FF"

    non_mac = "00:00:00:00:00:00"

    header=('\x60\x98\x00\x00\x0c\x1a\x00\x20\x00\x00\x00\x00')
    data=('\x48\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64')
    iface='mon0'
    
    #frame = RadioTap()/Dot11(type=2, subtype=8, addr1=dst_mac,
    frame = RadioTap()/Dot11(type=0, subtype=4, addr1=dst_mac,
		addr2=src_mac, addr3=non_mac)/header/data

    frame.show()
    print("\nHexdump of frame:")
    hexdump(frame)

    sendp(frame, iface=iface, count=5, inter=1)
    
    # Create an 802.11 frame
    frame = RadioTap() / Dot11(type=0, subtype=4, addr1=dst_mac, addr2=src_mac, addr3="00:00:00:00:00:00")
    
    # Send the frame
    sendp(frame, iface="mon0", count=5, inter=1)  # Change "wlan0" to your actual Wi-Fi interface
    
    print("802.11 frame sent!")

send_80211_frame()


#from scapy.all import *
#
#def send_8023_frame():
#    # Define the source MAC address (you can change this to any valid MAC address)
#    src_mac = "00:11:22:33:44:55"
#    
#    # Define the destination MAC address (change this to your neighbor's MAC address or a broadcast address)
#    dst_mac = "FF:FF:FF:FF:FF:FF"
#    
#    # Create an 802.3 frame
#    frame = Ether(src=src_mac, dst=dst_mac) / IP(dst="192.168.1.1") / TCP(dport=80)
#    
#    # Send the frame
#    sendp(frame, iface="eth0", count=5, inter=1)  # Change "hci0" to your actual Bluetooth interface
#    
#    print("802.3 frame sent!")
#
#send_8023_frame()
#
#from scapy.all import *
#
#def process_80211_frame(packet):
#    if packet.haslayer(Dot11):
#        print("Received 802.11 frame:")
#        print(packet.summary())
#
#sniff(iface="wlan0", prn=process_80211_frame)

