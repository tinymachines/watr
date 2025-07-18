#include "watr_protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
//#include <linux/if.h>
//#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <fcntl.h>

// Forward declaration
void print_hex_dump(const uint8_t *data, size_t len, const char *label);

int create_raw_socket(const char *interface) {
    int sockfd;
    struct sockaddr_ll sll;
    struct ifreq ifr;
    
    // Create raw socket for 802.11 - using ETH_P_ALL like tcpdump
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    // Set socket options for immediate transmission
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_BROADCAST");
    }
    
    // Set socket priority for better injection
    int priority = 7; // High priority
    if (setsockopt(sockfd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority)) < 0) {
        perror("setsockopt SO_PRIORITY");
    }
    
    // Get interface index
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(sockfd);
        return -1;
    }
    
    // Bind socket to interface
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    
    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sockfd);
        return -1;
    }
    
    // Verify interface is up
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCGIFFLAGS");
        close(sockfd);
        return -1;
    }
    
    if (!(ifr.ifr_flags & IFF_UP)) {
        fprintf(stderr, "Interface %s is not up\n", interface);
        close(sockfd);
        return -1;
    }
    
    printf("Socket created successfully on interface %s (index %d)\n", 
           interface, sll.sll_ifindex);
    
    return sockfd;
}

int send_watr_packet(int sockfd, const uint8_t *dst_mac, const uint8_t *src_mac,
                     uint16_t msg_type, uint32_t sequence, 
                     const void *payload, size_t payload_len) {
    struct watr_packet pkt;
    struct sockaddr_ll socket_address;
    size_t total_len;
    
    // Clear packet structure
    memset(&pkt, 0, sizeof(pkt));
    
    // Initialize headers exactly as Scapy does
    init_radiotap_header(&pkt.radiotap);
    init_ieee80211_header(&pkt.wifi, dst_mac, src_mac);
    init_llc_snap_header(&pkt.llc, &pkt.snap);
    init_watr_header(&pkt.watr, msg_type, sequence, payload_len);
    
    // Copy payload
    if (payload && payload_len > 0) {
        if (payload_len > sizeof(pkt.payload)) {
            payload_len = sizeof(pkt.payload);
            fprintf(stderr, "Warning: Payload truncated to %zu bytes\n", payload_len);
        }
        memcpy(pkt.payload, payload, payload_len);
    }
    
    // Calculate total packet length
    total_len = sizeof(pkt.radiotap) + sizeof(pkt.wifi) + 
                sizeof(pkt.llc) + sizeof(pkt.snap) + 
                sizeof(pkt.watr) + payload_len;
    
    // Calculate and set checksum
    uint16_t checksum = calculate_checksum(&pkt.watr, sizeof(pkt.watr) + payload_len);
    pkt.watr.checksum = htons(checksum);
    
    // Setup socket address for raw injection
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ALL);
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, dst_mac, ETH_ALEN);
    
    // Send packet
    ssize_t sent = sendto(sockfd, &pkt, total_len, 0,
                         (struct sockaddr *)&socket_address, sizeof(socket_address));
    
    if (sent < 0) {
        perror("sendto");
        return -1;
    }
    
    if (sent != (ssize_t)total_len) {
        fprintf(stderr, "Warning: Sent %zd bytes, expected %zu\n", sent, total_len);
    }
    
    return sent;
}

int receive_watr_packet(int sockfd, struct watr_packet *pkt, size_t *pkt_len) {
    ssize_t received;
    struct sockaddr_ll from;
    socklen_t fromlen = sizeof(from);
    uint8_t buffer[4096];  // Larger buffer for variable radiotap
    
    // Receive into larger buffer first
    received = recvfrom(sockfd, buffer, sizeof(buffer), 0, 
                       (struct sockaddr *)&from, &fromlen);
    
    if (received < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("recvfrom");
        }
        return -1;
    }
    
    // Skip packets that are outgoing (our own transmissions)
    if (from.sll_pkttype == PACKET_OUTGOING) {
        return 0;
    }
    
    // Minimum size check for radiotap header
    if (received < (ssize_t)sizeof(struct radiotap_header)) {
        return 0;
    }
    
    // Parse radiotap header
    struct radiotap_header *rt = (struct radiotap_header *)buffer;
    if (rt->version != 0) {
        return 0; // Invalid radiotap version
    }
    
    uint16_t rt_len = le16toh(rt->length);
    if (rt_len < sizeof(struct radiotap_header) || rt_len > received) {
        return 0; // Invalid radiotap length
    }
    
    // Calculate offsets based on actual radiotap length
    size_t offset = rt_len;
    
    // Check if we have enough data for 802.11 header
    if (received < (ssize_t)(offset + sizeof(struct ieee80211_hdr))) {
        return 0;
    }
    
    struct ieee80211_hdr *wifi = (struct ieee80211_hdr *)(buffer + offset);
    offset += sizeof(struct ieee80211_hdr);
    
    // Check 802.11 frame type (Data, subtype 0)
    uint16_t fc = le16toh(wifi->frame_control);
    if ((fc & 0x0C) != 0x08 || (fc & 0xF0) != 0x00) {
        return 0; // Not the right frame type/subtype
    }
    
    // Check for LLC/SNAP headers
    if (received < (ssize_t)(offset + sizeof(struct llc_header) + sizeof(struct snap_header))) {
        return 0;
    }
    
    struct llc_header *llc = (struct llc_header *)(buffer + offset);
    offset += sizeof(struct llc_header);
    
    if (llc->dsap != 0xAA || llc->ssap != 0xAA || llc->control != 0x03) {
        return 0; // Not LLC/SNAP
    }
    
    struct snap_header *snap = (struct snap_header *)(buffer + offset);
    offset += sizeof(struct snap_header);
    
    // Check SNAP OUI and protocol
    if (snap->oui[0] != 0 || snap->oui[1] != 0 || snap->oui[2] != 0) {
        return 0; // Wrong OUI
    }
    
    if (ntohs(snap->protocol_id) != WATR_PROTO_ID) {
        return 0; // Not WATR protocol
    }
    
    // Check for WATR header
    if (received < (ssize_t)(offset + sizeof(struct watr_header))) {
        return 0;
    }
    
    struct watr_header *watr = (struct watr_header *)(buffer + offset);
    offset += sizeof(struct watr_header);
    
    // Check WATR magic
    if (ntohl(watr->magic) != WATR_MAGIC) {
        return 0; // Invalid magic
    }
    
    // Get payload length
    uint16_t payload_len = ntohs(watr->length);
    if (received < (ssize_t)(offset + payload_len)) {
        return 0; // Truncated payload
    }
    
    // Now copy the packet to our structure, adjusting for radiotap length
    memset(pkt, 0, sizeof(*pkt));
    
    // Copy minimal radiotap header
    memcpy(&pkt->radiotap, rt, sizeof(pkt->radiotap));
    pkt->radiotap.length = htole16(sizeof(pkt->radiotap)); // Normalize to our size
    
    // Copy rest of packet
    memcpy(&pkt->wifi, wifi, sizeof(pkt->wifi));
    memcpy(&pkt->llc, llc, sizeof(pkt->llc));
    memcpy(&pkt->snap, snap, sizeof(pkt->snap));
    memcpy(&pkt->watr, watr, sizeof(pkt->watr));
    
    // Copy payload
    if (payload_len > 0 && payload_len <= sizeof(pkt->payload)) {
        memcpy(pkt->payload, buffer + offset, payload_len);
    }
    
    *pkt_len = sizeof(pkt->radiotap) + sizeof(pkt->wifi) + 
               sizeof(pkt->llc) + sizeof(pkt->snap) + 
               sizeof(pkt->watr) + payload_len;
    
    // Verify checksum
    uint16_t received_checksum = ntohs(pkt->watr.checksum);
    pkt->watr.checksum = 0; // Clear for calculation
    
    uint16_t calculated_checksum = calculate_checksum(&pkt->watr, 
                                                      sizeof(pkt->watr) + payload_len);
    
    if (received_checksum != calculated_checksum) {
        fprintf(stderr, "Checksum mismatch: received 0x%04x, calculated 0x%04x\n",
                received_checksum, calculated_checksum);
        // Still accept packet for now during debugging
    }
    
    pkt->watr.checksum = htons(received_checksum); // Restore
    
    return 1; // Valid WATR packet
}

void print_mac_address(const char *label, const uint8_t *mac) {
    printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", label,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_hex_dump(const uint8_t *data, size_t len, const char *label) {
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) {
            printf("  %04zx: ", i);
        }
        printf("%02x ", data[i]);
        if (i % 16 == 15 || i == len - 1) {
            // Print ASCII representation
            int spaces = (16 - (i % 16)) * 3 - 1;
            if (i % 16 != 15) spaces += 16 - (i % 16);
            printf("%*s", spaces, "");
            printf(" |");
            size_t start = i - (i % 16);
            for (size_t j = start; j <= i; j++) {
                uint8_t c = data[j];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            }
            printf("|\n");
        }
    }
}

void print_watr_packet(const struct watr_packet *pkt, size_t pkt_len) {
    size_t payload_len;
    
    // Print 802.11 addresses
    print_mac_address("Src MAC", pkt->wifi.addr2);
    print_mac_address("Dst MAC", pkt->wifi.addr1);
    print_mac_address("BSSID", pkt->wifi.addr3);
    
    // Print frame control info
    uint16_t fc = le16toh(pkt->wifi.frame_control);
    printf("Frame Control: 0x%04x (Type: %d, Subtype: %d)\n", 
           fc, (fc >> 2) & 0x03, (fc >> 4) & 0x0F);
    
    // Print WATR header
    printf("WATR Header:\n");
    printf("  Magic: 0x%08x\n", ntohl(pkt->watr.magic));
    printf("  Version: %u\n", ntohs(pkt->watr.version));
    printf("  Message Type: %u\n", ntohs(pkt->watr.msg_type));
    printf("  Sequence: %u\n", ntohl(pkt->watr.sequence));
    printf("  Length: %u\n", ntohs(pkt->watr.length));
    printf("  Checksum: 0x%04x\n", ntohs(pkt->watr.checksum));
    
    // Print payload
    payload_len = ntohs(pkt->watr.length);
    if (payload_len > 0 && payload_len <= sizeof(pkt->payload)) {
        printf("  Payload: ");
        for (size_t i = 0; i < payload_len && i < 32; i++) {
            printf("%02x ", pkt->payload[i]);
        }
        if (payload_len > 32) {
            printf("...");
        }
        printf("\n");
        
        // If payload looks like text, print it
        int is_text = 1;
        for (size_t i = 0; i < payload_len; i++) {
            if (pkt->payload[i] < 32 || pkt->payload[i] > 126) {
                if (pkt->payload[i] != '\0' || i != payload_len - 1) {
                    is_text = 0;
                    break;
                }
            }
        }
        
        if (is_text) {
            printf("  Payload (text): %.*s\n", (int)payload_len, pkt->payload);
        }
    }
    
    // Debug: print raw hex of entire packet
    if (getenv("WATR_DEBUG")) {
        print_hex_dump((const uint8_t *)pkt, pkt_len, "Raw packet");
    }
}
