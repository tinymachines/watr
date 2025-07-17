#include "watr_protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

int create_raw_socket(const char *interface) {
    int sockfd;
    struct sockaddr_ll sll;
    struct ifreq ifr;
    
    // Create raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        return -1;
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
    
    return sockfd;
}

int send_watr_packet(int sockfd, const uint8_t *dst_mac, const uint8_t *src_mac,
                     uint16_t msg_type, uint32_t sequence, 
                     const void *payload, size_t payload_len) {
    struct watr_packet pkt;
    size_t total_len;
    
    // Clear packet structure
    memset(&pkt, 0, sizeof(pkt));
    
    // Initialize headers
    init_radiotap_header(&pkt.radiotap);
    init_ieee80211_header(&pkt.wifi, dst_mac, src_mac);
    init_llc_snap_header(&pkt.llc, &pkt.snap);
    init_watr_header(&pkt.watr, msg_type, sequence, payload_len);
    
    // Copy payload
    if (payload && payload_len > 0) {
        if (payload_len > sizeof(pkt.payload)) {
            payload_len = sizeof(pkt.payload);
        }
        memcpy(pkt.payload, payload, payload_len);
    }
    
    // Calculate total packet length
    total_len = sizeof(pkt.radiotap) + sizeof(pkt.wifi) + 
                sizeof(pkt.llc) + sizeof(pkt.snap) + 
                sizeof(pkt.watr) + payload_len;
    
    // Calculate checksum
    pkt.watr.checksum = htons(calculate_checksum(&pkt.watr, 
                                                  sizeof(pkt.watr) + payload_len));
    
    // Send packet
    ssize_t sent = send(sockfd, &pkt, total_len, 0);
    if (sent < 0) {
        perror("send");
        return -1;
    }
    
    return sent;
}

int receive_watr_packet(int sockfd, struct watr_packet *pkt, size_t *pkt_len) {
    ssize_t received;
    
    received = recv(sockfd, pkt, sizeof(*pkt), 0);
    if (received < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("recv");
        }
        return -1;
    }
    
    *pkt_len = received;
    
    // Validate packet
    if (received < (ssize_t)(sizeof(struct radiotap_header) + 
                             sizeof(struct ieee80211_hdr) + 
                             sizeof(struct llc_header) + 
                             sizeof(struct snap_header) + 
                             sizeof(struct watr_header))) {
        return 0; // Not a WATR packet
    }
    
    // Check LLC/SNAP headers
    if (pkt->llc.dsap != 0xAA || pkt->llc.ssap != 0xAA || 
        pkt->llc.control != 0x03) {
        return 0; // Not LLC/SNAP
    }
    
    // Check protocol ID
    if (ntohs(pkt->snap.protocol_id) != WATR_PROTO_ID) {
        return 0; // Not WATR protocol
    }
    
    // Check WATR magic
    if (ntohl(pkt->watr.magic) != WATR_MAGIC) {
        return 0; // Invalid magic
    }
    
    return 1; // Valid WATR packet
}

void print_mac_address(const char *label, const uint8_t *mac) {
    printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", label,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_watr_packet(const struct watr_packet *pkt, size_t pkt_len) {
    size_t payload_len;
    
    print_mac_address("Src MAC", pkt->wifi.addr2);
    print_mac_address("Dst MAC", pkt->wifi.addr1);
    
    printf("WATR Header:\n");
    printf("  Version: %u\n", ntohs(pkt->watr.version));
    printf("  Message Type: %u\n", ntohs(pkt->watr.msg_type));
    printf("  Sequence: %u\n", ntohl(pkt->watr.sequence));
    printf("  Length: %u\n", ntohs(pkt->watr.length));
    
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
    }
}