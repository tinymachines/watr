#ifndef WATR_PROTOCOL_H
#define WATR_PROTOCOL_H

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <endian.h>
#include <stddef.h>

// IEEE 802.11 and protocol definitions
#define ETH_ALEN 6
#define WATR_PROTO_ID 0x8999
#define WATR_MAGIC 0x57415452  // "WATR" in hex

// 802.11 frame types (matching Scapy: type=2, subtype=0)
#define IEEE80211_FTYPE_DATA 0x0008    // Type 2 in FC field
#define IEEE80211_STYPE_DATA 0x0000    // Subtype 0
#define IEEE80211_FCTL_FROMDS 0x0200   // From-DS flag

// Minimal Radiotap flags - matching Scapy's default
#define IEEE80211_RADIOTAP_PRESENT_FLAGS 0x00000000

#pragma pack(push, 1)

// Minimal Radiotap header - matching Scapy's default
struct radiotap_header {
    uint8_t version;     // Always 0
    uint8_t pad;         // Always 0
    uint16_t length;     // Header length (8 bytes)
    uint32_t present;    // Present flags (0 for minimal)
};

// IEEE 802.11 header
struct ieee80211_hdr {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t addr1[ETH_ALEN];  // Destination
    uint8_t addr2[ETH_ALEN];  // Source
    uint8_t addr3[ETH_ALEN];  // BSSID
    uint16_t seq_ctrl;
};

// LLC header
struct llc_header {
    uint8_t dsap;
    uint8_t ssap;
    uint8_t control;
};

// SNAP header
struct snap_header {
    uint8_t oui[3];
    uint16_t protocol_id;
};

// WATR protocol header
struct watr_header {
    uint32_t magic;
    uint16_t version;
    uint16_t msg_type;
    uint32_t sequence;
    uint16_t length;
    uint16_t checksum;
};

// Complete packet structure
struct watr_packet {
    struct radiotap_header radiotap;
    struct ieee80211_hdr wifi;
    struct llc_header llc;
    struct snap_header snap;
    struct watr_header watr;
    uint8_t payload[1024];  // Max payload size
} __attribute__((packed));

#pragma pack(pop)

// Utility functions
static inline void init_radiotap_header(struct radiotap_header *rt) {
    rt->version = 0;
    rt->pad = 0;
    rt->length = htole16(8);  // Minimal 8-byte header
    rt->present = htole32(0); // No optional fields
}

static inline void init_ieee80211_header(struct ieee80211_hdr *hdr, 
                                        const uint8_t *dst, 
                                        const uint8_t *src) {
    // Match Scapy: type=2, subtype=0, FCfield='from-DS'
    // Frame Control: Version(2) + Type(2) + Subtype(4) + Flags(8)
    // Type=2 (Data): 0x08, Subtype=0: 0x00, FromDS: 0x02
    uint16_t fc = IEEE80211_FTYPE_DATA | IEEE80211_STYPE_DATA | IEEE80211_FCTL_FROMDS;
    hdr->frame_control = htole16(fc);
    
    hdr->duration = 0;
    memcpy(hdr->addr1, dst, ETH_ALEN);
    memcpy(hdr->addr2, src, ETH_ALEN);
    memcpy(hdr->addr3, src, ETH_ALEN);  // BSSID = source (matching Python)
    hdr->seq_ctrl = 0;  // Let driver handle sequence numbers
}

static inline void init_llc_snap_header(struct llc_header *llc, 
                                       struct snap_header *snap) {
    llc->dsap = 0xAA;
    llc->ssap = 0xAA;
    llc->control = 0x03;
    
    memset(snap->oui, 0, 3);
    snap->protocol_id = htons(WATR_PROTO_ID);
}

static inline void init_watr_header(struct watr_header *hdr, 
                                   uint16_t msg_type, 
                                   uint32_t seq,
                                   uint16_t payload_len) {
    hdr->magic = htonl(WATR_MAGIC);
    hdr->version = htons(1);
    hdr->msg_type = htons(msg_type);
    hdr->sequence = htonl(seq);
    hdr->length = htons(payload_len);
    hdr->checksum = 0;  // Calculate after payload is added
}

static inline uint16_t calculate_checksum(const void *data, size_t len) {
    const uint16_t *ptr = (const uint16_t *)data;
    uint32_t sum = 0;
    
    // Skip checksum field itself
    size_t checksum_offset = offsetof(struct watr_header, checksum);
    size_t words_before = checksum_offset / 2;
    size_t words_after_start = (checksum_offset + 2) / 2;
    
    // Sum words before checksum
    for (size_t i = 0; i < words_before; i++) {
        sum += ntohs(ptr[i]);
    }
    
    // Sum words after checksum
    ptr = (const uint16_t *)((const uint8_t *)data + checksum_offset + 2);
    size_t remaining = len - checksum_offset - 2;
    
    while (remaining > 1) {
        sum += ntohs(*ptr++);
        remaining -= 2;
    }
    
    if (remaining == 1) {
        sum += *(const uint8_t *)ptr;
    }
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

// Function declarations
int create_raw_socket(const char *interface);
int send_watr_packet(int sockfd, const uint8_t *dst_mac, const uint8_t *src_mac,
                     uint16_t msg_type, uint32_t sequence, 
                     const void *payload, size_t payload_len);
int receive_watr_packet(int sockfd, struct watr_packet *pkt, size_t *pkt_len);
void print_mac_address(const char *label, const uint8_t *mac);
void print_watr_packet(const struct watr_packet *pkt, size_t pkt_len);
void print_hex_dump(const uint8_t *data, size_t len, const char *label);

#endif // WATR_PROTOCOL_H
