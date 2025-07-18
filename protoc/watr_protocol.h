#ifndef WATR_PROTOCOL_H
#define WATR_PROTOCOL_H

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

// IEEE 802.11 and protocol definitions
#define ETH_ALEN 6
#define WATR_PROTO_ID 0x8999
#define WATR_MAGIC 0x57415452  // "WATR" in hex

// 802.11 frame types
#define IEEE80211_FTYPE_DATA 0x08
#define IEEE80211_STYPE_DATA 0x00
#define IEEE80211_FCTL_FROMDS 0x0200  // From-DS flag

// Radiotap header flags
#define IEEE80211_RADIOTAP_PRESENT_FLAGS 0x00000002

#pragma pack(push, 1)

// Minimal Radiotap header
struct radiotap_header {
    uint8_t version;
    uint8_t pad;
    uint16_t length;
    uint32_t present_flags;
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
};

#pragma pack(pop)

// Utility functions
static inline void init_radiotap_header(struct radiotap_header *rt) {
    rt->version = 0;
    rt->pad = 0;
    rt->length = htole16(sizeof(struct radiotap_header));
    rt->present_flags = htole32(IEEE80211_RADIOTAP_PRESENT_FLAGS);
}

static inline void init_ieee80211_header(struct ieee80211_hdr *hdr, 
                                        const uint8_t *dst, 
                                        const uint8_t *src) {
    hdr->frame_control = htole16(IEEE80211_FTYPE_DATA | IEEE80211_FCTL_FROMDS);
    hdr->duration = 0;
    memcpy(hdr->addr1, dst, ETH_ALEN);
    memcpy(hdr->addr2, src, ETH_ALEN);
    memcpy(hdr->addr3, src, ETH_ALEN);  // Use src as BSSID (matches Python)
    hdr->seq_ctrl = 0;
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
    hdr->checksum = 0;  // TODO: Calculate checksum
}

static inline uint16_t calculate_checksum(const void *data, size_t len) {
    const uint16_t *ptr = (const uint16_t *)data;
    uint32_t sum = 0;
    
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    
    if (len == 1) {
        sum += *(uint8_t *)ptr;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

#endif // WATR_PROTOCOL_H