#include "watr_protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

// Function declarations from watr_protocol.cpp
extern int create_raw_socket(const char *interface);
extern int send_watr_packet(int sockfd, const uint8_t *dst_mac, const uint8_t *src_mac,
                           uint16_t msg_type, uint32_t sequence, 
                           const void *payload, size_t payload_len);

static volatile int running = 1;

void signal_handler(int sig) {
    running = 0;
    printf("\nStopping sender...\n");
}

void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s <interface> [dst_mac]\n", prog);
    fprintf(stderr, "  interface: Monitor mode interface (e.g., mon0)\n");
    fprintf(stderr, "  dst_mac: Destination MAC (default: ff:ff:ff:ff:ff:ff)\n");
    fprintf(stderr, "\nExample: %s mon0 00:11:22:33:44:55\n", prog);
}

int parse_mac_address(const char *str, uint8_t *mac) {
    return sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6;
}

int main(int argc, char *argv[]) {
    int sockfd;
    const char *interface;
    uint8_t dst_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; // Broadcast
    uint8_t src_mac[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}; // Local admin
    uint32_t sequence = 0;
    int packet_count = 0;
    time_t start_time, current_time;
    
    // Check arguments
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    interface = argv[1];
    
    // Parse destination MAC if provided
    if (argc >= 3) {
        if (!parse_mac_address(argv[2], dst_mac)) {
            fprintf(stderr, "Error: Invalid MAC address format\n");
            print_usage(argv[0]);
            return 1;
        }
    }
    
    // Check if running as root
    if (geteuid() != 0) {
        fprintf(stderr, "Error: This program must be run as root\n");
        return 1;
    }
    
    // Create raw socket
    printf("Creating raw socket on interface %s...\n", interface);
    sockfd = create_raw_socket(interface);
    if (sockfd < 0) {
        fprintf(stderr, "Error: Failed to create raw socket\n");
        return 1;
    }
    
    // Set up signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("Starting WATR packet transmission...\n");
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
    printf("Press Ctrl+C to stop\n\n");
    
    start_time = time(NULL);
    
    // Main transmission loop
    while (running) {
        char payload[256];
        size_t payload_len;
        int ret;
        
        // Create test payload
        snprintf(payload, sizeof(payload), 
                 "WATR Test Packet #%u from %s", 
                 sequence, interface);
        payload_len = strlen(payload);
        
        // Send packet
        ret = send_watr_packet(sockfd, dst_mac, src_mac, 
                              1, // MSG_TYPE_TEST
                              sequence,
                              payload, payload_len);
        
        if (ret > 0) {
            packet_count++;
            current_time = time(NULL);
            
            // Print status every 10 packets
            if (packet_count % 10 == 0) {
                double elapsed = difftime(current_time, start_time);
                double rate = packet_count / elapsed;
                printf("Sent %d packets (%.1f pkt/s)\n", packet_count, rate);
            }
        } else {
            fprintf(stderr, "Error sending packet %u\n", sequence);
        }
        
        sequence++;
        
        // Sleep between packets (100ms)
        usleep(100000);
    }
    
    // Final statistics
    current_time = time(NULL);
    double elapsed = difftime(current_time, start_time);
    printf("\nTransmission complete:\n");
    printf("  Total packets sent: %d\n", packet_count);
    printf("  Total time: %.1f seconds\n", elapsed);
    printf("  Average rate: %.1f packets/second\n", packet_count / elapsed);
    
    close(sockfd);
    return 0;
}