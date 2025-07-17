#include "watr_protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>

// Function declarations from watr_protocol.cpp
extern int create_raw_socket(const char *interface);
extern int receive_watr_packet(int sockfd, struct watr_packet *pkt, size_t *pkt_len);
extern void print_mac_address(const char *label, const uint8_t *mac);
extern void print_watr_packet(const struct watr_packet *pkt, size_t pkt_len);

static volatile int running = 1;

void signal_handler(int sig) {
    running = 0;
    printf("\nStopping receiver...\n");
}

void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s <interface>\n", prog);
    fprintf(stderr, "  interface: Monitor mode interface (e.g., mon0)\n");
    fprintf(stderr, "\nExample: %s mon0\n", prog);
}

int set_socket_nonblocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) {
        perror("fcntl F_GETFL");
        return -1;
    }
    
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("fcntl F_SETFL");
        return -1;
    }
    
    return 0;
}

int main(int argc, char *argv[]) {
    int sockfd;
    const char *interface;
    struct watr_packet pkt;
    size_t pkt_len;
    int packet_count = 0;
    int watr_count = 0;
    time_t start_time, current_time, last_packet_time;
    
    // Check arguments
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    interface = argv[1];
    
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
    
    // Set socket to non-blocking mode
    if (set_socket_nonblocking(sockfd) < 0) {
        close(sockfd);
        return 1;
    }
    
    // Set up signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("Starting WATR packet reception...\n");
    printf("Listening on interface: %s\n", interface);
    printf("Press Ctrl+C to stop\n\n");
    
    start_time = time(NULL);
    last_packet_time = start_time;
    
    // Main reception loop
    while (running) {
        int ret;
        
        // Try to receive packet
        ret = receive_watr_packet(sockfd, &pkt, &pkt_len);
        
        if (ret > 0) {
            // Valid WATR packet received
            watr_count++;
            last_packet_time = time(NULL);
            
            printf("\n=== WATR Packet #%d ===\n", watr_count);
            print_watr_packet(&pkt, pkt_len);
            
            // Extract and print payload as string if it looks like text
            size_t payload_len = ntohs(pkt.watr.length);
            if (payload_len > 0 && payload_len <= sizeof(pkt.payload)) {
                // Check if payload looks like printable text
                int is_text = 1;
                for (size_t i = 0; i < payload_len; i++) {
                    if (pkt.payload[i] < 32 || pkt.payload[i] > 126) {
                        if (pkt.payload[i] != '\0' || i != payload_len - 1) {
                            is_text = 0;
                            break;
                        }
                    }
                }
                
                if (is_text) {
                    printf("  Payload (text): %.*s\n", (int)payload_len, pkt.payload);
                }
            }
            
            printf("========================\n");
            
        } else if (ret == 0) {
            // Not a WATR packet, count total packets
            packet_count++;
        }
        
        // Print statistics every second
        current_time = time(NULL);
        if (current_time > last_packet_time && (current_time - last_packet_time) % 5 == 0) {
            double elapsed = difftime(current_time, start_time);
            printf("\rTotal packets: %d, WATR packets: %d (%.1f%%), Elapsed: %.0fs",
                   packet_count, watr_count, 
                   packet_count > 0 ? (100.0 * watr_count / packet_count) : 0,
                   elapsed);
            fflush(stdout);
        }
        
        // Small sleep to prevent CPU spinning
        usleep(1000); // 1ms
    }
    
    // Final statistics
    printf("\n\nReception statistics:\n");
    current_time = time(NULL);
    double elapsed = difftime(current_time, start_time);
    printf("  Total runtime: %.1f seconds\n", elapsed);
    printf("  Total packets seen: %d\n", packet_count);
    printf("  WATR packets received: %d\n", watr_count);
    if (packet_count > 0) {
        printf("  WATR packet ratio: %.1f%%\n", 100.0 * watr_count / packet_count);
    }
    if (elapsed > 0) {
        printf("  Average WATR rate: %.1f packets/second\n", watr_count / elapsed);
    }
    
    close(sockfd);
    return 0;
}