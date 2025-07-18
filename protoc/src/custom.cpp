#include <tins/tins.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <tins/tins.h>
using namespace Tins;

using namespace Tins;

class Custom80211Handler {
private:
    std::string interface_name;
    HWAddress<6> src_addr;
    HWAddress<6> dst_addr;
    
public:
    Custom80211Handler(const std::string& iface, 
                       const std::string& src, 
                       const std::string& dst) 
        : interface_name(iface), src_addr(src), dst_addr(dst) {}
    
    /**
     * Creates a custom 802.11 data frame optimized for LLM node communication
     * Using type=2 (Data) and subtype=0 (Data) to avoid control/management frame interference
     */
    Dot11Data create_custom_frame(const std::string& payload) {
        // Create the 802.11 data frame
        Dot11Data dot11_frame;
        
        // Set frame control fields
        dot11_frame.type(Dot11::DATA);
        dot11_frame.subtype(0x00); // Data subtype
        dot11_frame.from_ds(1);    // Set from-DS flag
        dot11_frame.to_ds(0);      // Clear to-DS flag
        
        // Set addresses
        dot11_frame.addr1(dst_addr);  // Destination address
        dot11_frame.addr2(src_addr);  // Source address  
        dot11_frame.addr3(src_addr);  // BSSID (using source address)
        
        // Create LLC header
        LLC llc_header;
        llc_header.dsap(0xAA);  // Individual LLC SAP
        llc_header.ssap(0xAA);  // Individual LLC SAP

	// Set frame format type
	llc_header.type(LLC::INFORMATION);

	// Set sequence numbers
	llc_header.send_seq_number(0x03);      // Send sequence number
	llc_header.receive_seq_number(0x03);   // Receive sequence number

	// Set modifier function for unnumbered frames
	llc_header.modifier_function(LLC::UI);

	// Set poll/final bit
	llc_header.poll_final(true);

        // Create SNAP header with custom protocol ID
	SNAP snap_header;
	snap_header.org_code(0x000000);    // Organization Code
	snap_header.eth_type(0x8999);      // Custom protocol ID
        
        // Create payload
        RawPDU raw_payload(payload);
        
        // Stack the layers: Dot11Data / LLC / SNAP / RawPDU
        dot11_frame = dot11_frame / llc_header / snap_header / raw_payload;
        
        return dot11_frame;
    }
    
    /**
     * Sends custom frame on specified interface
     */
    void send_custom_frame(const std::string& payload, int count = 10) {
        try {
            // Create the packet sender
            PacketSender sender;
            
            // Create the frame
            auto frame = create_custom_frame(payload);
            
            // Add RadioTap header for injection
            RadioTap radiotap_frame = RadioTap() / frame;
            
            std::cout << "Sending " << count << " frames on interface " 
                      << interface_name << std::endl;
            
            // Send the frame multiple times
            for (int i = 0; i < count; ++i) {
                sender.send(radiotap_frame, interface_name);
                std::cout << "Frame " << (i + 1) << " sent" << std::endl;
            }
            
        } catch (const std::exception& e) {
            std::cerr << "Error sending frame: " << e.what() << std::endl;
        }
    }
    
    /**
     * Frame filter function to identify our custom frames
     */
    static bool frame_filter(const PDU& pdu) {
        try {
            // Check if it's a Dot11Data frame
            const Dot11Data* dot11 = pdu.find_pdu<Dot11Data>();
            if (!dot11) return false;
            
            // Check type and subtype
            if (dot11->type() != Dot11::DATA || dot11->subtype() != 0x00) {
                return false;
            }
            
            // Check for SNAP header with our custom protocol ID
            const SNAP* snap = pdu.find_pdu<SNAP>();
            if (!snap) return false;
            
            return snap->eth_type() == 0x8999;  // Match our custom protocol ID
            
        } catch (const std::exception&) {
            return false;
        }
    }
    
    /**
     * Callback function for processing received frames
     */
    static bool frame_handler(const PDU& pdu) {
        try {
            if (frame_filter(pdu)) {
                std::cout << "Custom frame received!" << std::endl;
                
                // Extract payload
                const RawPDU* raw = pdu.find_pdu<RawPDU>();
                if (raw) {
                    const auto& payload = raw->payload();
                    std::string data(payload.begin(), payload.end());
                    std::cout << "Payload: " << data << std::endl;
                }
                
                // Print frame details
                const Dot11Data* dot11 = pdu.find_pdu<Dot11Data>();
                if (dot11) {
                    std::cout << "From: " << dot11->addr2() << std::endl;
                    std::cout << "To: " << dot11->addr1() << std::endl;
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Error processing frame: " << e.what() << std::endl;
        }
        
        return true; // Continue sniffing
    }
    
    /**
     * Receives and processes custom frames
     */
    void receive_frames() {
        try {
            std::cout << "Starting frame capture on interface " 
                      << interface_name << std::endl;
            
            // Create sniffer configuration
            SnifferConfiguration config;
            config.set_immediate_mode(true);
            config.set_promisc_mode(true);
            
            // Create sniffer
            Sniffer sniffer(interface_name, config);
            
            // Start sniffing with our handler
            sniffer.sniff_loop(frame_handler);
            
        } catch (const std::exception& e) {
            std::cerr << "Error during frame capture: " << e.what() << std::endl;
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " [send|receive] [interface]" << std::endl;
        return 1;
    }
    
    std::string mode = argv[1];
    std::string interface = argv[2];
    
    // Example addresses (use your actual node addresses)
    std::string src = "00:11:22:33:44:55";
    std::string dst = "66:77:88:99:AA:BB";
    
    // Uncomment and modify these if you want to use different addresses
    // std::string src = "00:00:00:00:00:00";
    // std::string dst = "00:00:00:00:00:00";
    
    Custom80211Handler handler(interface, src, dst);
    
    if (mode == "send") {
        int count = 10;
        std::string data = "WATR SENDING " + std::to_string(count) + " FRAMES";
        handler.send_custom_frame(data, count);
        
    } else if (mode == "receive") {
        handler.receive_frames();
        
    } else {
        std::cout << "Invalid mode. Use 'send' or 'receive'" << std::endl;
        return 1;
    }
    
    return 0;
}
