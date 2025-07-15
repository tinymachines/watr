#pragma once

#include <cstdint>
#include <vector>
#include <string>

namespace watr {

class Protocol {
public:
    Protocol();
    ~Protocol() = default;
    
    // Basic packet operations
    std::vector<uint8_t> craft_packet(const std::string& data);
    bool parse_packet(const std::vector<uint8_t>& packet);
    
    // Protocol-specific methods
    void set_header_field(const std::string& field, uint32_t value);
    uint32_t get_header_field(const std::string& field) const;
    
private:
    std::vector<uint8_t> header_;
    std::vector<uint8_t> payload_;
};

} // namespace watr