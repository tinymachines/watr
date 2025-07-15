#include "watr/protocol.h"
#include <stdexcept>

namespace watr {

Protocol::Protocol() {
    // Initialize with basic header structure
    header_.resize(8); // 8-byte header for example
}

std::vector<uint8_t> Protocol::craft_packet(const std::string& data) {
    payload_ = std::vector<uint8_t>(data.begin(), data.end());
    
    std::vector<uint8_t> packet;
    packet.reserve(header_.size() + payload_.size());
    
    // Add header
    packet.insert(packet.end(), header_.begin(), header_.end());
    
    // Add payload
    packet.insert(packet.end(), payload_.begin(), payload_.end());
    
    return packet;
}

bool Protocol::parse_packet(const std::vector<uint8_t>& packet) {
    if (packet.size() < header_.size()) {
        return false;
    }
    
    // Extract header
    header_ = std::vector<uint8_t>(packet.begin(), packet.begin() + header_.size());
    
    // Extract payload
    if (packet.size() > header_.size()) {
        payload_ = std::vector<uint8_t>(packet.begin() + header_.size(), packet.end());
    } else {
        payload_.clear();
    }
    
    return true;
}

void Protocol::set_header_field(const std::string& field, uint32_t value) {
    // Simple implementation - would need proper field mapping
    if (field == "type" && header_.size() >= 4) {
        header_[0] = static_cast<uint8_t>(value & 0xFF);
        header_[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
        header_[2] = static_cast<uint8_t>((value >> 16) & 0xFF);
        header_[3] = static_cast<uint8_t>((value >> 24) & 0xFF);
    }
}

uint32_t Protocol::get_header_field(const std::string& field) const {
    // Simple implementation - would need proper field mapping
    if (field == "type" && header_.size() >= 4) {
        return static_cast<uint32_t>(header_[0]) |
               (static_cast<uint32_t>(header_[1]) << 8) |
               (static_cast<uint32_t>(header_[2]) << 16) |
               (static_cast<uint32_t>(header_[3]) << 24);
    }
    return 0;
}

} // namespace watr