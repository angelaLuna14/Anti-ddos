#include "vpn_detector.h"
#include <fstream>
#include <sstream>
#include <algorithm>

namespace antiddos {

VPNDetector::VPNDetector() {
    vpn_ports_ = {
        1194, 41194,  // OpenVPN
        51820,        // WireGuard
        500, 4500,    // IPSec
        1723,         // PPTP
        1701,         // L2TP
        443,          // SSTP/Various
        8388,         // Shadowsocks
        1080, 3128,   // SOCKS proxy
    };
    
    suspicious_patterns_ = {
        {0x00, 0x0e},  // OpenVPN header
        {0x01, 0x00, 0x00, 0x00},  // WireGuard init
        {0x21, 0x20, 0x23, 0x08},  // IPSec IKE
    };
}

VPNDetector::~VPNDetector() = default;

void VPNDetector::load_blacklists(const std::string& directory) {
    std::ifstream vpn_file(directory + "/vpn_ips.txt");
    if (vpn_file.is_open()) {
        std::string line;
        while (std::getline(vpn_file, line)) {
            IPReputation rep;
            rep.ip = line;
            rep.is_known_vpn = true;
            rep.threat_score = 30;
            rep.last_updated = std::chrono::steady_clock::now();
            ip_reputation_[line] = rep;
        }
    }
    
    std::ifstream tor_file(directory + "/tor_exit_nodes.txt");
    if (tor_file.is_open()) {
        std::string line;
        while (std::getline(tor_file, line)) {
            IPReputation rep;
            rep.ip = line;
            rep.is_tor_exit = true;
            rep.threat_score = 50;
            rep.last_updated = std::chrono::steady_clock::now();
            ip_reputation_[line] = rep;
        }
    }
}

void VPNDetector::update_ip_reputation(const std::string& ip, const IPReputation& rep) {
    std::lock_guard<std::mutex> lock(mutex_);
    ip_reputation_[ip] = rep;
}

VPNDetectionResult VPNDetector::analyze_connection(
    const std::string& src_ip,
    const std::string& dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    uint32_t protocol,
    const std::vector<uint8_t>& payload,
    uint32_t packet_size
) {
    VPNDetectionResult result = {false, VPNType::NONE, 0.0f, {}, ""};
    
    if (is_ip_in_blocked_cidr(src_ip)) {
        result.is_vpn = true;
        result.vpn_type = VPNType::NONE;
        result.confidence = 1.0f;
        result.indicators.push_back("BLOCKED_CIDR");
        result.explanation = "IP is in a blocked CIDR range";
        return result;
    }
    
    auto rep_it = ip_reputation_.find(src_ip);
    if (rep_it != ip_reputation_.end()) {
        const auto& rep = rep_it->second;
        if (rep.is_known_vpn) {
            result.is_vpn = true;
            result.vpn_type = VPNType::OPENVPN;
            result.confidence = 0.9f;
            result.indicators.push_back("KNOWN_VPN_IP");
            result.explanation = "IP is in known VPN provider list";
            return result;
        }
        if (rep.is_tor_exit) {
            result.is_vpn = true;
            result.vpn_type = VPNType::NONE;
            result.confidence = 0.95f;
            result.indicators.push_back("TOR_EXIT_NODE");
            result.explanation = "IP is a known Tor exit node";
            return result;
        }
    }
    
    if (auto vpn_type = detect_openvpn(payload, dst_port); vpn_type != VPNType::NONE) {
        result.is_vpn = true;
        result.vpn_type = vpn_type;
        result.indicators.push_back("OPENVPN_SIGNATURE");
    }
    
    if (auto vpn_type = detect_wireguard(payload, dst_port); vpn_type != VPNType::NONE) {
        result.is_vpn = true;
        result.vpn_type = vpn_type;
        result.indicators.push_back("WIREGUARD_SIGNATURE");
    }
    
    if (auto vpn_type = detect_ipsec(payload, dst_port); vpn_type != VPNType::NONE) {
        result.is_vpn = true;
        result.vpn_type = vpn_type;
        result.indicators.push_back("IPSEC_SIGNATURE");
    }
    
    if (auto vpn_type = detect_shadowsocks(payload, dst_port); vpn_type != VPNType::NONE) {
        result.is_vpn = true;
        result.vpn_type = vpn_type;
        result.indicators.push_back("SHADOWSOCKS_SIGNATURE");
    }
    
    for (const auto& pattern : suspicious_patterns_) {
        if (payload.size() >= pattern.size()) {
            if (memcmp(payload.data(), pattern.data(), pattern.size()) == 0) {
                result.indicators.push_back("SUSPICIOUS_PATTERN");
                break;
            }
        }
    }
    
    result.confidence = calculate_confidence(result.vpn_type, result.indicators);
    
    if (result.confidence > 0.7f) {
        result.is_vpn = true;
    }
    
    return result;
}

VPNType VPNDetector::detect_openvpn(const std::vector<uint8_t>& payload, uint16_t port) const {
    if (port == 1194 || port == 41194) {
        if (payload.size() >= 2) {
            uint8_t opcode = (payload[0] >> 3) & 0x1F;
            if (opcode >= 1 && opcode <= 8) {
                return VPNType::OPENVPN;
            }
        }
    }
    return VPNType::NONE;
}

VPNType VPNDetector::detect_wireguard(const std::vector<uint8_t>& payload, uint16_t port) const {
    if (port == 51820 && payload.size() >= 4) {
        if (payload[0] == 0x01 || payload[0] == 0x02 || payload[0] == 0x03 || payload[0] == 0x04) {
            return VPNType::WIREGUARD;
        }
    }
    return VPNType::NONE;
}

VPNType VPNDetector::detect_ipsec(const std::vector<uint8_t>& payload, uint16_t port) const {
    if ((port == 500 || port == 4500) && payload.size() >= 8) {
        uint8_t next_payload = payload[6];
        uint8_t version = payload[0] & 0x0F;
        
        if (version == 0x02 && (next_payload == 0 || next_payload == 17 || next_payload == 1)) {
            return VPNType::IPSEC;
        }
    }
    return VPNType::NONE;
}

VPNType VPNDetector::detect_shadowsocks(const std::vector<uint8_t>& payload, uint16_t port) const {
    if (port == 8388 && payload.size() > 0) {
        uint8_t first_byte = payload[0];
        if (first_byte == 0x03) {
            return VPNType::SHADOWSOCKS;
        }
    }
    return VPNType::NONE;
}

float VPNDetector::calculate_confidence(VPNType type, const std::vector<std::string>& indicators) const {
    if (type == VPNType::NONE && indicators.empty()) return 0.0f;
    
    float confidence = 0.0f;
    
    switch (type) {
        case VPNType::OPENVPN: confidence += 0.6f; break;
        case VPNType::WIREGUARD: confidence += 0.7f; break;
        case VPNType::IPSEC: confidence += 0.65f; break;
        case VPNType::SHADOWSOCKS: confidence += 0.75f; break;
        default: break;
    }
    
    confidence += indicators.size() * 0.1f;
    
    return std::min(confidence, 1.0f);
}

bool VPNDetector::is_known_vpn_provider(const std::string& ip) const {
    auto it = ip_reputation_.find(ip);
    return it != ip_reputation_.end() && it->second.is_known_vpn;
}

bool VPNDetector::is_tor_exit_node(const std::string& ip) const {
    auto it = ip_reputation_.find(ip);
    return it != ip_reputation_.end() && it->second.is_tor_exit;
}

bool VPNDetector::is_datacenter_ip(const std::string& ip) const {
    auto it = ip_reputation_.find(ip);
    return it != ip_reputation_.end() && it->second.tags.size() > 0;
}

void VPNDetector::add_vpn_port(uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (std::find(vpn_ports_.begin(), vpn_ports_.end(), port) == vpn_ports_.end()) {
        vpn_ports_.push_back(port);
    }
}

void VPNDetector::add_suspicious_pattern(const std::vector<uint8_t>& pattern) {
    std::lock_guard<std::mutex> lock(mutex_);
    suspicious_patterns_.push_back(pattern);
}

std::vector<std::string> VPNDetector::get_blocked_asn() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (uint32_t asn : blocked_asns_) {
        result.push_back(std::to_string(asn));
    }
    return result;
}

void VPNDetector::block_asn(uint32_t asn) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (std::find(blocked_asns_.begin(), blocked_asns_.end(), asn) == blocked_asns_.end()) {
        blocked_asns_.push_back(asn);
    }
}

void VPNDetector::add_blocked_cidr(const std::string& cidr, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    CIDRBlockEntry entry;
    entry.range = utils::IPUtils::parse_cidr(cidr);
    entry.reason = reason;
    blocked_cidrs_.push_back(entry);
}

void VPNDetector::remove_blocked_cidr(const std::string& cidr) {
    std::lock_guard<std::mutex> lock(mutex_);
    utils::CIDRRange target = utils::IPUtils::parse_cidr(cidr);
    blocked_cidrs_.erase(
        std::remove_if(blocked_cidrs_.begin(), blocked_cidrs_.end(),
            [&target](const CIDRBlockEntry& e) {
                return e.range.network == target.network && e.range.prefix == target.prefix;
            }),
        blocked_cidrs_.end()
    );
}

bool VPNDetector::is_ip_in_blocked_cidr(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& entry : blocked_cidrs_) {
        if (utils::IPUtils::is_ip_in_cidr(ip, entry.range)) {
            return true;
        }
    }
    return false;
}

std::vector<std::string> VPNDetector::get_blocked_cidrs() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (const auto& entry : blocked_cidrs_) {
        result.push_back(utils::IPUtils::int_to_ip(entry.range.network) + "/" + std::to_string(entry.range.prefix));
    }
    return result;
}

} // namespace antiddos