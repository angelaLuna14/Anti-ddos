#ifndef VPN_DETECTOR_H
#define VPN_DETECTOR_H

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include "utils.h"

namespace antiddos {

enum class VPNType {
    NONE,
    OPENVPN,
    WIREGUARD,
    IPSEC,
    L2TP,
    PPTP,
    SSTP,
    SHADOWSOCKS,
    V2RAY,
    TROJAN
};

struct VPNDetectionResult {
    bool is_vpn;
    VPNType vpn_type;
    float confidence;
    std::vector<std::string> indicators;
    std::string explanation;
};

struct IPReputation {
    std::string ip;
    uint32_t threat_score;
    std::vector<std::string> tags;
    std::chrono::steady_clock::time_point last_updated;
    bool is_tor_exit;
    bool is_known_vpn;
    bool is_proxy;
};

class VPNDetector {
public:
    VPNDetector();
    ~VPNDetector();
    
    void load_blacklists(const std::string& directory);
    void update_ip_reputation(const std::string& ip, const IPReputation& rep);
    
    VPNDetectionResult analyze_connection(
        const std::string& src_ip,
        const std::string& dst_ip,
        uint16_t src_port,
        uint16_t dst_port,
        uint32_t protocol,
        const std::vector<uint8_t>& payload,
        uint32_t packet_size
    );
    
    bool is_known_vpn_provider(const std::string& ip) const;
    bool is_tor_exit_node(const std::string& ip) const;
    bool is_datacenter_ip(const std::string& ip) const;
    
    void add_vpn_port(uint16_t port);
    void add_suspicious_pattern(const std::vector<uint8_t>& pattern);
    
    std::vector<std::string> get_blocked_asn() const;
    void block_asn(uint32_t asn);
    
    void add_blocked_cidr(const std::string& cidr, const std::string& reason = "");
    void remove_blocked_cidr(const std::string& cidr);
    bool is_ip_in_blocked_cidr(const std::string& ip) const;
    std::vector<std::string> get_blocked_cidrs() const;
    
private:
    mutable std::mutex mutex_;
    
    std::unordered_map<std::string, IPReputation> ip_reputation_;
    std::vector<uint16_t> vpn_ports_;
    std::vector<std::vector<uint8_t>> suspicious_patterns_;
    std::vector<uint32_t> blocked_asns_;
    
    struct CIDRBlockEntry {
        utils::CIDRRange range;
        std::string reason;
    };
    std::vector<CIDRBlockEntry> blocked_cidrs_;
    
    VPNType detect_openvpn(const std::vector<uint8_t>& payload, uint16_t port) const;
    VPNType detect_wireguard(const std::vector<uint8_t>& payload, uint16_t port) const;
    VPNType detect_ipsec(const std::vector<uint8_t>& payload, uint16_t port) const;
    VPNType detect_shadowsocks(const std::vector<uint8_t>& payload, uint16_t port) const;
    
    float calculate_confidence(VPNType type, const std::vector<std::string>& indicators) const;
};

} // namespace antiddos

#endif // VPN_DETECTOR_H