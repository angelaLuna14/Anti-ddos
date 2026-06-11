#ifndef PACKET_ENGINE_H
#define PACKET_ENGINE_H

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <memory>
#include <functional>
#include <mutex>

namespace antiddos {

struct PacketInfo {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t protocol;
    uint32_t packet_size;
    std::vector<uint8_t> payload;
    std::chrono::steady_clock::time_point timestamp;
    
    bool is_tcp() const { return protocol == 6; }
    bool is_udp() const { return protocol == 17; }
    bool is_icmp() const { return protocol == 1; }
};

enum class ThreatLevel {
    NONE = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

enum class TrafficType {
    NORMAL,
    VPN_OPENVPN,
    VPN_WIREGUARD,
    VPN_IPSEC,
    VPN_SSH_TUNNEL,
    VPN_SHADOWSOCKS,
    VPN_V2RAY,
    SUSPICIOUS,
    ATTACK
};

struct ConnectionStats {
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    uint32_t syn_count = 0;
    uint32_t ack_count = 0;
    uint32_t fin_count = 0;
    uint32_t rst_count = 0;
    uint32_t udp_flood_score = 0;
    uint32_t icmp_flood_score = 0;
    uint32_t http_flood_score = 0;
    uint32_t dns_amplification_score = 0;
    TrafficType detected_type = TrafficType::NORMAL;
    ThreatLevel threat_level = ThreatLevel::NONE;
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    std::vector<std::string> suspicious_signatures;
};

using AlertCallback = std::function<void(const std::string&, ThreatLevel, const ConnectionStats&)>;

class PacketEngine {
public:
    PacketEngine();
    ~PacketEngine();
    
    void start_capture(const std::string& interface);
    void stop_capture();
    void process_packet(const PacketInfo& packet);
    
    void set_alert_callback(AlertCallback callback);
    
    ConnectionStats get_connection_stats(const std::string& ip) const;
    std::unordered_map<std::string, ConnectionStats> get_all_stats() const;
    
    void set_threshold(uint32_t syn_threshold, uint32_t packet_threshold, uint32_t byte_threshold);
    
    bool is_vpn_traffic(const PacketInfo& packet, TrafficType& detected) const;
    bool is_amplification_attack(const PacketInfo& packet) const;
    
    std::vector<std::string> get_blocked_ips() const;
    void block_ip(const std::string& ip, uint32_t duration_seconds);
    void unblock_ip(const std::string& ip);
    
private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, ConnectionStats> connection_map_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> blocked_ips_;
    
    uint32_t syn_threshold_ = 100;
    uint32_t packet_threshold_ = 1000;
    uint32_t byte_threshold_ = 1048576;
    
    AlertCallback alert_callback_;
    
    void analyze_tcp_flags(const PacketInfo& packet, ConnectionStats& stats);
    void analyze_udp_patterns(const PacketInfo& packet, ConnectionStats& stats);
    void detect_ddos_patterns(const std::string& src_ip, ConnectionStats& stats);
    void check_vpn_signatures(const PacketInfo& packet, ConnectionStats& stats);
    
    void trigger_alert(const std::string& src_ip, ThreatLevel level, const std::string& message);
};

} // namespace antiddos

#endif // PACKET_ENGINE_H