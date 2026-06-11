#include "packet_engine.h"
#include <algorithm>
#include <sstream>
#include <cstring>

namespace antiddos {

PacketEngine::PacketEngine() = default;
PacketEngine::~PacketEngine() = default;

void PacketEngine::start_capture(const std::string& interface) {
    std::lock_guard<std::mutex> lock(mutex_);
    connection_map_.clear();
    blocked_ips_.clear();
}

void PacketEngine::stop_capture() {
    std::lock_guard<std::mutex> lock(mutex_);
}

void PacketEngine::process_packet(const PacketInfo& packet) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (blocked_ips_.count(packet.src_ip)) {
        auto unblock_time = blocked_ips_[packet.src_ip];
        if (std::chrono::steady_clock::now() > unblock_time) {
            blocked_ips_.erase(packet.src_ip);
        } else {
            return;
        }
    }
    
    auto& stats = connection_map_[packet.src_ip];
    if (stats.total_packets == 0) {
        stats.first_seen = packet.timestamp;
    }
    stats.last_seen = packet.timestamp;
    
    stats.total_packets++;
    stats.total_bytes += packet.packet_size;
    
    TrafficType traffic_type;
    if (is_vpn_traffic(packet, traffic_type)) {
        stats.detected_type = traffic_type;
        stats.suspicious_signatures.push_back("VPN_TRAFFIC_DETECTED");
        if (stats.threat_level < ThreatLevel::MEDIUM) {
            stats.threat_level = ThreatLevel::MEDIUM;
        }
    }
    
    if (packet.is_tcp()) {
        analyze_tcp_flags(packet, stats);
    } else if (packet.is_udp()) {
        analyze_udp_patterns(packet, stats);
    }
    
    detect_ddos_patterns(packet.src_ip, stats);
}

void PacketEngine::analyze_tcp_flags(const PacketInfo& packet, ConnectionStats& stats) {
    if (packet.payload.size() < 14) return;
    
    uint8_t flags = packet.payload[13];
    
    if (flags & 0x02) stats.syn_count++;
    if (flags & 0x10) stats.ack_count++;
    if (flags & 0x01) stats.fin_count++;
    if (0x04) stats.rst_count++;
}

void PacketEngine::analyze_udp_patterns(const PacketInfo& packet, ConnectionStats& stats) {
    if (packet.dst_port == 53) {
        stats.dns_amplification_score++;
    }
    
    if (packet.payload.size() > 512) {
        stats.udp_flood_score += 2;
    } else {
        stats.udp_flood_score++;
    }
}

void PacketEngine::detect_ddos_patterns(const std::string& src_ip, ConnectionStats& stats) {
    if (stats.syn_count > syn_threshold_ && stats.ack_count < stats.syn_count / 10) {
        stats.threat_level = ThreatLevel::HIGH;
        stats.suspicious_signatures.push_back("SYN_FLOOD_DETECTED");
        trigger_alert(src_ip, ThreatLevel::HIGH, "SYN Flood Attack Detected");
        return;
    }
    
    if (stats.total_packets > packet_threshold_) {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(
            stats.last_seen - stats.first_seen
        ).count();
        
        if (duration > 0 && stats.total_packets / duration > 10000) {
            stats.threat_level = ThreatLevel::HIGH;
            stats.suspicious_signatures.push_back("VOLUMETRIC_FLOOD");
            trigger_alert(src_ip, ThreatLevel::HIGH, "Volumetric DDoS Attack Detected");
        }
    }
    
    if (stats.dns_amplification_score > 50) {
        stats.threat_level = ThreatLevel::CRITICAL;
        stats.suspicious_signatures.push_back("DNS_AMPLIFICATION");
        trigger_alert(src_ip, ThreatLevel::CRITICAL, "DNS Amplification Attack Detected");
    }
    
    if (stats.rst_count > 100 && stats.ack_count > stats.rst_count * 5) {
        stats.threat_level = ThreatLevel::MEDIUM;
        stats.suspicious_signatures.push_back("RST_FLOOD");
        trigger_alert(src_ip, ThreatLevel::MEDIUM, "RST Flood Detected");
    }
}

void PacketEngine::check_vpn_signatures(const PacketInfo& packet, ConnectionStats& stats) {
    if (packet.dst_port == 1194 || packet.dst_port == 41194) {
        stats.suspicious_signatures.push_back("OPENVPN_PORT");
    }
    
    if (packet.dst_port == 51820) {
        stats.suspicious_signatures.push_back("WIREGUARD_PORT");
    }
    
    if (packet.is_udp() && packet.dst_port == 443) {
        if (packet.payload.size() > 0) {
            uint8_t first_byte = packet.payload[0];
            if ((first_byte & 0xC0) == 0x40) {
                stats.suspicious_signatures.push_back("QUIC_PROTOCOL");
            }
        }
    }
    
    if (packet.is_tcp() && packet.dst_port == 443) {
        if (packet.payload.size() > 5) {
            if (memcmp(packet.payload.data(), "\x16\x03", 2) == 0) {
                uint8_t handshake_type = packet.payload[5];
                if (handshake_type == 0x01) {
                    stats.suspicious_signatures.push_back("TLS_CLIENT_HELLO");
                }
            }
        }
    }
}

void PacketEngine::trigger_alert(const std::string& src_ip, ThreatLevel level, const std::string& message) {
    if (alert_callback_) {
        auto& stats = connection_map_[src_ip];
        alert_callback_(src_ip, level, stats);
    }
}

bool PacketEngine::is_vpn_traffic(const PacketInfo& packet, TrafficType& detected) const {
    if (packet.dst_port == 1194 || packet.dst_port == 41194) {
        detected = TrafficType::VPN_OPENVPN;
        return true;
    }
    
    if (packet.dst_port == 51820 && packet.is_udp()) {
        detected = TrafficType::VPN_WIREGUARD;
        return true;
    }
    
    if (packet.dst_port == 500 || packet.dst_port == 4500) {
        if (packet.payload.size() >= 8) {
            uint8_t next_payload = packet.payload[6];
            if (next_payload == 0 || next_payload == 17) {
                detected = TrafficType::VPN_IPSEC;
                return true;
            }
        }
    }
    
    if (packet.is_tcp() && packet.src_port == 22) {
        detected = TrafficType::VPN_SSH_TUNNEL;
        return true;
    }
    
    return false;
}

bool PacketEngine::is_amplification_attack(const PacketInfo& packet) const {
    if (!packet.is_udp()) return false;
    
    uint16_t common_amp_ports[] = {53, 123, 161, 389, 520, 1900, 5353};
    for (uint16_t port : common_amp_ports) {
        if (packet.dst_port == port && packet.packet_size > 512) {
            return true;
        }
    }
    
    return false;
}

ConnectionStats PacketEngine::get_connection_stats(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connection_map_.find(ip);
    if (it != connection_map_.end()) {
        return it->second;
    }
    return ConnectionStats{};
}

std::unordered_map<std::string, ConnectionStats> PacketEngine::get_all_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return connection_map_;
}

void PacketEngine::set_threshold(uint32_t syn_threshold, uint32_t packet_threshold, uint32_t byte_threshold) {
    std::lock_guard<std::mutex> lock(mutex_);
    syn_threshold_ = syn_threshold;
    packet_threshold_ = packet_threshold;
    byte_threshold_ = byte_threshold;
}

std::vector<std::string> PacketEngine::get_blocked_ips() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    auto now = std::chrono::steady_clock::now();
    for (const auto& [ip, unblock_time] : blocked_ips_) {
        if (now <= unblock_time) {
            result.push_back(ip);
        }
    }
    return result;
}

void PacketEngine::block_ip(const std::string& ip, uint32_t duration_seconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    blocked_ips_[ip] = std::chrono::steady_clock::now() + std::chrono::seconds(duration_seconds);
}

void PacketEngine::unblock_ip(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    blocked_ips_.erase(ip);
}

void PacketEngine::set_alert_callback(AlertCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    alert_callback_ = callback;
}

} // namespace antiddos