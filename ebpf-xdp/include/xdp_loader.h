#ifndef XDP_LOADER_H
#define XDP_LOADER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>

namespace antiddos {
namespace xdp {

struct XDPConfig {
    uint32_t syn_threshold = 100;
    uint32_t syn_window_ms = 1000;
    uint32_t udp_pps_threshold = 10000;
    uint32_t udp_bps_threshold = 100000000;
    uint32_t amp_threshold = 50;
    uint32_t rate_limit_pps = 1000;
    uint32_t blacklist_duration_sec = 300;
    bool enable_syn_defense = true;
    bool enable_udp_defense = true;
    bool enable_amp_defense = true;
    bool enable_rate_limiting = true;
    bool enable_blacklist = true;
    std::string interface = "eth0";
};

struct XDPStats {
    uint64_t total_packets = 0;
    uint64_t passed_packets = 0;
    uint64_t dropped_packets = 0;
    uint64_t redirected_packets = 0;
    uint64_t syn_flood_drops = 0;
    uint64_t udp_flood_drops = 0;
    uint64_t amplification_drops = 0;
    uint64_t blacklist_drops = 0;
    uint64_t cidr_drops = 0;
    uint64_t rate_limit_drops = 0;
    uint32_t active_connections = 0;
    uint32_t blocked_ips = 0;
    uint32_t blocked_cidrs = 0;
};

struct BlacklistEntry {
    uint32_t ip;
    uint32_t expire_time;
    uint32_t reason;
    uint64_t packets_dropped;
};

struct CIDREntry {
    uint32_t network;
    uint32_t prefix;
    uint32_t action;
    uint64_t packets;
    uint64_t bytes;
    uint32_t expire_time;
};

class XDPLoader {
public:
    XDPLoader();
    ~XDPLoader();
    
    bool load(const std::string& obj_path, const std::string& interface);
    bool unload();
    bool is_loaded() const;
    
    bool attach(const std::string& interface);
    bool detach();
    
    void set_config(const XDPConfig& config);
    XDPConfig get_config() const;
    
    XDPStats get_stats() const;
    void reset_stats();
    
    void add_blacklist_entry(uint32_t ip, uint32_t duration_sec, uint32_t reason);
    void remove_blacklist_entry(uint32_t ip);
    std::vector<BlacklistEntry> get_blacklist() const;
    
    void add_cidr_entry(uint32_t network, uint32_t prefix, uint32_t duration_sec, uint32_t action);
    void remove_cidr_entry(uint32_t network, uint32_t prefix);
    std::vector<CIDREntry> get_cidr_list() const;
    
    void add_port_filter(uint16_t port, uint8_t protocol, uint32_t action);
    void remove_port_filter(uint16_t port);
    
    void set_rate_limit(uint32_t ip, uint32_t pps);
    void remove_rate_limit(uint32_t ip);
    
    void set_callback(std::function<void(const std::string&, uint64_t)> callback);
    
    void start_monitoring(uint32_t interval_ms = 1000);
    void stop_monitoring();
    
    static std::vector<std::string> get_available_interfaces();
    static bool is_xdp_supported();
    
private:
    bool load_bpf_program(const std::string& obj_path);
    void update_kernel_maps();
    void read_kernel_stats();
    
    int prog_fd_ = -1;
    int link_fd_ = -1;
    int map_fd_blacklist_ = -1;
    int map_fd_cidr_ = -1;
    int map_fd_rate_limit_ = -1;
    int map_fd_port_filter_ = -1;
    int map_fd_stats_ = -1;
    int map_fd_config_ = -1;
    
    XDPConfig config_;
    XDPStats stats_;
    std::vector<BlacklistEntry> blacklist_;
    std::vector<CIDREntry> cidr_list_;
    std::unordered_map<uint16_t, uint32_t> port_filters_;
    
    std::atomic<bool> loaded_{false};
    std::atomic<bool> attached_{false};
    std::atomic<bool> monitoring_{false};
    
    std::thread monitor_thread_;
    std::mutex mutex_;
    
    std::function<void(const std::string&, uint64_t)> callback_;
};

} // namespace xdp
} // namespace antiddos

#endif // XDP_LOADER_H