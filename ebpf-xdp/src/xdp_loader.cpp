#include "xdp_loader.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <chrono>
#include <algorithm>

#ifdef __linux__
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <unistd.h>
#endif

namespace antiddos {
namespace xdp {

XDPLoader::XDPLoader() = default;

XDPLoader::~XDPLoader() {
    stop_monitoring();
    unload();
}

bool XDPLoader::load(const std::string& obj_path, const std::string& interface) {
#ifdef __linux__
    if (!is_xdp_supported()) {
        return false;
    }
    
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rl)) {
        return false;
    }
    
    struct bpf_object *obj = bpf_object__open(obj_path.c_str());
    if (libbpf_get_error(obj)) {
        return false;
    }
    
    if (bpf_object__load(obj)) {
        bpf_object__close(obj);
        return false;
    }
    
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_filter_main");
    if (!prog) {
        bpf_object__close(obj);
        return false;
    }
    
    prog_fd_ = bpf_program__fd(prog);
    
    map_fd_blacklist_ = bpf_object__find_map_fd_by_name(obj, "ip_blacklist");
    map_fd_rate_limit_ = bpf_object__find_map_fd_by_name(obj, "rate_limit_map");
    map_fd_port_filter_ = bpf_object__find_map_fd_by_name(obj, "port_filter");
    map_fd_stats_ = bpf_object__find_map_fd_by_name(obj, "stats_map");
    map_fd_config_ = bpf_object__find_map_fd_by_name(obj, "config_map");
    
    if (prog_fd_ < 0 || map_fd_blacklist_ < 0 || map_fd_config_ < 0) {
        bpf_object__close(obj);
        return false;
    }
    
    config_.interface = interface;
    loaded_ = true;
    
    update_kernel_maps();
    
    return attach(interface);
#else
    return false;
#endif
}

bool XDPLoader::unload() {
#ifdef __linux__
    if (attached_) {
        detach();
    }
    
    if (prog_fd_ >= 0) {
        close(prog_fd_);
        prog_fd_ = -1;
    }
    
    loaded_ = false;
    return true;
#else
    return false;
#endif
}

bool XDPLoader::is_loaded() const {
    return loaded_.load();
}

bool XDPLoader::attach(const std::string& interface) {
#ifdef __linux__
    if (!loaded_ || prog_fd_ < 0) {
        return false;
    }
    
    unsigned int ifindex = if_nametoindex(interface.c_str());
    if (ifindex == 0) {
        return false;
    }
    
    link_fd_ = bpf_program__attach_xdp(prog_fd_, ifindex);
    if (link_fd_ < 0) {
        return false;
    }
    
    attached_ = true;
    config_.interface = interface;
    return true;
#else
    return false;
#endif
}

bool XDPLoader::detach() {
#ifdef __linux__
    if (!attached_ || link_fd_ < 0) {
        return false;
    }
    
    bpf_link__destroy(link_fd_);
    link_fd_ = -1;
    attached_ = false;
    return true;
#else
    return false;
#endif
}

void XDPLoader::set_config(const XDPConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
    if (loaded_) {
        update_kernel_maps();
    }
}

XDPConfig XDPLoader::get_config() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

XDPStats XDPLoader::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void XDPLoader::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = XDPStats{};
}

void XDPLoader::add_blacklist_entry(uint32_t ip, uint32_t duration_sec, uint32_t reason) {
#ifdef __linux__
    if (!loaded_ || map_fd_blacklist_ < 0) return;
    
    struct {
        uint32_t ip;
        uint32_t action;
        uint64_t packets;
        uint64_t bytes;
        uint32_t timestamp;
        uint32_t flags;
    } value;
    
    value.ip = ip;
    value.action = 1;
    value.packets = 0;
    value.bytes = 0;
    value.timestamp = duration_sec;
    value.flags = reason;
    
    bpf_map_update_elem(map_fd_blacklist_, &ip, &value, BPF_ANY);
    
    std::lock_guard<std::mutex> lock(mutex_);
    BlacklistEntry entry;
    entry.ip = ip;
    entry.expire_time = duration_sec;
    entry.reason = reason;
    entry.packets_dropped = 0;
    blacklist_.push_back(entry);
#endif
}

void XDPLoader::remove_blacklist_entry(uint32_t ip) {
#ifdef __linux__
    if (!loaded_ || map_fd_blacklist_ < 0) return;
    
    bpf_map_delete_elem(map_fd_blacklist_, &ip);
    
    std::lock_guard<std::mutex> lock(mutex_);
    blacklist_.erase(
        std::remove_if(blacklist_.begin(), blacklist_.end(),
            [ip](const BlacklistEntry& e) { return e.ip == ip; }),
        blacklist_.end()
    );
#endif
}

std::vector<BlacklistEntry> XDPLoader::get_blacklist() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return blacklist_;
}

void XDPLoader::add_port_filter(uint16_t port, uint8_t protocol, uint32_t action) {
#ifdef __linux__
    if (!loaded_ || map_fd_port_filter_ < 0) return;
    
    uint32_t key = (uint32_t)port;
    struct {
        uint16_t port;
        uint16_t protocol;
        uint32_t action;
        uint64_t packets;
        uint32_t max_rate;
        uint32_t current_rate;
        uint32_t window_start;
    } value;
    
    value.port = port;
    value.protocol = protocol;
    value.action = action;
    value.packets = 0;
    value.max_rate = 0;
    value.current_rate = 0;
    value.window_start = 0;
    
    bpf_map_update_elem(map_fd_port_filter_, &key, &value, BPF_ANY);
    
    std::lock_guard<std::mutex> lock(mutex_);
    port_filters_[port] = action;
#endif
}

void XDPLoader::remove_port_filter(uint16_t port) {
#ifdef __linux__
    if (!loaded_ || map_fd_port_filter_ < 0) return;
    
    uint32_t key = (uint32_t)port;
    bpf_map_delete_elem(map_fd_port_filter_, &key);
    
    std::lock_guard<std::mutex> lock(mutex_);
    port_filters_.erase(port);
#endif
}

void XDPLoader::set_rate_limit(uint32_t ip, uint32_t pps) {
#ifdef __linux__
    if (!loaded_ || map_fd_rate_limit_ < 0) return;
    
    struct {
        uint32_t ip;
        uint32_t token_count;
        uint32_t last_refill;
        uint32_t max_tokens;
        uint32_t refill_rate;
        uint32_t action;
    } value;
    
    value.ip = ip;
    value.token_count = pps;
    value.last_refill = 0;
    value.max_tokens = pps;
    value.refill_rate = pps;
    value.action = 1;
    
    bpf_map_update_elem(map_fd_rate_limit_, &ip, &value, BPF_ANY);
#endif
}

void XDPLoader::remove_rate_limit(uint32_t ip) {
#ifdef __linux__
    if (!loaded_ || map_fd_rate_limit_ < 0) return;
    
    bpf_map_delete_elem(map_fd_rate_limit_, &ip);
#endif
}

void XDPLoader::set_callback(std::function<void(const std::string&, uint64_t)> callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = callback;
}

void XDPLoader::start_monitoring(uint32_t interval_ms) {
    if (monitoring_) return;
    
    monitoring_ = true;
    monitor_thread_ = std::thread([this, interval_ms]() {
        while (monitoring_) {
            read_kernel_stats();
            std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
        }
    });
}

void XDPLoader::stop_monitoring() {
    monitoring_ = false;
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
}

std::vector<std::string> XDPLoader::get_available_interfaces() {
    std::vector<std::string> interfaces;
    
#ifdef __linux__
    std::ifstream net_dev("/proc/net/dev");
    std::string line;
    
    std::getline(net_dev, line);
    std::getline(net_dev, line);
    
    while (std::getline(net_dev, line)) {
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string iface = line.substr(0, colon);
            iface.erase(0, iface.find_first_not_of(" \t"));
            iface.erase(iface.find_last_not_of(" \t") + 1);
            if (!iface.empty() && iface != "lo") {
                interfaces.push_back(iface);
            }
        }
    }
#else
    interfaces.push_back("eth0");
    interfaces.push_back("Ethernet");
#endif
    
    return interfaces;
}

bool XDPLoader::is_xdp_supported() {
#ifdef __linux__
    struct bpf_object *obj = bpf_object__open_file("/sys/fs/bpf", NULL);
    if (libbpf_get_error(obj)) {
        return false;
    }
    bpf_object__close(obj);
    return true;
#else
    return false;
#endif
}

void XDPLoader::update_kernel_maps() {
#ifdef __linux__
    if (map_fd_config_ < 0) return;
    
    struct xdp_config {
        uint32_t syn_threshold;
        uint32_t syn_window_ms;
        uint32_t udp_pps_threshold;
        uint32_t udp_bps_threshold;
        uint32_t amp_threshold;
        uint32_t rate_limit_pps;
        uint32_t blacklist_duration_sec;
        uint32_t enable_syn_defense;
        uint32_t enable_udp_defense;
        uint32_t enable_amp_defense;
        uint32_t enable_rate_limiting;
        uint32_t enable_blacklist;
        uint32_t default_action;
    } kernel_config;
    
    kernel_config.syn_threshold = config_.syn_threshold;
    kernel_config.syn_window_ms = config_.syn_window_ms;
    kernel_config.udp_pps_threshold = config_.udp_pps_threshold;
    kernel_config.udp_bps_threshold = config_.udp_bps_threshold;
    kernel_config.amp_threshold = config_.amp_threshold;
    kernel_config.rate_limit_pps = config_.rate_limit_pps;
    kernel_config.blacklist_duration_sec = config_.blacklist_duration_sec;
    kernel_config.enable_syn_defense = config_.enable_syn_defense ? 1 : 0;
    kernel_config.enable_udp_defense = config_.enable_udp_defense ? 1 : 0;
    kernel_config.enable_amp_defense = config_.enable_amp_defense ? 1 : 0;
    kernel_config.enable_rate_limiting = config_.enable_rate_limiting ? 1 : 0;
    kernel_config.enable_blacklist = config_.enable_blacklist ? 1 : 0;
    kernel_config.default_action = 0;
    
    __u32 key = 0;
    bpf_map_update_elem(map_fd_config_, &key, &kernel_config, BPF_ANY);
#endif
}

void XDPLoader::read_kernel_stats() {
#ifdef __linux__
    if (map_fd_stats_ < 0) return;
    
    struct kernel_stats {
        uint64_t total_packets;
        uint64_t passed_packets;
        uint64_t dropped_packets;
        uint64_t redirected_packets;
        uint64_t syn_flood_drops;
        uint64_t udp_flood_drops;
        uint64_t amplification_drops;
        uint64_t blacklist_drops;
        uint64_t rate_limit_drops;
        uint32_t active_connections;
        uint32_t blocked_ips;
        uint32_t last_update;
    } ks;
    
    __u32 key = 0;
    if (bpf_map_lookup_elem(map_fd_stats_, &key, &ks) == 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_.total_packets = ks.total_packets;
        stats_.passed_packets = ks.passed_packets;
        stats_.dropped_packets = ks.dropped_packets;
        stats_.redirected_packets = ks.redirected_packets;
        stats_.syn_flood_drops = ks.syn_flood_drops;
        stats_.udp_flood_drops = ks.udp_flood_drops;
        stats_.amplification_drops = ks.amplification_drops;
        stats_.blacklist_drops = ks.blacklist_drops;
        stats_.rate_limit_drops = ks.rate_limit_drops;
        stats_.active_connections = ks.active_connections;
        stats_.blocked_ips = ks.blocked_ips;
    }
#endif
}

} // namespace xdp
} // namespace antiddos