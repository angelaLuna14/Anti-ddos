#include "xdp_cli.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>

namespace antiddos {
namespace xdp {

XDPCli::XDPCli() = default;
XDPCli::~XDPCli() = default;

XDPCli& XDPCli::instance() {
    static XDPCli inst;
    return inst;
}

void XDPCli::init() {
    if (!XDPLoader::is_xdp_supported()) {
        print_error("XDP/eBPF is not supported on this system");
        print_info("Requires Linux 4.18+ with eBPF support");
        return;
    }
    initialized_ = true;
}

void XDPCli::run(const std::vector<std::string>& args) {
    if (args.empty()) {
        cmd_help(args);
        return;
    }
    
    const std::string& cmd = args[0];
    std::vector<std::string> cmd_args(args.begin() + 1, args.end());
    
    if (cmd == "load" || cmd == "attach") cmd_load(cmd_args);
    else if (cmd == "unload" || cmd == "detach") cmd_unload(cmd_args);
    else if (cmd == "status") cmd_status(cmd_args);
    else if (cmd == "stats") cmd_stats(cmd_args);
    else if (cmd == "blacklist-add" || cmd == "ba") cmd_blacklist_add(cmd_args);
    else if (cmd == "blacklist-remove" || cmd == "br") cmd_blacklist_remove(cmd_args);
    else if (cmd == "blacklist-list" || cmd == "bl") cmd_blacklist_list(cmd_args);
    else if (cmd == "port-block" || cmd == "pb") cmd_port_block(cmd_args);
    else if (cmd == "port-allow" || cmd == "pa") cmd_port_allow(cmd_args);
    else if (cmd == "port-list" || cmd == "pl") cmd_port_list(cmd_args);
    else if (cmd == "rate-limit" || cmd == "rl") cmd_rate_limit(cmd_args);
    else if (cmd == "rate-remove" || cmd == "rr") cmd_rate_remove(cmd_args);
    else if (cmd == "rate-list") cmd_rate_list(cmd_args);
    else if (cmd == "config") cmd_config(cmd_args);
    else if (cmd == "monitor" || cmd == "watch") cmd_monitor(cmd_args);
    else if (cmd == "interfaces" || cmd == "if") cmd_interfaces(cmd_args);
    else if (cmd == "help" || cmd == "?") cmd_help(cmd_args);
    else print_error("Unknown command: " + cmd + ". Type 'help' for available commands.");
}

void XDPCli::cmd_load(const std::vector<std::string>& args) {
    if (!initialized_) {
        print_error("XDP not initialized. Run 'xdp-cli init' first.");
        return;
    }
    
    std::string obj_path = (args.size() > 0) ? args[0] : "/usr/lib/antiddos/xdp_filter_kern.o";
    std::string interface = (args.size() > 1) ? args[1] : "eth0";
    
    print_info("Loading XDP program on " + interface + "...");
    
    if (loader_.load(obj_path, interface)) {
        print_success("XDP filter loaded successfully on " + interface);
        loader_.start_monitoring(1000);
    } else {
        print_error("Failed to load XDP program");
    }
}

void XDPCli::cmd_unload(const std::vector<std::string>& args) {
    loader_.stop_monitoring();
    
    if (loader_.unload()) {
        print_success("XDP filter unloaded");
    } else {
        print_error("Failed to unload XDP filter");
    }
}

void XDPCli::cmd_status(const std::vector<std::string>& args) {
    print_separator();
    std::cout << "  XDP/eBPF Filter Status" << std::endl;
    print_separator();
    
    std::cout << "  Loaded:     " << (loader_.is_loaded() ? "YES" : "NO") << std::endl;
    
    if (loader_.is_loaded()) {
        auto config = loader_.get_config();
        std::cout << "  Interface:  " << config.interface << std::endl;
        std::cout << "  SYN Defense:" << (config.enable_syn_defense ? "ON" : "OFF") << std::endl;
        std::cout << "  UDP Defense:" << (config.enable_udp_defense ? "ON" : "OFF") << std::endl;
        std::cout << "  Rate Limit: " << (config.enable_rate_limiting ? "ON" : "OFF") << std::endl;
        std::cout << "  Blacklist:  " << (config.enable_blacklist ? "ON" : "OFF") << std::endl;
    }
    
    print_separator();
}

void XDPCli::cmd_stats(const std::vector<std::string>& args) {
    auto stats = loader_.get_stats();
    
    print_separator();
    std::cout << "  XDP Packet Statistics" << std::endl;
    print_separator();
    
    std::cout << "  Total Packets:       " << std::setw(15) << stats.total_packets << std::endl;
    std::cout << "  Passed:              " << std::setw(15) << stats.passed_packets << std::endl;
    std::cout << "  Dropped:             " << std::setw(15) << stats.dropped_packets << std::endl;
    std::cout << "  Redirected:          " << std::setw(15) << stats.redirected_packets << std::endl;
    std::cout << std::endl;
    std::cout << "  SYN Flood Drops:     " << std::setw(15) << stats.syn_flood_drops << std::endl;
    std::cout << "  UDP Flood Drops:     " << std::setw(15) << stats.udp_flood_drops << std::endl;
    std::cout << "  Amplification Drops: " << std::setw(15) << stats.amplification_drops << std::endl;
    std::cout << "  Blacklist Drops:     " << std::setw(15) << stats.blacklist_drops << std::endl;
    std::cout << "  Rate Limit Drops:    " << std::setw(15) << stats.rate_limit_drops << std::endl;
    
    print_separator();
}

void XDPCli::cmd_blacklist_add(const std::vector<std::string>& args) {
    if (args.empty()) {
        print_error("Usage: blacklist-add <ip> [duration_sec] [reason]");
        return;
    }
    
    uint32_t ip = inet_addr(args[0].c_str());
    uint32_t duration = (args.size() > 1) ? std::stoul(args[1]) : 300;
    uint32_t reason = (args.size() > 2) ? std::stoul(args[2]) : 0;
    
    loader_.add_blacklist_entry(ip, duration, reason);
    print_success("Added " + args[0] + " to kernel blacklist");
}

void XDPCli::cmd_blacklist_remove(const std::vector<std::string>& args) {
    if (args.empty()) {
        print_error("Usage: blacklist-remove <ip>");
        return;
    }
    
    uint32_t ip = inet_addr(args[0].c_str());
    loader_.remove_blacklist_entry(ip);
    print_success("Removed " + args[0] + " from kernel blacklist");
}

void XDPCli::cmd_blacklist_list(const std::vector<std::string>& args) {
    auto blacklist = loader_.get_blacklist();
    
    print_separator();
    std::cout << "  Kernel Blacklist" << std::endl;
    print_separator();
    
    if (blacklist.empty()) {
        std::cout << "  Empty" << std::endl;
    } else {
        for (const auto& entry : blacklist) {
            struct in_addr addr;
            addr.s_addr = entry.ip;
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
            
            std::cout << "  " << std::setw(15) << ip_str 
                      << " | Expires: " << std::setw(6) << entry.expire_time << "s"
                      << " | Dropped: " << entry.packets_dropped << std::endl;
        }
    }
    
    print_separator();
}

void XDPCli::cmd_port_block(const std::vector<std::string>& args) {
    if (args.empty()) {
        print_error("Usage: port-block <port> [protocol:tcp/udp]");
        return;
    }
    
    uint16_t port = std::stoul(args[0]);
    uint8_t protocol = (args.size() > 1 && args[1] == "udp") ? 17 : 6;
    
    loader_.add_port_filter(port, protocol, 1);
    print_success("Blocked port " + args[0] + " in kernel");
}

void XDPCli::cmd_port_allow(const std::vector<std::string>& args) {
    if (args.empty()) {
        print_error("Usage: port-allow <port>");
        return;
    }
    
    uint16_t port = std::stoul(args[0]);
    loader_.remove_port_filter(port);
    print_success("Allowed port " + args[0] + " in kernel");
}

void XDPCli::cmd_port_list(const std::vector<std::string>& args) {
    print_separator();
    std::cout << "  Kernel Port Filters" << std::endl;
    print_separator();
    std::cout << "  (Use 'config' to view port filter settings)" << std::endl;
    print_separator();
}

void XDPCli::cmd_rate_limit(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        print_error("Usage: rate-limit <ip> <pps>");
        return;
    }
    
    uint32_t ip = inet_addr(args[0].c_str());
    uint32_t pps = std::stoul(args[1]);
    
    loader_.set_rate_limit(ip, pps);
    print_success("Set kernel rate limit for " + args[0] + ": " + args[1] + " pps");
}

void XDPCli::cmd_rate_remove(const std::vector<std::string>& args) {
    if (args.empty()) {
        print_error("Usage: rate-remove <ip>");
        return;
    }
    
    uint32_t ip = inet_addr(args[0].c_str());
    loader_.remove_rate_limit(ip);
    print_success("Removed kernel rate limit for " + args[0]);
}

void XDPCli::cmd_rate_list(const std::vector<std::string>& args) {
    print_separator();
    std::cout << "  Kernel Rate Limits" << std::endl;
    print_separator();
    std::cout << "  (Use 'config' to view rate limit settings)" << std::endl;
    print_separator();
}

void XDPCli::cmd_config(const std::vector<std::string>& args) {
    auto config = loader_.get_config();
    
    print_separator();
    std::cout << "  XDP/eBPF Configuration" << std::endl;
    print_separator();
    
    std::cout << "  SYN Threshold:      " << std::setw(10) << config.syn_threshold << " packets" << std::endl;
    std::cout << "  SYN Window:         " << std::setw(10) << config.syn_window_ms << " ms" << std::endl;
    std::cout << "  UDP PPS Threshold:  " << std::setw(10) << config.udp_pps_threshold << " pps" << std::endl;
    std::cout << "  UDP BPS Threshold:  " << std::setw(10) << config.udp_bps_threshold << " bps" << std::endl;
    std::cout << "  Rate Limit PPS:     " << std::setw(10) << config.rate_limit_pps << " pps" << std::endl;
    std::cout << "  Blacklist Duration: " << std::setw(10) << config.blacklist_duration_sec << " sec" << std::endl;
    
    print_separator();
}

void XDPCli::cmd_monitor(const std::vector<std::string>& args) {
    print_info("Starting XDP monitor (Press Ctrl+C to stop)...");
    
    for (int i = 0; i < 20; i++) {
        auto stats = loader_.get_stats();
        
        std::cout << "\r  " << std::time(nullptr)
                  << " | Total: " << std::setw(12) << stats.total_packets
                  << " | Drop: " << std::setw(10) << stats.dropped_packets
                  << " | SYN: " << std::setw(8) << stats.syn_flood_drops << std::flush;
        
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    std::cout << std::endl;
}

void XDPCli::cmd_interfaces(const std::vector<std::string>& args) {
    auto interfaces = XDPLoader::get_available_interfaces();
    
    print_separator();
    std::cout << "  Available Network Interfaces" << std::endl;
    print_separator();
    
    for (const auto& iface : interfaces) {
        std::cout << "  " << iface << std::endl;
    }
    
    print_separator();
}

void XDPCli::cmd_help(const std::vector<std::string>& args) {
    print_separator();
    std::cout << "  XDP/eBPF Filter Commands:" << std::endl;
    print_separator();
    
    std::cout << "  load [obj] [iface]      Load XDP program" << std::endl;
    std::cout << "  unload                   Unload XDP program" << std::endl;
    std::cout << "  status                   Show filter status" << std::endl;
    std::cout << "  stats                    Show packet statistics" << std::endl;
    std::cout << std::endl;
    std::cout << "  blacklist-add <ip> [sec] Add IP to kernel blacklist" << std::endl;
    std::cout << "  blacklist-remove <ip>    Remove IP from blacklist" << std::endl;
    std::cout << "  blacklist-list           List blacklisted IPs" << std::endl;
    std::cout << std::endl;
    std::cout << "  port-block <port> [proto] Block port in kernel" << std::endl;
    std::cout << "  port-allow <port>        Allow port in kernel" << std::endl;
    std::cout << "  port-list                List port filters" << std::endl;
    std::cout << std::endl;
    std::cout << "  rate-limit <ip> <pps>    Set rate limit in kernel" << std::endl;
    std::cout << "  rate-remove <ip>         Remove rate limit" << std::endl;
    std::cout << "  rate-list                List rate limits" << std::endl;
    std::cout << std::endl;
    std::cout << "  config                   Show configuration" << std::endl;
    std::cout << "  monitor                  Real-time monitoring" << std::endl;
    std::cout << "  interfaces               List network interfaces" << std::endl;
    std::cout << "  help                     Show this help" << std::endl;
    
    print_separator();
}

void XDPCli::print_header() {
    std::cout << std::endl;
    std::cout << "  =============================================" << std::endl;
    std::cout << "     XDP/eBPF Kernel Filter CLI" << std::endl;
    std::cout << "  =============================================" << std::endl;
    std::cout << std::endl;
}

void XDPCli::print_separator() {
    std::cout << "  --------------------------------------------" << std::endl;
}

void XDPCli::print_error(const std::string& msg) {
    std::cerr << "  [ERROR] " << msg << std::endl;
}

void XDPCli::print_success(const std::string& msg) {
    std::cout << "  [OK] " << msg << std::endl;
}

void XDPCli::print_info(const std::string& msg) {
    std::cout << "  [INFO] " << msg << std::endl;
}

} // namespace xdp
} // namespace antiddos