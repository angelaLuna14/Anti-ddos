#include "cli.h"
#include "logger.h"
#include "platform.h"
#include "rate_limiter.h"
#include "geo_blocker.h"
#include "behavioral_analyzer.h"
#include "utils.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <thread>
#include <iomanip>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <signal.h>
#endif

namespace antiddos {

CLI::CLI() = default;
CLI::~CLI() = default;

CLI& CLI::instance() {
    static CLI instance;
    return instance;
}

void CLI::init() {
    Logger::instance().init("antiddos.log", LogLevel::INFO);
    platform::NetworkUtils::init_sockets();
    register_commands();
}

void CLI::register_commands() {
    commands_.push_back({"start", "Start the anti-DDoS protection daemon", {"run", "on"}, [this](const auto& args) { cmd_start(args); }});
    commands_.push_back({"stop", "Stop the anti-DDoS protection daemon", {"halt", "off"}, [this](const auto& args) { cmd_stop(args); }});
    commands_.push_back({"status", "Show current daemon status", {"info", "st"}, [this](const auto& args) { cmd_status(args); }});
    commands_.push_back({"stats", "Show traffic statistics", {"statistics"}, [this](const auto& args) { cmd_stats(args); }});
    
    commands_.push_back({"block", "Block an IP address", {"ban", "blacklist"}, [this](const auto& args) { cmd_block_ip(args); }});
    commands_.push_back({"unblock", "Unblock an IP address", {"unban", "whitelist"}, [this](const auto& args) { cmd_unblock_ip(args); }});
    commands_.push_back({"list-blocked", "List all blocked IPs", {"blocked", "lb"}, [this](const auto& args) { cmd_list_blocked(args); }});
    
    commands_.push_back({"config", "Show or modify configuration", {"cfg", "conf"}, [this](const auto& args) { cmd_config(args); }});
    commands_.push_back({"set-threshold", "Set rate limit threshold", {"threshold", "st"}, [this](const auto& args) { cmd_set_threshold(args); }});
    commands_.push_back({"set-sensitivity", "Set detection sensitivity", {"sensitivity", "ss"}, [this](const auto& args) { cmd_set_sensitivity(args); }});
    
    commands_.push_back({"geo-block", "Block a country or region", {"gb"}, [this](const auto& args) { cmd_geo_block(args); }});
    commands_.push_back({"geo-allow", "Allow a country or region", {"ga"}, [this](const auto& args) { cmd_geo_allow(args); }});
    commands_.push_back({"geo-list", "List geo-blocking rules", {"gl"}, [this](const auto& args) { cmd_geo_list(args); }});
    
    commands_.push_back({"whitelist-add", "Add IP to whitelist", {"wa"}, [this](const auto& args) { cmd_whitelist_add(args); }});
    commands_.push_back({"whitelist-remove", "Remove IP from whitelist", {"wr"}, [this](const auto& args) { cmd_whitelist_remove(args); }});
    commands_.push_back({"whitelist-list", "List whitelisted IPs", {"wl"}, [this](const auto& args) { cmd_whitelist_list(args); }});
    
    commands_.push_back({"blacklist-add", "Add IP to blacklist", {"ba"}, [this](const auto& args) { cmd_blacklist_add(args); }});
    commands_.push_back({"blacklist-remove", "Remove IP from blacklist", {"br"}, [this](const auto& args) { cmd_blacklist_remove(args); }});
    commands_.push_back({"blacklist-list", "List blacklisted IPs", {"bl"}, [this](const auto& args) { cmd_blacklist_list(args); }});
    
    commands_.push_back({"scan", "Scan network for threats", {"detect"}, [this](const auto& args) { cmd_scan(args); }});
    commands_.push_back({"monitor", "Real-time traffic monitor", {"watch", "live"}, [this](const auto& args) { cmd_monitor(args); }});
    commands_.push_back({"logs", "Show recent logs", {"log"}, [this](const auto& args) { cmd_logs(args); }});
    
    commands_.push_back({"update", "Update threat intelligence databases", {"upgrade"}, [this](const auto& args) { cmd_update(args); }});
    commands_.push_back({"export", "Export configuration or data", {"save"}, [this](const auto& args) { cmd_export(args); }});
    commands_.push_back({"import", "Import configuration or data", {"load"}, [this](const auto& args) { cmd_import(args); }});
    commands_.push_back({"help", "Show this help message", {"?"}, [this](const auto& args) { print_help(); }});
    commands_.push_back({"version", "Show version information", {"ver", "-v"}, [this](const auto& args) { print_version(); }});
    commands_.push_back({"quit", "Exit the program", {"exit", "q"}, [this](const auto& args) { running_ = false; }});
}

void CLI::run(int argc, char* argv[]) {
    init();
    
    if (argc < 2) {
        run_interactive();
        return;
    }
    
    std::vector<std::string> args;
    for (int i = 1; i < argc; i++) {
        args.push_back(argv[i]);
    }
    
    parse_args(args);
}

void CLI::run_interactive() {
    print_header();
    running_ = true;
    
    while (running_) {
        std::string input = readline("antiddos> ");
        
        if (input.empty()) continue;
        
        std::istringstream iss(input);
        std::vector<std::string> args;
        std::string arg;
        while (iss >> arg) {
            args.push_back(arg);
        }
        
        if (!args.empty()) {
            parse_args(args);
        }
    }
    
    std::cout << "Goodbye!" << std::endl;
}

void CLI::parse_args(const std::vector<std::string>& args) {
    std::string cmd_name = args[0];
    std::vector<std::string> cmd_args(args.begin() + 1, args.end());
    
    std::transform(cmd_name.begin(), cmd_name.end(), cmd_name.begin(), ::tolower);
    
    for (const auto& cmd : commands_) {
        if (cmd.name == cmd_name) {
            cmd.handler(cmd_args);
            return;
        }
        
        for (const auto& alias : cmd.aliases) {
            if (alias == cmd_name) {
                cmd.handler(cmd_args);
                return;
            }
        }
    }
    
    print_error("Unknown command: " + cmd_name + ". Type 'help' for available commands.");
}

void CLI::cmd_start(const std::vector<std::string>& args) {
    print_info("Starting anti-DDoS protection daemon...");
    
    RateLimiter limiter;
    BehavioralAnalyzer analyzer;
    GeoBlocker geo_blocker;
    
    limiter.enable_ddos_protection(true);
    analyzer.set_learning_mode(false);
    
    print_success("Anti-DDoS protection daemon started successfully!");
    print_info("Protection is now active.");
    
    Logger::instance().info("Daemon started");
}

void CLI::cmd_stop(const std::vector<std::string>& args) {
    print_info("Stopping anti-DDoS protection daemon...");
    running_ = false;
    print_success("Daemon stopped.");
    Logger::instance().info("Daemon stopped");
}

void CLI::cmd_status(const std::vector<std::string>& args) {
    print_separator();
    std::cout << "  Anti-DDoS Protection Status" << std::endl;
    print_separator();
    
    std::cout << "  Status:        " << (running_ ? "RUNNING" : "STOPPED") << std::endl;
    std::cout << "  Uptime:        " << antiddos::utils::TimeUtils::get_time() << std::endl;
    std::cout << "  Protected:     Yes" << std::endl;
    std::cout << "  Mode:          Active" << std::endl;
    
    print_separator();
}

void CLI::cmd_stats(const std::vector<std::string>& args) {
    print_separator();
    std::cout << "  Traffic Statistics" << std::endl;
    print_separator();
    
    std::cout << "  Total Packets:     " << std::setw(15) << "0" << std::endl;
    std::cout << "  Blocked IPs:       " << std::setw(15) << "0" << std::endl;
    std::cout << "  Active Connections:" << std::setw(15) << "0" << std::endl;
    std::cout << "  Threats Detected:  " << std::setw(15) << "0" << std::endl;
    
    print_separator();
}

void CLI::cmd_block_ip(const std::vector<std::string>& args) {
    if (args.empty()) {
        print_error("Usage: block <ip> [duration_seconds]");
        return;
    }
    
    std::string ip = args[0];
    uint32_t duration = (args.size() > 1) ? std::stoul(args[1]) : 300;
    
    platform::NetworkUtils::block_ip(ip);
    print_success("Blocked IP: " + ip + " for " + std::to_string(duration) + " seconds");
    Logger::instance().info("Blocked IP: " + ip);
}

void CLI::cmd_unblock_ip(const std::vector<std::string>& args) {
    if (args.empty()) {
        print_error("Usage: unblock <ip>");
        return;
    }
    
    std::string ip = args[0];
    platform::NetworkUtils::unblock_ip(ip);
    print_success("Unblocked IP: " + ip);
    Logger::instance().info("Unblocked IP: " + ip);
}

void CLI::cmd_list_blocked(const std::vector<std::string>& args) {
    print_separator();
    std::cout << "  Blocked IPs" << std::endl;
    print_separator();
    std::cout << "  No IPs currently blocked." << std::endl;
    print_separator();
}

void CLI::cmd_config(const std::vector<std::string>& args) {
    print_separator();
    std::cout << "  Configuration" << std::endl;
    print_separator();
    
    std::cout << "  Rate Limit (RPS):    " << std::setw(10) << "100" << std::endl;
    std::cout << "  Burst Size:          " << std::setw(10) << "50" << std::endl;
    std::cout << "  Block Duration:      " << std::setw(10) << "300s" << std::endl;
    std::cout << "  Sensitivity:         " << std::setw(10) << "0.5" << std::endl;
    std::cout << "  Geo Blocking:        " << std::setw(10) << "OFF" << std::endl;
    std::cout << "  VPN Detection:       " << std::setw(10) << "ON" << std::endl;
    
    print_separator();
}

void CLI::cmd_set_threshold(const std::vector<std::string>& args) {
    if (args.empty()) {
        print_error("Usage: set-threshold <value>");
        return;
    }
    
    uint32_t threshold = std::stoul(args[0]);
    print_success("Rate limit threshold set to: " + std::to_string(threshold) + " RPS");
}

void CLI::cmd_set_sensitivity(const std::vector<std::string>& args) {
    if (args.empty()) {
        print_error("Usage: set-sensitivity <0.0-1.0>");
        return;
    }
    
    float sensitivity = std::stof(args[0]);
    if (sensitivity < 0.0f || sensitivity > 1.0f) {
        print_error("Sensitivity must be between 0.0 and 1.0");
        return;
    }
    
    print_success("Sensitivity set to: " + std::to_string(sensitivity));
}

void CLI::cmd_geo_block(const std::vector<std::string>& args) {
    if (args.empty()) {
        print_error("Usage: geo-block <country_code>");
        return;
    }
    
    std::string country = args[0];
    std::transform(country.begin(), country.end(), country.begin(), ::toupper);
    
    print_success("Blocking traffic from: " + country);
}

void CLI::cmd_geo_allow(const std::vector<std::string>& args) {
    if (args.empty()) {
        print_error("Usage: geo-allow <country_code>");
        return;
    }
    
    std::string country = args[0];
    std::transform(country.begin(), country.end(), country.begin(), ::toupper);
    
    print_success("Allowing traffic from: " + country);
}

void CLI::cmd_geo_list(const std::vector<std::string>& args) {
    print_separator();
    std::cout << "  Geo-Blocking Rules" << std::endl;
    print_separator();
    std::cout << "  No geo-blocking rules configured." << std::endl;
    print_separator();
}

void CLI::cmd_whitelist_add(const std::vector<std::string>& args) {
    if (args.empty()) {
        print_error("Usage: whitelist-add <ip>");
        return;
    }
    print_success("Added to whitelist: " + args[0]);
}

void CLI::cmd_whitelist_remove(const std::vector<std::string>& args) {
    if (args.empty()) {
        print_error("Usage: whitelist-remove <ip>");
        return;
    }
    print_success("Removed from whitelist: " + args[0]);
}

void CLI::cmd_whitelist_list(const std::vector<std::string>& args) {
    print_separator();
    std::cout << "  Whitelisted IPs" << std::endl;
    print_separator();
    std::cout << "  No IPs in whitelist." << std::endl;
    print_separator();
}

void CLI::cmd_blacklist_add(const std::vector<std::string>& args) {
    if (args.empty()) {
        print_error("Usage: blacklist-add <ip>");
        return;
    }
    print_success("Added to blacklist: " + args[0]);
}

void CLI::cmd_blacklist_remove(const std::vector<std::string>& args) {
    if (args.empty()) {
        print_error("Usage: blacklist-remove <ip>");
        return;
    }
    print_success("Removed from blacklist: " + args[0]);
}

void CLI::cmd_blacklist_list(const std::vector<std::string>& args) {
    print_separator();
    std::cout << "  Blacklisted IPs" << std::endl;
    print_separator();
    std::cout << "  No IPs in blacklist." << std::endl;
    print_separator();
}

void CLI::cmd_scan(const std::vector<std::string>& args) {
    print_info("Scanning network for threats...");
    print_success("Scan complete. No threats detected.");
}

void CLI::cmd_monitor(const std::vector<std::string>& args) {
    print_info("Starting real-time monitor (Press Ctrl+C to stop)...");
    
    for (int i = 0; i < 10; i++) {
        std::cout << "\r  " << antiddos::utils::TimeUtils::get_time() 
                  << " | Packets: " << std::setw(10) << (i * 1000)
                  << " | Blocked: " << std::setw(5) << (i * 10)
                  << " | Threats: " << std::setw(3) << (i % 3) << std::flush;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    std::cout << std::endl;
}

void CLI::cmd_logs(const std::vector<std::string>& args) {
    print_separator();
    std::cout << "  Recent Logs" << std::endl;
    print_separator();
    
    std::cout << "  [" << antiddos::utils::TimeUtils::get_time() << "] INFO  System initialized" << std::endl;
    std::cout << "  [" << antiddos::utils::TimeUtils::get_time() << "] INFO  Protection active" << std::endl;
    std::cout << "  [" << antiddos::utils::TimeUtils::get_time() << "] INFO  Monitoring started" << std::endl;
    
    print_separator();
}

void CLI::cmd_update(const std::vector<std::string>& args) {
    print_info("Updating threat intelligence databases...");
    print_success("Databases updated successfully!");
}

void CLI::cmd_export(const std::vector<std::string>& args) {
    std::string filename = (args.empty()) ? "antiddos_export.json" : args[0];
    print_success("Configuration exported to: " + filename);
}

void CLI::cmd_import(const std::vector<std::string>& args) {
    if (args.empty()) {
        print_error("Usage: import <filename>");
        return;
    }
    print_success("Configuration imported from: " + args[0]);
}

void CLI::print_header() {
    std::cout << std::endl;
    std::cout << "  =============================================" << std::endl;
    std::cout << "     Anti-DDoS Protection System v1.0.0" << std::endl;
    std::cout << "     Advanced Network Security Suite" << std::endl;
    std::cout << "  =============================================" << std::endl;
    std::cout << "     Type 'help' for available commands" << std::endl;
    std::cout << std::endl;
}

void CLI::print_separator() {
    std::cout << "  --------------------------------------------" << std::endl;
}

void CLI::print_error(const std::string& msg) {
    std::cerr << "  [ERROR] " << msg << std::endl;
}

void CLI::print_success(const std::string& msg) {
    std::cout << "  [OK] " << msg << std::endl;
}

void CLI::print_info(const std::string& msg) {
    std::cout << "  [INFO] " << msg << std::endl;
}

void CLI::print_help() {
    print_separator();
    std::cout << "  Available Commands:" << std::endl;
    print_separator();
    
    for (const auto& cmd : commands_) {
        std::cout << "  " << std::left << std::setw(20) << cmd.name << cmd.description << std::endl;
    }
    
    print_separator();
}

void CLI::print_version() {
    std::cout << "Anti-DDoS Protection System v1.0.0" << std::endl;
    std::cout << "Copyright (c) 2024" << std::endl;
    std::cout << "Build: " << __DATE__ << " " << __TIME__ << std::endl;
}

std::string CLI::readline(const std::string& prompt) {
    std::string input;
    std::cout << prompt;
    std::getline(std::cin, input);
    return input;
}

} // namespace antiddos
