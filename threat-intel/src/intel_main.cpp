#include "threat_intel.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <csignal>
#include <atomic>

static std::atomic<bool> running(true);

void signal_handler(int signum) {
    std::cout << "\nReceived signal " << signum << ", shutting down..." << std::endl;
    running = false;
}

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -d, --database <path>    Local database path" << std::endl;
    std::cout << "  -a, --add-feed <url>     Add threat feed" << std::endl;
    std::cout << "  -b, --block-ip <ip>      Block an IP" << std::endl;
    std::cout << "  -w, --whitelist-ip <ip>  Whitelist an IP" << std::endl;
    std::cout << "  -l, --list               List blocked IPs" << std::endl;
    std::cout << "  -s, --stats              Show statistics" << std::endl;
    std::cout << "  --export <path>          Export intel data" << std::endl;
    std::cout << "  --import <path>          Import intel data" << std::endl;
    std::cout << "  -h, --help               Show this help" << std::endl;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    std::string database_path = "/var/lib/antiddos/threat_intel.db";
    std::string add_feed;
    std::string block_ip;
    std::string whitelist_ip;
    bool list_blocked = false;
    bool show_stats = false;
    std::string export_path;
    std::string import_path;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-d" || arg == "--database") {
            if (i + 1 < argc) database_path = argv[++i];
        } else if (arg == "-a" || arg == "--add-feed") {
            if (i + 1 < argc) add_feed = argv[++i];
        } else if (arg == "-b" || arg == "--block-ip") {
            if (i + 1 < argc) block_ip = argv[++i];
        } else if (arg == "-w" || arg == "--whitelist-ip") {
            if (i + 1 < argc) whitelist_ip = argv[++i];
        } else if (arg == "-l" || arg == "--list") {
            list_blocked = true;
        } else if (arg == "-s" || arg == "--stats") {
            show_stats = true;
        } else if (arg == "--export") {
            if (i + 1 < argc) export_path = argv[++i];
        } else if (arg == "--import") {
            if (i + 1 < argc) import_path = argv[++i];
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    antiddos::intel::ThreatIntelManager intel;
    
    std::cout << "=============================================" << std::endl;
    std::cout << "  Anti-DDoS Threat Intelligence v2.0.0" << std::endl;
    std::cout << "=============================================" << std::endl;
    
    intel.load_local_database(database_path);
    
    if (!add_feed.empty()) {
        antiddos::intel::ThreatFeed feed;
        feed.name = "custom-feed-" + std::to_string(time(nullptr));
        feed.url = add_feed;
        feed.type = antiddos::intel::FeedType::IP_BLACKLIST;
        feed.update_interval_minutes = 60;
        feed.enabled = true;
        feed.priority = 1;
        
        if (intel.add_feed(feed)) {
            std::cout << "Added feed: " << add_feed << std::endl;
            intel.update_feed(feed.name);
        } else {
            std::cerr << "Failed to add feed" << std::endl;
        }
    }
    
    if (!block_ip.empty()) {
        intel.add_ip_to_blacklist(block_ip, 24, "Manual block");
        std::cout << "Blocked IP: " << block_ip << std::endl;
    }
    
    if (!whitelist_ip.empty()) {
        intel.add_ip_to_whitelist(whitelist_ip, "Manual whitelist");
        std::cout << "Whitelisted IP: " << whitelist_ip << std::endl;
    }
    
    if (list_blocked) {
        auto blocked = intel.get_blacklisted_ips();
        std::cout << std::endl;
        std::cout << "Blocked IPs (" << blocked.size() << "):" << std::endl;
        for (const auto& ip : blocked) {
            std::cout << "  " << ip << std::endl;
        }
    }
    
    if (show_stats) {
        auto stats = intel.get_stats();
        std::cout << std::endl;
        std::cout << "Threat Intelligence Statistics:" << std::endl;
        std::cout << "  Total Queries:      " << stats.total_queries << std::endl;
        std::cout << "  Malicious Detected: " << stats.malicious_detections << std::endl;
        std::cout << "  Whitelist Hits:     " << stats.whitelist_hits << std::endl;
        std::cout << "  Active Feeds:       " << stats.active_feeds << std::endl;
        std::cout << "  IP Entries:         " << stats.total_ip_entries << std::endl;
        std::cout << "  Domain Entries:     " << stats.total_domain_entries << std::endl;
        std::cout << "  Indicators:         " << stats.total_indicators << std::endl;
    }
    
    if (!export_path.empty()) {
        std::string data = intel.export_intel_json();
        std::ofstream file(export_path);
        if (file.is_open()) {
            file << data;
            std::cout << "Exported to: " << export_path << std::endl;
        }
    }
    
    if (!import_path.empty()) {
        std::ifstream file(import_path);
        if (file.is_open()) {
            std::string data((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
            if (intel.import_intel_json(data)) {
                std::cout << "Imported from: " << import_path << std::endl;
            }
        }
    }
    
    if (add_feed.empty() && block_ip.empty() && whitelist_ip.empty() && 
        !list_blocked && !show_stats && export_path.empty() && import_path.empty()) {
        print_usage(argv[0]);
    }
    
    intel.save_local_database(database_path);
    
    return 0;
}