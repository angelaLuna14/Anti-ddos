#include "cluster_manager.h"
#include <iostream>
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
    std::cout << "  -c, --cluster-id <id>    Cluster ID (default: antiddos-cluster)" << std::endl;
    std::cout << "  -j, --join <addr:port>   Join existing cluster" << std::endl;
    std::cout << "  -p, --port <port>        Node port (default: 7000)" << std::endl;
    std::cout << "  --discover               Enable auto-discovery" << std::endl;
    std::cout << "  --heartbeat <ms>         Heartbeat interval (default: 1000)" << std::endl;
    std::cout << "  -h, --help               Show this help" << std::endl;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    std::string cluster_id = "antiddos-cluster";
    std::string join_address;
    uint16_t port = 7000;
    bool auto_discover = true;
    uint32_t heartbeat_ms = 1000;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-c" || arg == "--cluster-id") {
            if (i + 1 < argc) cluster_id = argv[++i];
        } else if (arg == "-j" || arg == "--join") {
            if (i + 1 < argc) join_address = argv[++i];
        } else if (arg == "-p" || arg == "--port") {
            if (i + 1 < argc) port = std::stoi(argv[++i]);
        } else if (arg == "--discover") {
            auto_discover = true;
        } else if (arg == "--heartbeat") {
            if (i + 1 < argc) heartbeat_ms = std::stoi(argv[++i]);
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    antiddos::distributed::ClusterConfig config;
    config.cluster_id = cluster_id;
    config.heartbeat_interval_ms = heartbeat_ms;
    config.discovery_port = port + 1000;
    config.auto_discover = auto_discover;
    
    antiddos::distributed::ClusterManager cluster;
    
    std::cout << "=============================================" << std::endl;
    std::cout << "  Anti-DDoS Cluster Manager v2.0.0" << std::endl;
    std::cout << "=============================================" << std::endl;
    
    if (!cluster.initialize(config)) {
        std::cerr << "Failed to initialize cluster" << std::endl;
        return 1;
    }
    
    std::cout << "  Node ID:     " << cluster.get_node_id() << std::endl;
    std::cout << "  Cluster ID:  " << cluster_id << std::endl;
    std::cout << "  Port:        " << port << std::endl;
    std::cout << "  Discovery:   " << (auto_discover ? "Enabled" : "Disabled") << std::endl;
    std::cout << "=============================================" << std::endl;
    
    if (!join_address.empty()) {
        size_t colon = join_address.find(':');
        std::string seed_addr = join_address.substr(0, colon);
        uint16_t seed_port = std::stoi(join_address.substr(colon + 1));
        
        std::cout << "Joining cluster at " << seed_addr << ":" << seed_port << "..." << std::endl;
        
        if (cluster.join_cluster(seed_addr, seed_port)) {
            std::cout << "Joined cluster successfully" << std::endl;
        } else {
            std::cerr << "Failed to join cluster" << std::endl;
        }
    }
    
    std::cout << std::endl;
    std::cout << "Cluster node running. Press Ctrl+C to stop." << std::endl;
    
    auto last_stats = std::chrono::steady_clock::now();
    
    while (running) {
        auto now = std::chrono::steady_clock::now();
        
        if (now - last_stats > std::chrono::seconds(30)) {
            auto stats = cluster.get_stats();
            std::cout << "\r[Cluster] Nodes: " << stats.active_nodes 
                      << " | Threats: " << stats.total_threats
                      << " | Leader: " << (stats.leader_node.empty() ? "None" : stats.leader_node)
                      << std::flush;
            last_stats = now;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    cluster.leave_cluster();
    cluster.shutdown();
    
    std::cout << std::endl << "Cluster node stopped" << std::endl;
    return 0;
}