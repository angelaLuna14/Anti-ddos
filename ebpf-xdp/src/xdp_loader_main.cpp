#include "xdp_loader.h"
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
    std::cout << "  -i, --interface <iface>  Network interface (default: eth0)" << std::endl;
    std::cout << "  -f, --file <path>        XDP object file path" << std::endl;
    std::cout << "  -d, --detach             Detach XDP program" << std::endl;
    std::cout << "  -s, --stats              Show statistics" << std::endl;
    std::cout << "  -h, --help               Show this help" << std::endl;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    std::string interface = "eth0";
    std::string obj_path = "/usr/lib/antiddos/xdp_filter_kern.o";
    bool detach = false;
    bool show_stats = false;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-i" || arg == "--interface") {
            if (i + 1 < argc) interface = argv[++i];
        } else if (arg == "-f" || arg == "--file") {
            if (i + 1 < argc) obj_path = argv[++i];
        } else if (arg == "-d" || arg == "--detach") {
            detach = true;
        } else if (arg == "-s" || arg == "--stats") {
            show_stats = true;
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    antiddos::xdp::XDPLoader loader;
    
    if (detach) {
        std::cout << "Detaching XDP program from " << interface << "..." << std::endl;
        if (loader.detach()) {
            std::cout << "XDP program detached successfully" << std::endl;
        } else {
            std::cerr << "Failed to detach XDP program" << std::endl;
            return 1;
        }
        return 0;
    }
    
    if (show_stats) {
        std::cout << "Loading XDP program to read stats..." << std::endl;
        if (!loader.load(obj_path, interface)) {
            std::cerr << "Failed to load XDP program" << std::endl;
            return 1;
        }
        
        loader.start_monitoring(1000);
        
        std::cout << "Statistics (Ctrl+C to stop):" << std::endl;
        std::cout << std::endl;
        
        while (running) {
            auto stats = loader.get_stats();
            
            std::cout << "\r  Total: " << stats.total_packets
                      << " | Passed: " << stats.passed_packets
                      << " | Dropped: " << stats.dropped_packets
                      << " | SYN: " << stats.syn_flood_drops
                      << " | UDP: " << stats.udp_flood_drops << std::flush;
            
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        std::cout << std::endl;
        loader.unload();
        return 0;
    }
    
    std::cout << "Loading XDP program on " << interface << "..." << std::endl;
    
    if (!loader.load(obj_path, interface)) {
        std::cerr << "Failed to load XDP program" << std::endl;
        std::cerr << "Make sure:" << std::endl;
        std::cerr << "  - You are running as root" << std::endl;
        std::cerr << "  - The interface exists" << std::endl;
        std::cerr << "  - eBPF is supported" << std::endl;
        return 1;
    }
    
    std::cout << "XDP program loaded successfully on " << interface << std::endl;
    std::cout << "Press Ctrl+C to unload and exit" << std::endl;
    
    loader.start_monitoring(1000);
    
    while (running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    loader.stop_monitoring();
    loader.unload();
    
    std::cout << "XDP program unloaded" << std::endl;
    return 0;
}