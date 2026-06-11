#include "logger.h"
#include "platform.h"
#include "rate_limiter.h"
#include "behavioral_analyzer.h"
#include "geo_blocker.h"
#include "vpn_detector.h"
#include <iostream>
#include <signal.h>
#include <chrono>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#include <winsvc.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#endif

namespace antiddos {

class AntiDDoSDaemon {
public:
    AntiDDoSDaemon() = default;
    ~AntiDDoSDaemon() = default;
    
    bool initialize(const std::string& config_path) {
        Logger::instance().init("antiddos_daemon.log", LogLevel::INFO);
        Logger::instance().info("Initializing Anti-DDoS Daemon");
        
        if (!platform::NetworkUtils::init_sockets()) {
            Logger::instance().error("Failed to initialize network sockets");
            return false;
        }
        
        rate_limiter_.enable_ddos_protection(true);
        behavioral_analyzer_.set_learning_mode(false);
        
        RateLimitConfig config;
        config.max_requests_per_second = 100;
        config.max_requests_per_minute = 1000;
        config.burst_size = 50;
        config.block_duration_seconds = 300;
        rate_limiter_.set_config(config);
        
        rate_limiter_.set_block_callback([](const std::string& ip, uint32_t duration, RateLimitAction action) {
            Logger::instance().warning("Blocking IP: " + ip + " for " + std::to_string(duration) + " seconds");
            platform::NetworkUtils::block_ip(ip);
        });
        
        behavioral_analyzer_.set_callback([](const std::string& ip, BehaviorType type, float confidence) {
            std::string type_str;
            switch (type) {
                case BehaviorType::BOT: type_str = "BOT"; break;
                case BehaviorType::SCRAPER: type_str = "SCRAPER"; break;
                case BehaviorType::SCANNER: type_str = "SCANNER"; break;
                case BehaviorType::DDOS: type_str = "DDOS"; break;
                case BehaviorType::HTTP_FLOOD: type_str = "HTTP_FLOOD"; break;
                default: type_str = "UNKNOWN"; break;
            }
            Logger::instance().info("Detected " + type_str + " from " + ip + " (confidence: " + std::to_string(confidence) + ")");
        });
        
        Logger::instance().info("Anti-DDoS Daemon initialized successfully");
        return true;
    }
    
    void run() {
        running_ = true;
        Logger::instance().info("Daemon started");
        
        auto last_cleanup = std::chrono::steady_clock::now();
        auto last_stats = std::chrono::steady_clock::now();
        
        while (running_) {
            auto now = std::chrono::steady_clock::now();
            
            if (now - last_cleanup > std::chrono::minutes(5)) {
                cleanup_expired_blocks();
                last_cleanup = now;
            }
            
            if (now - last_stats > std::chrono::minutes(1)) {
                print_stats();
                last_stats = now;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        Logger::instance().info("Daemon stopped");
    }
    
    void stop() {
        running_ = false;
    }
    
    static AntiDDoSDaemon& instance() {
        static AntiDDoSDaemon inst;
        return inst;
    }
    
private:
    void cleanup_expired_blocks() {
        auto blocked = rate_limiter_.get_blocked_ips();
        Logger::instance().debug("Active blocks: " + std::to_string(blocked.size()));
    }
    
    void print_stats() {
        auto stats = rate_limiter_.get_stats();
        auto analytics = behavioral_analyzer_.get_analytics();
        
        Logger::instance().info(
            "Stats - Total: " + std::to_string(stats.total_requests) +
            " | Allowed: " + std::to_string(stats.allowed_requests) +
            " | Blocked: " + std::to_string(stats.blocked_requests) +
            " | Bots: " + std::to_string(analytics.bots_detected) +
            " | Attackers: " + std::to_string(analytics.attackers_detected)
        );
    }
    
    RateLimiter rate_limiter_;
    BehavioralAnalyzer behavioral_analyzer_;
    GeoBlocker geo_blocker_;
    VPNDetector vpn_detector_;
    
    volatile bool running_ = false;
};

} // namespace antiddos

static void signal_handler(int signum) {
    std::cout << "\nReceived signal " << signum << ", shutting down..." << std::endl;
    antiddos::AntiDDoSDaemon::instance().stop();
}

#ifdef _WIN32

SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
SERVICE_STATUS g_ServiceStatus = {0};

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    
    g_StatusHandle = RegisterServiceCtrlHandler(TEXT("AntiDDoS"), [](DWORD ctrl) {
        switch (ctrl) {
            case SERVICE_CONTROL_STOP:
            case SERVICE_CONTROL_SHUTDOWN:
                g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
                antiddos::AntiDDoSDaemon::instance().stop();
                return;
        }
    });
    
    if (g_StatusHandle == NULL) return;
    
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    
    antiddos::AntiDDoSDaemon::instance().run();
    
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

int main(int argc, char* argv[]) {
    if (argc > 1 && std::string(argv[1]) == "--console") {
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
        
        if (!antiddos::AntiDDoSDaemon::instance().initialize("config.ini")) {
            std::cerr << "Failed to initialize daemon" << std::endl;
            return 1;
        }
        
        antiddos::AntiDDoSDaemon::instance().run();
        return 0;
    }
    
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        { TEXT("AntiDDoS"), (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };
    
    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        return GetLastError();
    }
    
    return 0;
}

#else

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);
    
    bool daemon_mode = false;
    
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--daemon" || std::string(argv[i]) == "-d") {
            daemon_mode = true;
        }
    }
    
    if (daemon_mode) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork failed");
            return 1;
        }
        if (pid > 0) {
            return 0;
        }
        
        umask(0);
        setsid();
        
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }
    
    if (!antiddos::AntiDDoSDaemon::instance().initialize("/etc/antiddos/config.ini")) {
        std::cerr << "Failed to initialize daemon" << std::endl;
        return 1;
    }
    
    antiddos::AntiDDoSDaemon::instance().run();
    return 0;
}

#endif