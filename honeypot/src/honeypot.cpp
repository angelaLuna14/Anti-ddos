#include "honeypot.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define CLOSE_SOCKET closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define CLOSE_SOCKET close
#include <thread>
#endif

namespace antiddos {
namespace honeypot {

HoneypotManager::HoneypotManager() = default;

HoneypotManager::~HoneypotManager() {
    for (auto& [name, thread] : threads_) {
        if (thread.joinable()) {
            thread.detach();
        }
    }
}

bool HoneypotManager::create_honeypot(const std::string& name, const HoneypotConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (honeypots_.count(name)) return false;
    
    honeypots_[name] = config;
    running_status_[name] = false;
    
    return true;
}

bool HoneypotManager::destroy_honeypot(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!honeypots_.count(name)) return false;
    
    stop_honeypot(name);
    honeypots_.erase(name);
    running_status_.erase(name);
    
    return true;
}

bool HoneypotManager::start_honeypot(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!honeypots_.count(name) || running_status_[name]) return false;
    
    auto& config = honeypots_[name];
    
    threads_[name] = std::thread([this, name, config]() {
#ifdef _WIN32
        WSADATA wsa_data;
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) return;
#endif
        
        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) return;
        
        int opt = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config.port);
        inet_pton(AF_INET, config.bind_address.c_str(), &addr.sin_addr);
        
        if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            CLOSE_SOCKET(server_fd);
            return;
        }
        
        if (listen(server_fd, 128) < 0) {
            CLOSE_SOCKET(server_fd);
            return;
        }
        
        running_status_[name] = true;
        
        while (running_status_[name]) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
            
            if (client_fd < 0) continue;
            
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, INET_ADDRSTRLEN);
            
            std::thread(&HoneypotManager::handle_connection, this, name, std::string(ip_str), ntohs(client_addr.sin_port)).detach();
        }
        
        CLOSE_SOCKET(server_fd);
        
#ifdef _WIN32
        WSACleanup();
#endif
    });
    
    return true;
}

bool HoneypotManager::stop_honeypot(const std::string& name) {
    if (!running_status_.count(name)) return false;
    
    running_status_[name] = false;
    
    if (threads_.count(name) && threads_[name].joinable()) {
        threads_[name].join();
    }
    
    return true;
}

bool HoneypotManager::is_running(const std::string& name) const {
    auto it = running_status_.find(name);
    return (it != running_status_.end()) ? it->second : false;
}

void HoneypotManager::set_event_callback(EventCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = callback;
}

std::vector<std::string> HoneypotManager::get_active_honeypots() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (const auto& [name, running] : running_status_) {
        if (running) result.push_back(name);
    }
    return result;
}

HoneypotConfig HoneypotManager::get_config(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = honeypots_.find(name);
    return (it != honeypots_.end()) ? it->second : HoneypotConfig{};
}

std::vector<AttackerSession> HoneypotManager::get_sessions(const std::string& honeypot) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<AttackerSession> result;
    
    for (const auto& [ip, session] : sessions_) {
        if (honeypot.empty() || session.honeypot_type != HoneypotType::CUSTOM) {
            result.push_back(session);
        }
    }
    
    return result;
}

AttackerSession HoneypotManager::get_session(const std::string& attacker_ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(attacker_ip);
    return (it != sessions_.end()) ? it->second : AttackerSession{};
}

void HoneypotManager::add_blacklist(const std::string& ip, uint32_t duration_sec) {
    std::lock_guard<std::mutex> lock(mutex_);
    blacklist_.push_back({ip, std::chrono::steady_clock::now() + std::chrono::seconds(duration_sec)});
}

void HoneypotManager::remove_blacklist(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    blacklist_.erase(
        std::remove_if(blacklist_.begin(), blacklist_.end(),
            [&ip](const auto& pair) { return pair.first == ip; }),
        blacklist_.end()
    );
}

std::vector<std::string> HoneypotManager::get_blacklisted_ips() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    auto now = std::chrono::steady_clock::now();
    
    for (const auto& [ip, expiry] : blacklist_) {
        if (now <= expiry) {
            result.push_back(ip);
        }
    }
    
    return result;
}

std::vector<std::string> HoneypotManager::get_known_attackers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    
    for (const auto& [ip, session] : sessions_) {
        if (session.threat_score > 0.7f) {
            result.push_back(ip);
        }
    }
    
    return result;
}

void HoneypotManager::set_decoy_services(const std::vector<uint16_t>& ports) {
    std::lock_guard<std::mutex> lock(mutex_);
}

void HoneypotManager::set_fake_services(const std::unordered_map<uint16_t, HoneypotType>& services) {
    std::lock_guard<std::mutex> lock(mutex_);
}

HoneypotManager::Stats HoneypotManager::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void HoneypotManager::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = Stats{};
}

std::string HoneypotManager::export_sessions_json() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream oss;
    oss << "{\"sessions\":[";
    
    bool first = true;
    for (const auto& [ip, session] : sessions_) {
        if (!first) oss << ",";
        first = false;
        
        oss << "{\"ip\":\"" << ip << "\","
            << "\"commands\":" << session.commands_attempted << ","
            << "\"threat_score\":" << session.threat_score << ","
            << "\"first_seen\":" << std::chrono::duration_cast<std::chrono::seconds>(
                session.first_seen.time_since_epoch()).count() << ","
            << "\"last_seen\":" << std::chrono::duration_cast<std::chrono::seconds>(
                session.last_seen.time_since_epoch()).count() << "}";
    }
    
    oss << "]}";
    return oss.str();
}

bool HoneypotManager::import_sessions_json(const std::string& json) {
    return true;
}

void HoneypotManager::handle_connection(const std::string& name, const std::string& client_ip, uint16_t client_port) {
    auto& config = honeypots_[name];
    
    auto now = std::chrono::steady_clock::now();
    auto& session = sessions_[client_ip];
    
    if (session.first_seen == std::chrono::steady_clock::time_point{}) {
        session.first_seen = now;
        session.attacker_ip = client_ip;
        session.honeypot_type = config.type;
    }
    session.last_seen = now;
    session.connection_count++;
    session.is_active = true;
    
    stats_.total_connections++;
    
    log_event("CONNECTION", client_ip, name, "New connection");
}

void HoneypotManager::log_event(const std::string& type, const std::string& ip, const std::string& name, const std::string& data) {
    HoneypotEvent event;
    event.event_type = type;
    event.attacker_ip = ip;
    event.honeypot_name = name;
    event.data = data;
    event.timestamp = std::chrono::steady_clock::now();
    
    events_.push_back(event);
    
    if (callback_) {
        callback_(event);
    }
}

void HoneypotManager::update_session(const std::string& attacker_ip, const std::string& command) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto& session = sessions_[attacker_ip];
    session.commands.push_back(command);
    session.commands_attempted++;
    session.last_seen = std::chrono::steady_clock::now();
    
    stats_.total_commands++;
    
    analyze_behavior(session);
}

void HoneypotManager::analyze_behavior(AttackerSession& session) {
    float score = 0.0f;
    
    if (session.commands_attempted > 10) score += 0.2f;
    if (session.commands_attempted > 50) score += 0.3f;
    
    if (!session.usernames_tried.empty() || !session.passwords_tried.empty()) {
        score += 0.3f;
    }
    
    for (const auto& cmd : session.commands) {
        if (cmd.find("SELECT") != std::string::npos ||
            cmd.find("UNION") != std::string::npos ||
            cmd.find("DROP") != std::string::npos ||
            cmd.find("INSERT") != std::string::npos) {
            score += 0.2f;
            break;
        }
    }
    
    session.threat_score = std::min(1.0f, score);
}

} // namespace honeypot
} // namespace antiddos
