#ifndef HONEYPOT_H
#define HONEYPOT_H

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <functional>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>

namespace antiddos {
namespace honeypot {

enum class HoneypotType {
    HTTP,
    HTTPS,
    SSH,
    FTP,
    SMTP,
    MYSQL,
    POSTGRESQL,
    REDIS,
    MEMCACHED,
    DNS,
    TELNET,
    RDP,
    CUSTOM
};

enum class AttackPhase {
    RECONNAISSANCE,
    WEAPONIZATION,
    DELIVERY,
    EXPLOITATION,
    INSTALLATION,
    COMMAND_AND_CONTROL,
    ACTIONS_ON_OBJECTIVES
};

struct HoneypotConfig {
    HoneypotType type;
    uint16_t port;
    std::string bind_address = "0.0.0.0";
    std::string fake_banner;
    std::string fake_version;
    bool log_all_traffic = true;
    bool capture_payloads = true;
    uint32_t max_connections = 1000;
    uint32_t timeout_seconds = 30;
};

struct AttackerSession {
    std::string attacker_ip;
    std::string attacker_port;
    HoneypotType honeypot_type;
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    uint32_t connection_count;
    uint32_t commands_attempted;
    uint32_t payload_size;
    std::vector<std::string> commands;
    std::vector<std::string> usernames_tried;
    std::vector<std::string> passwords_tried;
    std::string captured_payload;
    AttackPhase current_phase;
    float threat_score;
    bool is_active;
};

struct HoneypotEvent {
    std::string event_type;
    std::string attacker_ip;
    uint16_t attacker_port;
    std::string honeypot_name;
    std::string data;
    std::chrono::steady_clock::time_point timestamp;
};

using EventCallback = std::function<void(const HoneypotEvent&)>;

class HoneypotManager {
public:
    HoneypotManager();
    ~HoneypotManager();
    
    bool create_honeypot(const std::string& name, const HoneypotConfig& config);
    bool destroy_honeypot(const std::string& name);
    
    bool start_honeypot(const std::string& name);
    bool stop_honeypot(const std::string& name);
    bool is_running(const std::string& name) const;
    
    void set_event_callback(EventCallback callback);
    
    std::vector<std::string> get_active_honeypots() const;
    HoneypotConfig get_config(const std::string& name) const;
    
    std::vector<AttackerSession> get_sessions(const std::string& honeypot = "") const;
    AttackerSession get_session(const std::string& attacker_ip) const;
    
    void add_blacklist(const std::string& ip, uint32_t duration_sec);
    void remove_blacklist(const std::string& ip);
    
    std::vector<std::string> get_blacklisted_ips() const;
    std::vector<std::string> get_known_attackers() const;
    
    void set_decoy_services(const std::vector<uint16_t>& ports);
    void set_fake_services(const std::unordered_map<uint16_t, HoneypotType>& services);
    
    struct Stats {
        uint64_t total_connections;
        uint64_t total_commands;
        uint32_t active_sessions;
        uint32_t blacklisted_ips;
        uint32_t known_attackers;
        std::unordered_map<std::string, uint32_t> connections_per_type;
    };
    
    Stats get_stats() const;
    void reset_stats();
    
    std::string export_sessions_json() const;
    bool import_sessions_json(const std::string& json);
    
private:
    void handle_connection(const std::string& name, const std::string& client_ip, uint16_t client_port);
    void simulate_http(const std::string& name, int client_fd);
    void simulate_ssh(const std::string& name, int client_fd);
    void simulate_ftp(const std::string& name, int client_fd);
    void simulate_mysql(const std::string& name, int client_fd);
    
    void log_event(const std::string& type, const std::string& ip, const std::string& name, const std::string& data);
    void update_session(const std::string& attacker_ip, const std::string& command);
    void analyze_behavior(AttackerSession& session);
    
    mutable std::mutex mutex_;
    std::unordered_map<std::string, HoneypotConfig> honeypots_;
    std::unordered_map<std::string, bool> running_status_;
    std::unordered_map<std::string, std::thread> threads_;
    std::unordered_map<std::string, AttackerSession> sessions_;
    std::vector<std::pair<std::string, std::chrono::steady_clock::time_point>> blacklist_;
    
    std::vector<HoneypotEvent> events_;
    EventCallback callback_;
    
    Stats stats_;
    std::atomic<bool> running_{false};
};

} // namespace honeypot
} // namespace antiddos

#endif // HONEYPOT_H