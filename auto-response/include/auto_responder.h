#ifndef AUTO_RESPONDER_H
#define AUTO_RESPONDER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>
#include <functional>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <queue>
#include "utils.h"

namespace antiddos {
namespace response {

enum class ResponseAction {
    NONE,
    LOG_ONLY,
    RATE_LIMIT,
    CAPTCHA,
    BLOCK_IP,
    BLOCK_CIDR,
    BLOCK_PORT,
    REDIRECT,
    CHALLENGE,
    DROP_TRAFFIC,
    BLACKLIST,
    WHITELIST,
    NOTIFY_ADMIN,
    TRIGGER_HONEYPOT,
    GEO_BLOCK,
    THROTTLE,
    CHALLENGE_RESPONSE
};

enum class ThreatSeverity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

enum class AttackType {
    UNKNOWN,
    SYN_FLOOD,
    UDP_FLOOD,
    HTTP_FLOOD,
    DNS_AMPLIFICATION,
    NTP_AMPLIFICATION,
    SLOWLORIS,
    BRUTE_FORCE,
    SCANNER,
    BOT,
    VPN_ABUSE,
    API_ABUSE,
    CREDENTIAL_STUFFING
};

struct ResponseRule {
    std::string name;
    AttackType attack_type;
    ThreatSeverity min_severity;
    std::vector<ResponseAction> actions;
    uint32_t cooldown_seconds;
    uint32_t duration_seconds;
    bool enabled = true;
    uint32_t priority = 0;
};

struct IncidentResponse {
    std::string id;
    std::string attacker_ip;
    AttackType attack_type;
    ThreatSeverity severity;
    std::vector<ResponseAction> actions_taken;
    std::chrono::steady_clock::time_point detected_at;
    std::chrono::steady_clock::time_point resolved_at;
    bool is_active;
    std::string description;
};

struct MitigationPlan {
    std::string name;
    AttackType target_attack;
    std::vector<ResponseAction> escalation_steps;
    std::vector<uint32_t> escalation_thresholds;
    uint32_t auto_resolve_after_seconds;
};

struct ResponseStats {
    uint64_t total_incidents;
    uint32_t active_incidents;
    uint32_t blocks_executed;
    uint32_t rate_limits_applied;
    uint32_t captchas_served;
    uint32_t notifications_sent;
    uint32_t auto_resolved;
    std::unordered_map<AttackType, uint32_t> incidents_by_type;
    std::unordered_map<ThreatSeverity, uint32_t> incidents_by_severity;
};

using ResponseCallback = std::function<void(const IncidentResponse&)>;

class AutoResponder {
public:
    AutoResponder();
    ~AutoResponder();
    
    void add_rule(const ResponseRule& rule);
    void remove_rule(const std::string& rule_name);
    void enable_rule(const std::string& rule_name, bool enable);
    
    void add_mitigation_plan(const MitigationPlan& plan);
    void remove_mitigation_plan(const std::string& name);
    
    void process_threat(const std::string& attacker_ip, AttackType attack_type, ThreatSeverity severity, float confidence);
    
    void set_callback(ResponseCallback callback);
    
    std::vector<IncidentResponse> get_active_incidents() const;
    IncidentResponse get_incident(const std::string& incident_id) const;
    
    void block_ip(const std::string& ip, uint32_t duration_sec, const std::string& reason);
    void unblock_ip(const std::string& ip);
    
    void block_cidr(const std::string& cidr, uint32_t duration_sec, const std::string& reason);
    void unblock_cidr(const std::string& cidr);
    bool is_ip_in_blocked_cidr(const std::string& ip) const;
    std::vector<std::string> get_blocked_cidrs() const;
    
    void set_rate_limit(const std::string& ip, uint32_t requests_per_second);
    void remove_rate_limit(const std::string& ip);
    
    void send_notification(const std::string& message, ThreatSeverity severity);
    
    void set_auto_response_enabled(bool enable);
    bool is_auto_response_enabled() const;
    
    void set_escalation_enabled(bool enable);
    void set_max_incidents_per_minute(uint32_t max);
    
    ResponseStats get_stats() const;
    void reset_stats();
    
    std::vector<std::string> get_blocked_ips() const;
    std::vector<std::string> get_rate_limited_ips() const;
    
    void add_to_blacklist(const std::string& ip, uint32_t duration_sec);
    void add_to_whitelist(const std::string& ip);
    
    std::string export_incidents_json() const;
    bool import_rules_json(const std::string& json);
    
private:
    void execute_response(const ResponseAction& action, const std::string& attacker_ip, uint32_t duration);
    void apply_rate_limit(const std::string& ip, uint32_t rps);
    void apply_block(const std::string& ip, uint32_t duration_sec);
    void apply_captcha(const std::string& ip);
    void apply_geo_block(const std::string& ip);
    
    void process_escalation(IncidentResponse& incident, ThreatSeverity current_severity);
    bool check_cooldown(const std::string& ip, const std::string& rule_name);
    
    mutable std::recursive_mutex mutex_;
    
    std::vector<ResponseRule> rules_;
    std::vector<MitigationPlan> plans_;
    std::vector<IncidentResponse> incidents_;
    
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> cooldowns_;
    std::unordered_map<std::string, uint32_t> rate_limits_;
    std::unordered_set<std::string> blacklisted_ips_;
    std::unordered_set<std::string> whitelisted_ips_;
    
    struct CIDRBlockEntry {
        utils::CIDRRange range;
        uint32_t duration_seconds;
        std::chrono::steady_clock::time_point blocked_at;
        std::string reason;
    };
    std::vector<CIDRBlockEntry> blocked_cidrs_;
    
    bool auto_response_enabled_ = true;
    bool escalation_enabled_ = true;
    uint32_t max_incidents_per_minute_ = 100;
    
    ResponseStats stats_;
    ResponseCallback callback_;
    
    std::atomic<uint64_t> incident_counter_{0};
};

} // namespace response
} // namespace antiddos

#endif // AUTO_RESPONDER_H