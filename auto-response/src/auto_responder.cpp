#include "auto_responder.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <random>

namespace antiddos {
namespace response {

AutoResponder::AutoResponder() = default;
AutoResponder::~AutoResponder() = default;

void AutoResponder::add_rule(const ResponseRule& rule) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    rules_.push_back(rule);
}

void AutoResponder::remove_rule(const std::string& rule_name) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    rules_.erase(
        std::remove_if(rules_.begin(), rules_.end(),
            [&rule_name](const ResponseRule& r) { return r.name == rule_name; }),
        rules_.end()
    );
}

void AutoResponder::enable_rule(const std::string& rule_name, bool enable) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (auto& rule : rules_) {
        if (rule.name == rule_name) {
            rule.enabled = enable;
            break;
        }
    }
}

void AutoResponder::add_mitigation_plan(const MitigationPlan& plan) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    plans_.push_back(plan);
}

void AutoResponder::remove_mitigation_plan(const std::string& name) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    plans_.erase(
        std::remove_if(plans_.begin(), plans_.end(),
            [&name](const MitigationPlan& p) { return p.name == name; }),
        plans_.end()
    );
}

void AutoResponder::process_threat(const std::string& attacker_ip, AttackType attack_type, ThreatSeverity severity, float confidence) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    if (!auto_response_enabled_) return;
    
    if (whitelisted_ips_.count(attacker_ip)) return;
    
    IncidentResponse incident;
    incident.id = "INC-" + std::to_string(incident_counter_++);
    incident.attacker_ip = attacker_ip;
    incident.attack_type = attack_type;
    incident.severity = severity;
    incident.detected_at = std::chrono::steady_clock::now();
    incident.is_active = true;
    incident.description = "Attack detected with confidence " + std::to_string(confidence);
    
    for (const auto& rule : rules_) {
        if (!rule.enabled) continue;
        if (rule.attack_type != AttackType::UNKNOWN && rule.attack_type != attack_type) continue;
        if (severity < rule.min_severity) continue;
        if (check_cooldown(attacker_ip, rule.name)) continue;
        
        for (const auto& action : rule.actions) {
            execute_response(action, attacker_ip, rule.duration_seconds);
            incident.actions_taken.push_back(action);
        }
        
        cooldowns_[attacker_ip + ":" + rule.name] = std::chrono::steady_clock::now() + std::chrono::seconds(rule.cooldown_seconds);
    }
    
    incidents_.push_back(incident);
    
    stats_.total_incidents++;
    stats_.incidents_by_type[attack_type]++;
    stats_.incidents_by_severity[severity]++;
    
    if (severity >= ThreatSeverity::HIGH) {
        send_notification("High severity attack detected from " + attacker_ip, severity);
    }
    
    if (callback_) {
        callback_(incident);
    }
}

void AutoResponder::set_callback(ResponseCallback callback) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    callback_ = callback;
}

std::vector<IncidentResponse> AutoResponder::get_active_incidents() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<IncidentResponse> result;
    for (const auto& inc : incidents_) {
        if (inc.is_active) result.push_back(inc);
    }
    return result;
}

IncidentResponse AutoResponder::get_incident(const std::string& incident_id) const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (const auto& inc : incidents_) {
        if (inc.id == incident_id) return inc;
    }
    return IncidentResponse{};
}

void AutoResponder::block_ip(const std::string& ip, uint32_t duration_sec, const std::string& reason) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    blacklisted_ips_.insert(ip);
    stats_.blocks_executed++;
}

void AutoResponder::unblock_ip(const std::string& ip) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    blacklisted_ips_.erase(ip);
}

void AutoResponder::block_cidr(const std::string& cidr, uint32_t duration_sec, const std::string& reason) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    CIDRBlockEntry entry;
    entry.range = utils::IPUtils::parse_cidr(cidr);
    entry.duration_seconds = duration_sec;
    entry.blocked_at = std::chrono::steady_clock::now();
    entry.reason = reason;
    blocked_cidrs_.push_back(entry);
    stats_.blocks_executed++;
}

void AutoResponder::unblock_cidr(const std::string& cidr) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    utils::CIDRRange target = utils::IPUtils::parse_cidr(cidr);
    blocked_cidrs_.erase(
        std::remove_if(blocked_cidrs_.begin(), blocked_cidrs_.end(),
            [&target](const CIDRBlockEntry& e) {
                return e.range.network == target.network && e.range.prefix == target.prefix;
            }),
        blocked_cidrs_.end()
    );
}

bool AutoResponder::is_ip_in_blocked_cidr(const std::string& ip) const {
    auto now = std::chrono::steady_clock::now();
    for (const auto& entry : blocked_cidrs_) {
        if (entry.duration_seconds > 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - entry.blocked_at).count();
            if (static_cast<uint32_t>(elapsed) > entry.duration_seconds) continue;
        }
        if (utils::IPUtils::is_ip_in_cidr(ip, entry.range)) {
            return true;
        }
    }
    return false;
}

std::vector<std::string> AutoResponder::get_blocked_cidrs() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<std::string> result;
    for (const auto& entry : blocked_cidrs_) {
        result.push_back(utils::IPUtils::int_to_ip(entry.range.network) + "/" + std::to_string(entry.range.prefix));
    }
    return result;
}

void AutoResponder::set_rate_limit(const std::string& ip, uint32_t requests_per_second) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    rate_limits_[ip] = requests_per_second;
    stats_.rate_limits_applied++;
}

void AutoResponder::remove_rate_limit(const std::string& ip) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    rate_limits_.erase(ip);
}

void AutoResponder::send_notification(const std::string& message, ThreatSeverity severity) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    stats_.notifications_sent++;
}

void AutoResponder::set_auto_response_enabled(bool enable) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto_response_enabled_ = enable;
}

bool AutoResponder::is_auto_response_enabled() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return auto_response_enabled_;
}

void AutoResponder::set_escalation_enabled(bool enable) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    escalation_enabled_ = enable;
}

void AutoResponder::set_max_incidents_per_minute(uint32_t max) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    max_incidents_per_minute_ = max;
}

ResponseStats AutoResponder::get_stats() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return stats_;
}

void AutoResponder::reset_stats() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    stats_ = ResponseStats{};
}

std::vector<std::string> AutoResponder::get_blocked_ips() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return std::vector<std::string>(blacklisted_ips_.begin(), blacklisted_ips_.end());
}

std::vector<std::string> AutoResponder::get_rate_limited_ips() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<std::string> result;
    for (const auto& [ip, rps] : rate_limits_) {
        result.push_back(ip + " (" + std::to_string(rps) + " rps)");
    }
    return result;
}

void AutoResponder::add_to_blacklist(const std::string& ip, uint32_t duration_sec) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    blacklisted_ips_.insert(ip);
    stats_.blocks_executed++;
}

void AutoResponder::add_to_whitelist(const std::string& ip) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    whitelisted_ips_.insert(ip);
}

std::string AutoResponder::export_incidents_json() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::ostringstream oss;
    oss << "{\"incidents\":[";
    
    bool first = true;
    for (const auto& inc : incidents_) {
        if (!first) oss << ",";
        first = false;
        
        oss << "{\"id\":\"" << inc.id << "\","
            << "\"attacker_ip\":\"" << inc.attacker_ip << "\","
            << "\"severity\":" << static_cast<int>(inc.severity) << ","
            << "\"is_active\":" << (inc.is_active ? "true" : "false") << ","
            << "\"actions_count\":" << inc.actions_taken.size() << "}";
    }
    
    oss << "]}";
    return oss.str();
}

bool AutoResponder::import_rules_json(const std::string& json) {
    return true;
}

void AutoResponder::execute_response(const ResponseAction& action, const std::string& attacker_ip, uint32_t duration) {
    switch (action) {
        case ResponseAction::BLOCK_IP:
            apply_block(attacker_ip, duration);
            break;
        case ResponseAction::BLOCK_CIDR:
            block_cidr(attacker_ip + "/24", duration, "Auto-response CIDR block");
            break;
        case ResponseAction::RATE_LIMIT:
            apply_rate_limit(attacker_ip, 10);
            break;
        case ResponseAction::CAPTCHA:
            apply_captcha(attacker_ip);
            break;
        case ResponseAction::BLACKLIST:
            blacklisted_ips_.insert(attacker_ip);
            stats_.blocks_executed++;
            break;
        case ResponseAction::NOTIFY_ADMIN:
            send_notification("Attack from " + attacker_ip, ThreatSeverity::HIGH);
            break;
        default:
            break;
    }
}

void AutoResponder::apply_rate_limit(const std::string& ip, uint32_t rps) {
    rate_limits_[ip] = rps;
    stats_.rate_limits_applied++;
}

void AutoResponder::apply_block(const std::string& ip, uint32_t duration_sec) {
    blacklisted_ips_.insert(ip);
    stats_.blocks_executed++;
}

void AutoResponder::apply_captcha(const std::string& ip) {
    stats_.captchas_served++;
}

void AutoResponder::apply_geo_block(const std::string& ip) {
}

void AutoResponder::process_escalation(IncidentResponse& incident, ThreatSeverity current_severity) {
    if (!escalation_enabled_) return;
    
    for (const auto& plan : plans_) {
        if (plan.target_attack == incident.attack_type) {
            for (size_t i = 0; i < plan.escalation_steps.size(); i++) {
                if (current_severity >= ThreatSeverity::HIGH) {
                    execute_response(plan.escalation_steps[i], incident.attacker_ip, plan.auto_resolve_after_seconds);
                    incident.actions_taken.push_back(plan.escalation_steps[i]);
                }
            }
        }
    }
}

bool AutoResponder::check_cooldown(const std::string& ip, const std::string& rule_name) {
    auto it = cooldowns_.find(ip + ":" + rule_name);
    if (it == cooldowns_.end()) return false;
    return std::chrono::steady_clock::now() < it->second;
}

} // namespace response
} // namespace antiddos