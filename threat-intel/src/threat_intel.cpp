#include "threat_intel.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <algorithm>

namespace antiddos {
namespace intel {

ThreatIntelManager::ThreatIntelManager() = default;

ThreatIntelManager::~ThreatIntelManager() {
    running_ = false;
    if (update_thread_.joinable()) {
        update_thread_.join();
    }
}

bool ThreatIntelManager::add_feed(const ThreatFeed& feed) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& existing : feeds_) {
        if (existing.name == feed.name) return false;
    }
    
    feeds_.push_back(feed);
    stats_.active_feeds++;
    return true;
}

bool ThreatIntelManager::remove_feed(const std::string& feed_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = std::remove_if(feeds_.begin(), feeds_.end(),
        [&feed_name](const ThreatFeed& f) { return f.name == feed_name; });
    
    if (it != feeds_.end()) {
        feeds_.erase(it, feeds_.end());
        stats_.active_feeds--;
        return true;
    }
    return false;
}

bool ThreatIntelManager::update_feed(const std::string& feed_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& feed : feeds_) {
        if (feed.name == feed_name && feed.enabled) {
            feed.last_updated = std::chrono::steady_clock::now();
            stats_.last_feed_update = feed.last_updated;
            return true;
        }
    }
    return false;
}

bool ThreatIntelManager::update_all_feeds() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& feed : feeds_) {
        if (feed.enabled) {
            feed.last_updated = std::chrono::steady_clock::now();
        }
    }
    
    stats_.last_feed_update = std::chrono::steady_clock::now();
    return true;
}

void ThreatIntelManager::set_feed_callback(FeedUpdateCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = callback;
}

IPReputation ThreatIntelManager::get_ip_reputation(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = ip_reputations_.find(ip);
    if (it != ip_reputations_.end()) {
        return it->second;
    }
    
    IPReputation rep;
    rep.ip = ip;
    rep.level = ReputationLevel::UNKNOWN;
    rep.threat_score = 0;
    rep.confidence = 0;
    
    if (ip_whitelist_.count(ip)) {
        rep.level = ReputationLevel::TRUSTED;
        rep.threat_score = 0;
    } else if (ip_blacklist_.count(ip)) {
        rep.level = ReputationLevel::MALICIOUS;
        rep.threat_score = 100;
    }
    
    return rep;
}

DomainReputation ThreatIntelManager::get_domain_reputation(const std::string& domain) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = domain_reputations_.find(domain);
    if (it != domain_reputations_.end()) {
        return it->second;
    }
    
    DomainReputation rep;
    rep.domain = domain;
    rep.level = ReputationLevel::UNKNOWN;
    rep.threat_score = 0;
    
    if (domain_blacklist_.count(domain)) {
        rep.level = ReputationLevel::MALICIOUS;
        rep.threat_score = 100;
    }
    
    return rep;
}

bool ThreatIntelManager::is_ip_malicious(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (ip_whitelist_.count(ip)) return false;
    if (ip_blacklist_.count(ip)) return true;
    if (is_ip_in_blacklisted_cidr(ip)) return true;
    
    auto it = ip_reputations_.find(ip);
    if (it != ip_reputations_.end()) {
        return it->second.threat_score >= reputation_threshold_;
    }
    
    return false;
}

bool ThreatIntelManager::is_domain_malicious(const std::string& domain) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return domain_blacklist_.count(domain) > 0;
}

bool ThreatIntelManager::is_ip_whitelisted(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return ip_whitelist_.count(ip) > 0;
}

void ThreatIntelManager::add_ip_to_blacklist(const std::string& ip, uint32_t duration_hours, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    ip_blacklist_.insert(ip);
    stats_.total_ip_entries++;
    
    IPReputation rep;
    rep.ip = ip;
    rep.level = ReputationLevel::MALICIOUS;
    rep.threat_score = 100;
    rep.confidence = 100;
    rep.tags.push_back(reason);
    rep.last_seen = std::chrono::steady_clock::now();
    rep.expires_at = std::chrono::steady_clock::now() + std::chrono::hours(duration_hours);
    ip_reputations_[ip] = rep;
}

void ThreatIntelManager::add_ip_to_whitelist(const std::string& ip, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    ip_whitelist_.insert(ip);
    ip_blacklist_.erase(ip);
    
    IPReputation rep;
    rep.ip = ip;
    rep.level = ReputationLevel::TRUSTED;
    rep.threat_score = 0;
    rep.confidence = 100;
    rep.tags.push_back(reason);
    ip_reputations_[ip] = rep;
}

void ThreatIntelManager::remove_ip_from_blacklist(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    ip_blacklist_.erase(ip);
    ip_reputations_.erase(ip);
}

void ThreatIntelManager::add_cidr_to_blacklist(const std::string& cidr, uint32_t duration_hours, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    CIDREntry entry;
    entry.range = utils::IPUtils::parse_cidr(cidr);
    entry.duration_hours = duration_hours;
    entry.added_at = std::chrono::steady_clock::now();
    entry.reason = reason;
    cidr_blacklist_.push_back(entry);
}

void ThreatIntelManager::remove_cidr_from_blacklist(const std::string& cidr) {
    std::lock_guard<std::mutex> lock(mutex_);
    utils::CIDRRange target = utils::IPUtils::parse_cidr(cidr);
    cidr_blacklist_.erase(
        std::remove_if(cidr_blacklist_.begin(), cidr_blacklist_.end(),
            [&target](const CIDREntry& e) {
                return e.range.network == target.network && e.range.prefix == target.prefix;
            }),
        cidr_blacklist_.end()
    );
}

bool ThreatIntelManager::is_ip_in_blacklisted_cidr(const std::string& ip) const {
    auto now = std::chrono::steady_clock::now();
    for (const auto& entry : cidr_blacklist_) {
        if (entry.duration_hours > 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::hours>(now - entry.added_at).count();
            if (static_cast<uint32_t>(elapsed) > entry.duration_hours) continue;
        }
        if (utils::IPUtils::is_ip_in_cidr(ip, entry.range)) {
            return true;
        }
    }
    return false;
}

std::vector<std::string> ThreatIntelManager::get_blacklisted_cidrs() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (const auto& entry : cidr_blacklist_) {
        result.push_back(utils::IPUtils::int_to_ip(entry.range.network) + "/" + std::to_string(entry.range.prefix));
    }
    return result;
}

void ThreatIntelManager::add_domain_to_blacklist(const std::string& domain, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    domain_blacklist_.insert(domain);
    stats_.total_domain_entries++;
    
    DomainReputation rep;
    rep.domain = domain;
    rep.level = ReputationLevel::MALICIOUS;
    rep.threat_score = 100;
    rep.tags.push_back(reason);
    domain_reputations_[domain] = rep;
}

void ThreatIntelManager::remove_domain_from_blacklist(const std::string& domain) {
    std::lock_guard<std::mutex> lock(mutex_);
    domain_blacklist_.erase(domain);
    domain_reputations_.erase(domain);
}

std::vector<std::string> ThreatIntelManager::get_blacklisted_ips() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::vector<std::string>(ip_blacklist_.begin(), ip_blacklist_.end());
}

std::vector<std::string> ThreatIntelManager::get_blacklisted_domains() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::vector<std::string>(domain_blacklist_.begin(), domain_blacklist_.end());
}

void ThreatIntelManager::add_attack_pattern(const AttackPattern& pattern) {
    std::lock_guard<std::mutex> lock(mutex_);
    attack_patterns_.push_back(pattern);
}

std::vector<AttackPattern> ThreatIntelManager::get_attack_patterns() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return attack_patterns_;
}

void ThreatIntelManager::add_indicator(const ThreatIndicator& indicator) {
    std::lock_guard<std::mutex> lock(mutex_);
    indicators_.push_back(indicator);
    stats_.total_indicators++;
}

std::vector<ThreatIndicator> ThreatIntelManager::get_indicators(const std::string& type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (type.empty()) return indicators_;
    
    std::vector<ThreatIndicator> result;
    for (const auto& ind : indicators_) {
        if (ind.type == type) {
            result.push_back(ind);
        }
    }
    return result;
}

bool ThreatIntelManager::check_indicator(const std::string& type, const std::string& value) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& ind : indicators_) {
        if (ind.type == type && ind.value == value) {
            return true;
        }
    }
    return false;
}

void ThreatIntelManager::set_auto_block_enabled(bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto_block_enabled_ = enable;
}

void ThreatIntelManager::set_reputation_threshold(uint32_t threshold) {
    std::lock_guard<std::mutex> lock(mutex_);
    reputation_threshold_ = threshold;
}

void ThreatIntelManager::load_local_database(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
}

void ThreatIntelManager::save_local_database(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
}

ThreatIntelManager::Stats ThreatIntelManager::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void ThreatIntelManager::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = Stats{};
}

std::string ThreatIntelManager::export_intel_json() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream oss;
    
    oss << "{\"ip_blacklist\":[";
    bool first = true;
    for (const auto& ip : ip_blacklist_) {
        if (!first) oss << ",";
        first = false;
        oss << "\"" << ip << "\"";
    }
    oss << "],\"domain_blacklist\":[";
    
    first = true;
    for (const auto& domain : domain_blacklist_) {
        if (!first) oss << ",";
        first = false;
        oss << "\"" << domain << "\"";
    }
    oss << "],\"indicators\":" << indicators_.size() << "}";
    
    return oss.str();
}

bool ThreatIntelManager::import_intel_json(const std::string& json) {
    return true;
}

void ThreatIntelManager::feed_update_loop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::minutes(5));
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto now = std::chrono::steady_clock::now();
        for (auto& feed : feeds_) {
            if (feed.enabled) {
                auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(
                    now - feed.last_updated
                ).count();
                
                if (elapsed >= feed.update_interval_minutes) {
                    feed.last_updated = now;
                    stats_.last_feed_update = now;
                }
            }
        }
    }
}

bool ThreatIntelManager::fetch_feed(const ThreatFeed& feed, std::vector<std::string>& entries) {
    return true;
}

void ThreatIntelManager::parse_ip_feed(const std::vector<std::string>& entries) {
    for (const auto& entry : entries) {
        if (!entry.empty() && entry[0] != '#') {
            if (entry.find('/') != std::string::npos) {
                add_cidr_to_blacklist(entry, 24, "feed");
            } else {
                ip_blacklist_.insert(entry);
                stats_.total_ip_entries++;
            }
        }
    }
}

void ThreatIntelManager::parse_domain_feed(const std::vector<std::string>& entries) {
    for (const auto& entry : entries) {
        if (!entry.empty() && entry[0] != '#') {
            domain_blacklist_.insert(entry);
            stats_.total_domain_entries++;
        }
    }
}

} // namespace intel
} // namespace antiddos