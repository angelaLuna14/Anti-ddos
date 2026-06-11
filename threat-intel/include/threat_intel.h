#ifndef THREAT_INTEL_H
#define THREAT_INTEL_H

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
#include "utils.h"

namespace antiddos {
namespace intel {

enum class FeedType {
    IP_BLACKLIST,
    IP_WHITELIST,
    DOMAIN_BLACKLIST,
    URL_BLACKLIST,
    HASH_MALWARE,
    CIDR_BLOCKLIST,
    ASN_BLOCKLIST,
    VULNERABILITY,
    ATTACK_PATTERN,
    CUSTOM
};

enum class ReputationLevel {
    UNKNOWN,
    TRUSTED,
    LOW_RISK,
    MEDIUM_RISK,
    HIGH_RISK,
    MALICIOUS
};

struct ThreatFeed {
    std::string name;
    std::string url;
    FeedType type;
    uint32_t update_interval_minutes;
    std::chrono::steady_clock::time_point last_updated;
    bool enabled;
    std::string api_key;
    uint32_t priority;
};

struct IPReputation {
    std::string ip;
    ReputationLevel level;
    uint32_t threat_score;
    uint32_t confidence;
    std::vector<std::string> tags;
    std::string country;
    std::string asn;
    std::string isp;
    bool is_proxy;
    bool is_vpn;
    bool is_tor;
    bool is_datacenter;
    std::chrono::steady_clock::time_point last_seen;
    std::chrono::steady_clock::time_point expires_at;
};

struct DomainReputation {
    std::string domain;
    ReputationLevel level;
    uint32_t threat_score;
    std::vector<std::string> tags;
    std::string category;
    bool is_phishing;
    bool is_malware;
    bool is_c2;
    std::chrono::steady_clock::time_point last_checked;
};

struct AttackPattern {
    std::string id;
    std::string name;
    std::string description;
    std::vector<std::string> indicators;
    std::string mitre_id;
    uint32_t severity;
    std::vector<std::string> ttps;
};

struct ThreatIndicator {
    std::string type;
    std::string value;
    ReputationLevel level;
    uint32_t confidence;
    std::string source;
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
};

using FeedUpdateCallback = std::function<void(const std::string& feed_name, uint32_t entries_added, uint32_t entries_updated)>;

class ThreatIntelManager {
public:
    ThreatIntelManager();
    ~ThreatIntelManager();
    
    bool add_feed(const ThreatFeed& feed);
    bool remove_feed(const std::string& feed_name);
    bool update_feed(const std::string& feed_name);
    bool update_all_feeds();
    
    void set_feed_callback(FeedUpdateCallback callback);
    
    IPReputation get_ip_reputation(const std::string& ip) const;
    DomainReputation get_domain_reputation(const std::string& domain) const;
    
    bool is_ip_malicious(const std::string& ip) const;
    bool is_domain_malicious(const std::string& domain) const;
    bool is_ip_whitelisted(const std::string& ip) const;
    
    void add_ip_to_blacklist(const std::string& ip, uint32_t duration_hours, const std::string& reason);
    void add_ip_to_whitelist(const std::string& ip, const std::string& reason);
    void remove_ip_from_blacklist(const std::string& ip);
    
    void add_cidr_to_blacklist(const std::string& cidr, uint32_t duration_hours, const std::string& reason);
    void remove_cidr_from_blacklist(const std::string& cidr);
    bool is_ip_in_blacklisted_cidr(const std::string& ip) const;
    std::vector<std::string> get_blacklisted_cidrs() const;
    
    void add_domain_to_blacklist(const std::string& domain, const std::string& reason);
    void remove_domain_from_blacklist(const std::string& domain);
    
    std::vector<std::string> get_blacklisted_ips() const;
    std::vector<std::string> get_blacklisted_domains() const;
    
    void add_attack_pattern(const AttackPattern& pattern);
    std::vector<AttackPattern> get_attack_patterns() const;
    
    void add_indicator(const ThreatIndicator& indicator);
    std::vector<ThreatIndicator> get_indicators(const std::string& type = "") const;
    
    bool check_indicator(const std::string& type, const std::string& value) const;
    
    void set_auto_block_enabled(bool enable);
    void set_reputation_threshold(uint32_t threshold);
    
    void load_local_database(const std::string& path);
    void save_local_database(const std::string& path);
    
    struct Stats {
        uint64_t total_queries;
        uint64_t malicious_detections;
        uint64_t whitelist_hits;
        uint32_t active_feeds;
        uint32_t total_ip_entries;
        uint32_t total_domain_entries;
        uint32_t total_indicators;
        std::chrono::steady_clock::time_point last_feed_update;
    };
    
    Stats get_stats() const;
    void reset_stats();
    
    std::string export_intel_json() const;
    bool import_intel_json(const std::string& json);
    
private:
    void feed_update_loop();
    bool fetch_feed(const ThreatFeed& feed, std::vector<std::string>& entries);
    
    void parse_ip_feed(const std::vector<std::string>& entries);
    void parse_domain_feed(const std::vector<std::string>& entries);
    
    mutable std::mutex mutex_;
    
    std::vector<ThreatFeed> feeds_;
    std::unordered_map<std::string, IPReputation> ip_reputations_;
    std::unordered_map<std::string, DomainReputation> domain_reputations_;
    std::unordered_set<std::string> ip_blacklist_;
    std::unordered_set<std::string> ip_whitelist_;
    std::unordered_set<std::string> domain_blacklist_;
    
    struct CIDREntry {
        utils::CIDRRange range;
        uint32_t duration_hours;
        std::chrono::steady_clock::time_point added_at;
        std::string reason;
    };
    std::vector<CIDREntry> cidr_blacklist_;
    std::vector<AttackPattern> attack_patterns_;
    std::vector<ThreatIndicator> indicators_;
    
    bool auto_block_enabled_ = true;
    uint32_t reputation_threshold_ = 70;
    
    Stats stats_;
    FeedUpdateCallback callback_;
    
    std::atomic<bool> running_{false};
    std::thread update_thread_;
};

} // namespace intel
} // namespace antiddos

#endif // THREAT_INTEL_H