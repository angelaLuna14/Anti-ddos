#ifndef GEO_BLOCKER_H
#define GEO_BLOCKER_H

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <mutex>

namespace antiddos {

struct GeoLocation {
    std::string ip;
    std::string country_code;
    std::string country_name;
    std::string city;
    std::string region;
    double latitude;
    double longitude;
    uint32_t asn;
    std::string isp;
    bool is_datacenter;
    bool is_proxy;
    bool is_tor;
    bool is_vpn;
};

struct GeoRule {
    std::string name;
    std::unordered_set<std::string> allowed_countries;
    std::unordered_set<std::string> blocked_countries;
    std::unordered_set<std::string> allowed_asns;
    std::unordered_set<std::string> blocked_asns;
    std::unordered_set<std::string> custom_whitelist_;
    std::unordered_set<std::string> custom_blacklist_;
    bool block_datacenters = false;
    bool block_proxies = false;
    bool block_tor = false;
    bool block_vpn = false;
    bool enabled = true;
    
    bool is_allowed(const GeoLocation& geo) const;
};

class GeoBlocker {
public:
    GeoBlocker();
    ~GeoBlocker();
    
    bool init_database(const std::string& db_path);
    bool init_from_csv(const std::string& csv_path);
    
    GeoLocation lookup(const std::string& ip) const;
    bool is_blocked(const std::string& ip) const;
    bool is_allowed(const std::string& ip) const;
    
    void add_rule(const GeoRule& rule);
    void remove_rule(const std::string& rule_name);
    void enable_rule(const std::string& rule_name, bool enable);
    
    void add_allowed_country(const std::string& rule_name, const std::string& country_code);
    void add_blocked_country(const std::string& rule_name, const std::string& country_code);
    
    void add_allowed_asn(const std::string& rule_name, const std::string& asn);
    void add_blocked_asn(const std::string& rule_name, const std::string& asn);
    
    void set_block_datacenters(const std::string& rule_name, bool block);
    void set_block_proxies(const std::string& rule_name, bool block);
    void set_block_tor(const std::string& rule_name, bool block);
    void set_block_vpn(const std::string& rule_name, bool block);
    
    std::vector<std::string> get_blocked_countries() const;
    std::vector<std::string> get_allowed_countries() const;
    std::vector<std::string> get_blocked_asns() const;
    
    void load_custom_blacklist(const std::string& filepath);
    void load_custom_whitelist(const std::string& filepath);
    void add_to_blacklist(const std::string& ip);
    void add_to_whitelist(const std::string& ip);
    
    struct Stats {
        uint64_t total_lookups = 0;
        uint64_t blocked_count = 0;
        uint64_t allowed_count = 0;
        std::unordered_map<std::string, uint64_t> country_blocks;
        std::unordered_map<std::string, uint64_t> asn_blocks;
    };
    
    Stats get_stats() const;
    void reset_stats();
    
private:
    mutable std::mutex mutex_;
    
    std::unordered_map<std::string, GeoLocation> geo_cache_;
    std::unordered_map<std::string, GeoRule> rules_;
    std::unordered_set<std::string> custom_blacklist_;
    std::unordered_set<std::string> custom_whitelist_;
    
    mutable Stats stats_;
    
    GeoLocation parse_csv_line(const std::string& line) const;
    bool check_rules(const GeoLocation& geo) const;
};

} // namespace antiddos

#endif // GEO_BLOCKER_H