#include "geo_blocker.h"
#include <fstream>
#include <sstream>
#include <algorithm>

namespace antiddos {

bool GeoRule::is_allowed(const GeoLocation& geo) const {
    if (!enabled) return true;
    
    if (custom_whitelist_.count(geo.ip)) return true;
    
    if (custom_blacklist_.count(geo.ip)) return false;
    
    if (block_datacenters && geo.is_datacenter) return false;
    if (block_proxies && geo.is_proxy) return false;
    if (block_tor && geo.is_tor) return false;
    if (block_vpn && geo.is_vpn) return false;
    
    if (!blocked_countries.empty()) {
        if (blocked_countries.count(geo.country_code)) return false;
    }
    
    if (!allowed_countries.empty()) {
        if (!allowed_countries.count(geo.country_code)) return false;
    }
    
    if (!blocked_asns.empty()) {
        std::string asn_str = std::to_string(geo.asn);
        if (blocked_asns.count(asn_str)) return false;
    }
    
    if (!allowed_asns.empty()) {
        std::string asn_str = std::to_string(geo.asn);
        if (!allowed_asns.count(asn_str)) return false;
    }
    
    return true;
}

GeoBlocker::GeoBlocker() = default;
GeoBlocker::~GeoBlocker() = default;

bool GeoBlocker::init_database(const std::string& db_path) {
    std::ifstream file(db_path);
    if (!file.is_open()) return false;
    
    std::string line;
    bool is_header = true;
    
    while (std::getline(file, line)) {
        if (is_header) {
            is_header = false;
            continue;
        }
        
        if (!line.empty()) {
            GeoLocation geo = parse_csv_line(line);
            if (!geo.ip.empty()) {
                geo_cache_[geo.ip] = geo;
            }
        }
    }
    
    return true;
}

bool GeoBlocker::init_from_csv(const std::string& csv_path) {
    return init_database(csv_path);
}

GeoLocation GeoBlocker::lookup(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = geo_cache_.find(ip);
    if (it != geo_cache_.end()) {
        return it->second;
    }
    
    return GeoLocation{};
}

bool GeoBlocker::is_blocked(const std::string& ip) const {
    return !is_allowed(ip);
}

bool GeoBlocker::is_allowed(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    stats_.total_lookups++;
    
    if (custom_whitelist_.count(ip)) {
        stats_.allowed_count++;
        return true;
    }
    
    if (custom_blacklist_.count(ip)) {
        stats_.blocked_count++;
        return false;
    }
    
    auto it = geo_cache_.find(ip);
    if (it == geo_cache_.end()) {
        stats_.allowed_count++;
        return true;
    }
    
    bool allowed = check_rules(it->second);
    
    if (allowed) {
        stats_.allowed_count++;
    } else {
        stats_.blocked_count++;
        stats_.country_blocks[it->second.country_code]++;
    }
    
    return allowed;
}

bool GeoBlocker::check_rules(const GeoLocation& geo) const {
    for (const auto& [name, rule] : rules_) {
        if (!rule.is_allowed(geo)) {
            return false;
        }
    }
    return true;
}

void GeoBlocker::add_rule(const GeoRule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);
    rules_[rule.name] = rule;
}

void GeoBlocker::remove_rule(const std::string& rule_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    rules_.erase(rule_name);
}

void GeoBlocker::enable_rule(const std::string& rule_name, bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = rules_.find(rule_name);
    if (it != rules_.end()) {
        it->second.enabled = enable;
    }
}

void GeoBlocker::add_allowed_country(const std::string& rule_name, const std::string& country_code) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = rules_.find(rule_name);
    if (it != rules_.end()) {
        it->second.allowed_countries.insert(country_code);
    }
}

void GeoBlocker::add_blocked_country(const std::string& rule_name, const std::string& country_code) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = rules_.find(rule_name);
    if (it != rules_.end()) {
        it->second.blocked_countries.insert(country_code);
    }
}

void GeoBlocker::add_allowed_asn(const std::string& rule_name, const std::string& asn) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = rules_.find(rule_name);
    if (it != rules_.end()) {
        it->second.allowed_asns.insert(asn);
    }
}

void GeoBlocker::add_blocked_asn(const std::string& rule_name, const std::string& asn) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = rules_.find(rule_name);
    if (it != rules_.end()) {
        it->second.blocked_asns.insert(asn);
    }
}

void GeoBlocker::set_block_datacenters(const std::string& rule_name, bool block) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = rules_.find(rule_name);
    if (it != rules_.end()) {
        it->second.block_datacenters = block;
    }
}

void GeoBlocker::set_block_proxies(const std::string& rule_name, bool block) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = rules_.find(rule_name);
    if (it != rules_.end()) {
        it->second.block_proxies = block;
    }
}

void GeoBlocker::set_block_tor(const std::string& rule_name, bool block) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = rules_.find(rule_name);
    if (it != rules_.end()) {
        it->second.block_tor = block;
    }
}

void GeoBlocker::set_block_vpn(const std::string& rule_name, bool block) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = rules_.find(rule_name);
    if (it != rules_.end()) {
        it->second.block_vpn = block;
    }
}

std::vector<std::string> GeoBlocker::get_blocked_countries() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::unordered_set<std::string> countries;
    
    for (const auto& [name, rule] : rules_) {
        for (const auto& country : rule.blocked_countries) {
            countries.insert(country);
        }
    }
    
    return std::vector<std::string>(countries.begin(), countries.end());
}

std::vector<std::string> GeoBlocker::get_allowed_countries() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::unordered_set<std::string> countries;
    
    for (const auto& [name, rule] : rules_) {
        for (const auto& country : rule.allowed_countries) {
            countries.insert(country);
        }
    }
    
    return std::vector<std::string>(countries.begin(), countries.end());
}

std::vector<std::string> GeoBlocker::get_blocked_asns() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::unordered_set<std::string> asns;
    
    for (const auto& [name, rule] : rules_) {
        for (const auto& asn : rule.blocked_asns) {
            asns.insert(asn);
        }
    }
    
    return std::vector<std::string>(asns.begin(), asns.end());
}

void GeoBlocker::load_custom_blacklist(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ifstream file(filepath);
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line[0] != '#') {
            custom_blacklist_.insert(line);
        }
    }
}

void GeoBlocker::load_custom_whitelist(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ifstream file(filepath);
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line[0] != '#') {
            custom_whitelist_.insert(line);
        }
    }
}

void GeoBlocker::add_to_blacklist(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    custom_blacklist_.insert(ip);
}

void GeoBlocker::add_to_whitelist(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    custom_whitelist_.insert(ip);
}

GeoBlocker::Stats GeoBlocker::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void GeoBlocker::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = Stats{};
}

GeoLocation GeoBlocker::parse_csv_line(const std::string& line) const {
    GeoLocation geo;
    std::istringstream iss(line);
    std::string token;
    std::vector<std::string> tokens;
    
    while (std::getline(iss, token, ',')) {
        token.erase(0, token.find_first_not_of(" \t"));
        token.erase(token.find_last_not_of(" \t") + 1);
        tokens.push_back(token);
    }
    
    if (tokens.size() >= 6) {
        geo.ip = tokens[0];
        geo.country_code = tokens[1];
        geo.country_name = tokens[2];
        geo.city = tokens[3];
        geo.region = tokens[4];
        geo.asn = std::stoul(tokens[5]);
        
        if (tokens.size() >= 7) geo.isp = tokens[6];
        if (tokens.size() >= 8) geo.is_datacenter = (tokens[7] == "1" || tokens[7] == "true");
        if (tokens.size() >= 9) geo.is_proxy = (tokens[8] == "1" || tokens[8] == "true");
        if (tokens.size() >= 10) geo.is_tor = (tokens[9] == "1" || tokens[9] == "true");
        if (tokens.size() >= 11) geo.is_vpn = (tokens[10] == "1" || tokens[10] == "true");
    }
    
    return geo;
}

} // namespace antiddos