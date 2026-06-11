#ifndef ASN_DATABASE_H
#define ASN_DATABASE_H

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>
#include <mutex>
#include <fstream>

namespace antiddos {
namespace asn {

struct ASNInfo {
    uint32_t asn;
    std::string name;
    std::string country;
    std::vector<std::string> prefixes;
    std::vector<std::string> domains;
    bool is_vpn_provider;
    bool is_datacenter;
    bool is_hosting;
    uint32_t threat_score;
};

struct IPRange {
    uint32_t start_ip;
    uint32_t end_ip;
    uint32_t asn;
    std::string prefix;
};

struct VPNProvider {
    std::string name;
    std::vector<uint32_t> asns;
    std::vector<std::string> prefixes;
    std::vector<std::string> domains;
    uint32_t threat_score;
    std::string country;
};

class ASNDatabase {
public:
    ASNDatabase();
    ~ASNDatabase();
    
    bool load_from_file(const std::string& path);
    bool save_to_file(const std::string& path) const;
    
    bool load_csv(const std::string& path);
    bool load_binnary(const std::string& path);
    
    uint32_t lookup_ip(const std::string& ip) const;
    std::string get_asn_name(uint32_t asn) const;
    ASNInfo get_asn_info(uint32_t asn) const;
    
    bool is_vpn_provider(uint32_t asn) const;
    bool is_vpn_provider_ip(const std::string& ip) const;
    bool is_datacenter(uint32_t asn) const;
    bool is_datacenter_ip(const std::string& ip) const;
    
    void add_vpn_provider(const VPNProvider& provider);
    void remove_vpn_provider(const std::string& name);
    std::vector<VPNProvider> get_vpn_providers() const;
    
    void block_asn(uint32_t asn, const std::string& reason = "");
    void unblock_asn(uint32_t asn);
    bool is_asn_blocked(uint32_t asn) const;
    bool is_ip_in_blocked_asn(const std::string& ip) const;
    std::vector<uint32_t> get_blocked_asns() const;
    
    void block_vpn_providers(bool enable);
    void block_datacenters(bool enable);
    
    void add_ip_range(uint32_t start, uint32_t end, uint32_t asn, const std::string& prefix);
    bool is_ip_in_range(const std::string& ip) const;
    
    struct Stats {
        uint64_t total_lookups;
        uint64_t vpn_detections;
        uint64_t datacenter_detections;
        uint32_t total_asns;
        uint32_t total_ip_ranges;
        uint32_t total_vpn_providers;
        uint32_t blocked_asn_count;
    };
    
    Stats get_stats() const;
    void reset_stats();
    
    static std::string asn_to_string(uint32_t asn);
    static uint32_t string_to_asn(const std::string& asn_str);
    static std::vector<std::string> get_common_vpn_asns();
    
private:
    struct TrieNode {
        std::unordered_map<uint8_t, std::shared_ptr<TrieNode>> children;
        uint32_t asn = 0;
        bool is_end = false;
    };
    
    mutable std::mutex mutex_;
    
    std::unordered_map<uint32_t, ASNInfo> asn_database_;
    std::unordered_map<std::string, uint32_t> ip_to_asn_;
    std::vector<IPRange> ip_ranges_;
    std::vector<VPNProvider> vpn_providers_;
    std::unordered_set<uint32_t> blocked_asns_;
    
    bool block_vpn_providers_ = false;
    bool block_datacenters_ = false;
    
    mutable Stats stats_;
    
    void build_ip_index();
    uint32_t ip_to_int(const std::string& ip) const;
    std::string int_to_ip(uint32_t ip_int) const;
    
    bool load_default_vpn_providers();
};

} // namespace asn
} // namespace antiddos

#endif // ASN_DATABASE_H
