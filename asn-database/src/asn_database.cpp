#include "asn_database.h"
#include <sstream>
#include <algorithm>
#include <cstring>

namespace antiddos {
namespace asn {

ASNDatabase::ASNDatabase() {
    stats_ = {0, 0, 0, 0, 0, 0, 0};
    load_default_vpn_providers();
}

ASNDatabase::~ASNDatabase() = default;

bool ASNDatabase::load_default_vpn_providers() {
    std::vector<VPNProvider> defaults = {
        {"NordVPN", {57043, 57652, 212584, 209921, 213234}, {}, {"nordvpn.com"}, 60, "PA"},
        {"ExpressVPN", {35995, 204118}, {}, {"expressvpn.com"}, 55, "VG"},
        {"Surfshark", {44402, 49544}, {}, {"surfshark.com"}, 55, "NL"},
        {"Mullvad", {33303, 57314, 206843}, {}, {"mullvad.net"}, 40, "SE"},
        {"ProtonVPN", {62092, 57589, 34549}, {}, {"protonvpn.com"}, 45, "CH"},
        {"CyberGhost", {44402, 49544}, {}, {"cyberghostvpn.com"}, 55, "RO"},
        {"PIA", {62092, 33303}, {}, {"privateinternetaccess.com"}, 55, "US"},
        {"Hotspot Shield", {35995, 57652}, {}, {"hotspotshield.com"}, 55, "US"},
        {"Windscribe", {36149, 57314}, {}, {"windscribe.com"}, 45, "CA"},
        {"IVPN", {36149, 57314}, {}, {"ivpn.net"}, 40, "MT"},
        {"HideMyAss", {44402, 49544}, {}, {"hidemyass.com"}, 60, "GB"},
        {"PureVPN", {36149, 44402}, {}, {"purevpn.com"}, 60, "HK"},
        {"IPVanish", {36149, 57314}, {}, {"ipvanish.com"}, 55, "US"},
        {"StrongVPN", {36149, 57314}, {}, {"strongvpn.com"}, 55, "US"},
        {"TunnelBear", {57314, 36149}, {}, {"tunnelbear.com"}, 45, "CA"},
    };
    
    vpn_providers_ = defaults;
    stats_.total_vpn_providers = vpn_providers_.size();
    
    return true;
}

bool ASNDatabase::load_from_file(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ifstream file(path);
    if (!file.is_open()) return false;
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        
        std::istringstream iss(line);
        std::string token;
        std::vector<std::string> tokens;
        
        while (std::getline(iss, token, ',')) {
            tokens.push_back(token);
        }
        
        if (tokens.size() >= 2) {
            ASNInfo info;
            info.asn = std::stoul(tokens[0]);
            info.name = tokens[1];
            if (tokens.size() >= 3) info.country = tokens[2];
            
            asn_database_[info.asn] = info;
            stats_.total_asns++;
        }
    }
    
    build_ip_index();
    return true;
}

bool ASNDatabase::save_to_file(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ofstream file(path);
    if (!file.is_open()) return false;
    
    file << "# ASN,Name,Country" << std::endl;
    
    for (const auto& [asn, info] : asn_database_) {
        file << asn << "," << info.name << "," << info.country << std::endl;
    }
    
    return true;
}

bool ASNDatabase::load_csv(const std::string& path) {
    return load_from_file(path);
}

bool ASNDatabase::load_binnary(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    
    uint32_t count;
    file.read(reinterpret_cast<char*>(&count), sizeof(count));
    
    for (uint32_t i = 0; i < count; i++) {
        IPRange range;
        file.read(reinterpret_cast<char*>(&range.start_ip), sizeof(range.start_ip));
        file.read(reinterpret_cast<char*>(&range.end_ip), sizeof(range.end_ip));
        file.read(reinterpret_cast<char*>(&range.asn), sizeof(range.asn));
        ip_ranges_.push_back(range);
    }
    
    stats_.total_ip_ranges = ip_ranges_.size();
    return true;
}

uint32_t ASNDatabase::lookup_ip(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.total_lookups++;
    
    auto it = ip_to_asn_.find(ip);
    if (it != ip_to_asn_.end()) {
        return it->second;
    }
    
    uint32_t ip_int = ip_to_int(ip);
    
    for (const auto& range : ip_ranges_) {
        if (ip_int >= range.start_ip && ip_int <= range.end_ip) {
            return range.asn;
        }
    }
    
    return 0;
}

std::string ASNDatabase::get_asn_name(uint32_t asn) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = asn_database_.find(asn);
    return (it != asn_database_.end()) ? it->second.name : "Unknown";
}

ASNInfo ASNDatabase::get_asn_info(uint32_t asn) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = asn_database_.find(asn);
    if (it != asn_database_.end()) {
        return it->second;
    }
    return {asn, "Unknown", "", {}, {}, false, false, false, 0};
}

bool ASNDatabase::is_vpn_provider(uint32_t asn) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& provider : vpn_providers_) {
        for (uint32_t provider_asn : provider.asns) {
            if (provider_asn == asn) {
                return true;
            }
        }
    }
    return false;
}

bool ASNDatabase::is_vpn_provider_ip(const std::string& ip) const {
    uint32_t asn = lookup_ip(ip);
    if (asn == 0) return false;
    
    bool result = is_vpn_provider(asn);
    if (result) {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_.vpn_detections++;
    }
    return result;
}

bool ASNDatabase::is_datacenter(uint32_t asn) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = asn_database_.find(asn);
    if (it != asn_database_.end()) {
        return it->second.is_datacenter || it->second.is_hosting;
    }
    return false;
}

bool ASNDatabase::is_datacenter_ip(const std::string& ip) const {
    uint32_t asn = lookup_ip(ip);
    if (asn == 0) return false;
    
    bool result = is_datacenter(asn);
    if (result) {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_.datacenter_detections++;
    }
    return result;
}

void ASNDatabase::add_vpn_provider(const VPNProvider& provider) {
    std::lock_guard<std::mutex> lock(mutex_);
    vpn_providers_.push_back(provider);
    stats_.total_vpn_providers = vpn_providers_.size();
}

void ASNDatabase::remove_vpn_provider(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    vpn_providers_.erase(
        std::remove_if(vpn_providers_.begin(), vpn_providers_.end(),
            [&name](const VPNProvider& p) { return p.name == name; }),
        vpn_providers_.end()
    );
    stats_.total_vpn_providers = vpn_providers_.size();
}

std::vector<VPNProvider> ASNDatabase::get_vpn_providers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return vpn_providers_;
}

void ASNDatabase::block_asn(uint32_t asn, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    blocked_asns_.insert(asn);
    stats_.blocked_asn_count = blocked_asns_.size();
    
    auto it = asn_database_.find(asn);
    if (it != asn_database_.end()) {
        it->second.threat_score = 100;
    }
}

void ASNDatabase::unblock_asn(uint32_t asn) {
    std::lock_guard<std::mutex> lock(mutex_);
    blocked_asns_.erase(asn);
    stats_.blocked_asn_count = blocked_asns_.size();
}

bool ASNDatabase::is_asn_blocked(uint32_t asn) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return blocked_asns_.count(asn) > 0;
}

bool ASNDatabase::is_ip_in_blocked_asn(const std::string& ip) const {
    uint32_t asn = lookup_ip(ip);
    return is_asn_blocked(asn);
}

std::vector<uint32_t> ASNDatabase::get_blocked_asns() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::vector<uint32_t>(blocked_asns_.begin(), blocked_asns_.end());
}

void ASNDatabase::block_vpn_providers(bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);
    block_vpn_providers_ = enable;
    
    if (enable) {
        for (const auto& provider : vpn_providers_) {
            for (uint32_t asn : provider.asns) {
                blocked_asns_.insert(asn);
            }
        }
    }
}

void ASNDatabase::block_datacenters(bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);
    block_datacenters_ = enable;
    
    if (enable) {
        for (auto& [asn, info] : asn_database_) {
            if (info.is_datacenter || info.is_hosting) {
                blocked_asns_.insert(asn);
            }
        }
    }
}

void ASNDatabase::add_ip_range(uint32_t start, uint32_t end, uint32_t asn, const std::string& prefix) {
    std::lock_guard<std::mutex> lock(mutex_);
    ip_ranges_.push_back({start, end, asn, prefix});
    stats_.total_ip_ranges = ip_ranges_.size();
}

bool ASNDatabase::is_ip_in_range(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t ip_int = ip_to_int(ip);
    
    for (const auto& range : ip_ranges_) {
        if (ip_int >= range.start_ip && ip_int <= range.end_ip) {
            return true;
        }
    }
    return false;
}

ASNDatabase::Stats ASNDatabase::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void ASNDatabase::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = {0, 0, 0, 0, 0, 0, 0};
}

std::string ASNDatabase::asn_to_string(uint32_t asn) {
    return "AS" + std::to_string(asn);
}

uint32_t ASNDatabase::string_to_asn(const std::string& asn_str) {
    std::string num = asn_str;
    if (num.substr(0, 2) == "AS" || num.substr(0, 2) == "as") {
        num = num.substr(2);
    }
    return std::stoul(num);
}

std::vector<std::string> ASNDatabase::get_common_vpn_asns() {
    return {
        "AS57043", "AS57652", "AS212584", "AS209921", "AS213234",
        "AS35995", "AS204118", "AS44402", "AS49544", "AS33303",
        "AS57314", "AS206843", "AS57589", "AS34549", "AS36149",
    };
}

void ASNDatabase::build_ip_index() {
    ip_to_asn_.clear();
    
    for (const auto& range : ip_ranges_) {
        uint32_t ip_count = range.end_ip - range.start_ip;
        if (ip_count > 10000) continue;
        
        for (uint32_t ip = range.start_ip; ip <= range.end_ip; ip++) {
            ip_to_asn_[int_to_ip(ip)] = range.asn;
        }
    }
    
    stats_.total_ip_ranges = ip_ranges_.size();
}

uint32_t ASNDatabase::ip_to_int(const std::string& ip) const {
    uint32_t result = 0;
    std::istringstream iss(ip);
    std::string segment;
    
    while (std::getline(iss, segment, '.')) {
        result = (result << 8) + std::stoi(segment);
    }
    return result;
}

std::string ASNDatabase::int_to_ip(uint32_t ip_int) const {
    std::ostringstream oss;
    oss << ((ip_int >> 24) & 0xFF) << "."
        << ((ip_int >> 16) & 0xFF) << "."
        << ((ip_int >> 8) & 0xFF) << "."
        << (ip_int & 0xFF);
    return oss.str();
}

} // namespace asn
} // namespace antiddos
