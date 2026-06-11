#include "utils.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <iomanip>
#include <cstring>
#include <unordered_map>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#define mkdir _mkdir
#else
#include <sys/stat.h>
#endif

namespace antiddos {
namespace utils {

bool IPUtils::is_valid_ip(const std::string& ip) {
    std::regex ipv4_regex(R"((\d{1,3}\.){3}\d{1,3})");
    if (!std::regex_match(ip, ipv4_regex)) return false;
    
    std::istringstream iss(ip);
    std::string segment;
    while (std::getline(iss, segment, '.')) {
        int num = std::stoi(segment);
        if (num < 0 || num > 255) return false;
    }
    return true;
}

bool IPUtils::is_private_ip(const std::string& ip) {
    uint32_t ip_int = ip_to_int(ip);
    
    if ((ip_int & 0xFF000000) == 0x0A000000) return true;
    if ((ip_int & 0xFFF00000) == 0xAC100000) return true;
    if ((ip_int & 0xFFFF0000) == 0xC0A80000) return true;
    if (ip_int == 0x7F000001) return true;
    
    return false;
}

bool IPUtils::is_loopback(const std::string& ip) {
    return ip == "127.0.0.1" || ip == "::1" || ip == "localhost";
}

std::string IPUtils::get_ip_class(const std::string& ip) {
    uint32_t ip_int = ip_to_int(ip);
    uint8_t first_octet = (ip_int >> 24) & 0xFF;
    
    if (first_octet >= 1 && first_octet <= 126) return "A";
    if (first_octet >= 128 && first_octet <= 191) return "B";
    if (first_octet >= 192 && first_octet <= 223) return "C";
    if (first_octet >= 224 && first_octet <= 239) return "D";
    return "E";
}

uint32_t IPUtils::ip_to_int(const std::string& ip) {
    uint32_t result = 0;
    std::istringstream iss(ip);
    std::string segment;
    
    while (std::getline(iss, segment, '.')) {
        result = (result << 8) + std::stoi(segment);
    }
    return result;
}

std::string IPUtils::int_to_ip(uint32_t ip_int) {
    std::ostringstream oss;
    oss << ((ip_int >> 24) & 0xFF) << "."
        << ((ip_int >> 16) & 0xFF) << "."
        << ((ip_int >> 8) & 0xFF) << "."
        << (ip_int & 0xFF);
    return oss.str();
}

std::string IPUtils::get_network_address(const std::string& ip, int cidr) {
    uint32_t ip_int = ip_to_int(ip);
    uint32_t mask = ~((1 << (32 - cidr)) - 1);
    return int_to_ip(ip_int & mask);
}

std::string IPUtils::get_broadcast_address(const std::string& ip, int cidr) {
    uint32_t ip_int = ip_to_int(ip);
    uint32_t mask = ~((1 << (32 - cidr)) - 1);
    return int_to_ip(ip_int | ~mask);
}

CIDRRange IPUtils::parse_cidr(const std::string& cidr) {
    CIDRRange range = {0, 0, 0};
    size_t slash = cidr.find('/');
    if (slash == std::string::npos) {
        range.network = ip_to_int(cidr);
        range.prefix = 32;
        range.mask = 0xFFFFFFFF;
        return range;
    }
    
    std::string ip_part = cidr.substr(0, slash);
    int prefix = std::stoi(cidr.substr(slash + 1));
    
    if (prefix < 0) prefix = 0;
    if (prefix > 32) prefix = 32;
    
    range.network = ip_to_int(ip_part);
    range.prefix = prefix;
    range.mask = (prefix == 0) ? 0 : ~((1U << (32 - prefix)) - 1);
    range.network &= range.mask;
    
    return range;
}

bool IPUtils::is_ip_in_cidr(const std::string& ip, const std::string& cidr) {
    CIDRRange range = parse_cidr(cidr);
    return is_ip_in_cidr(ip, range);
}

bool IPUtils::is_ip_in_cidr(const std::string& ip, const CIDRRange& range) {
    if (!is_valid_ip(ip)) return false;
    uint32_t ip_int = ip_to_int(ip);
    return (ip_int & range.mask) == range.network;
}

bool IPUtils::do_ips_share_subnet(const std::string& ip1, const std::string& ip2, int prefix) {
    if (!is_valid_ip(ip1) || !is_valid_ip(ip2)) return false;
    uint32_t mask = (prefix == 0) ? 0 : ~((1U << (32 - prefix)) - 1);
    uint32_t ip1_int = ip_to_int(ip1);
    uint32_t ip2_int = ip_to_int(ip2);
    return (ip1_int & mask) == (ip2_int & mask);
}

std::string IPUtils::get_subnet_key(const std::string& ip, int prefix) {
    uint32_t ip_int = ip_to_int(ip);
    uint32_t mask = (prefix == 0) ? 0 : ~((1U << (32 - prefix)) - 1);
    return int_to_ip(ip_int & mask) + "/" + std::to_string(prefix);
}

std::vector<std::string> IPUtils::expand_cidr(const std::string& cidr, uint32_t max_ips) {
    std::vector<std::string> result;
    CIDRRange range = parse_cidr(cidr);
    
    if (range.prefix >= 32) {
        result.push_back(int_to_ip(range.network));
        return result;
    }
    
    uint32_t num_hosts = 1U << (32 - range.prefix);
    if (num_hosts > max_ips) num_hosts = max_ips;
    
    result.reserve(num_hosts);
    for (uint32_t i = 0; i < num_hosts; i++) {
        result.push_back(int_to_ip(range.network + i));
    }
    return result;
}

bool FileUtils::file_exists(const std::string& path) {
    std::ifstream file(path);
    return file.good();
}

std::string FileUtils::read_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return "";
    
    std::ostringstream oss;
    oss << file.rdbuf();
    return oss.str();
}

bool FileUtils::write_file(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    if (!file.is_open()) return false;
    
    file << content;
    return file.good();
}

std::vector<std::string> FileUtils::read_lines(const std::string& path) {
    std::vector<std::string> lines;
    std::ifstream file(path);
    
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            lines.push_back(line);
        }
    }
    return lines;
}

bool FileUtils::append_line(const std::string& path, const std::string& line) {
    std::ofstream file(path, std::ios::app);
    if (!file.is_open()) return false;
    
    file << line << std::endl;
    return file.good();
}

std::string FileUtils::get_directory(const std::string& path) {
    size_t pos = path.find_last_of("/\\");
    return (pos != std::string::npos) ? path.substr(0, pos) : ".";
}

std::string FileUtils::get_filename(const std::string& path) {
    size_t pos = path.find_last_of("/\\");
    return (pos != std::string::npos) ? path.substr(pos + 1) : path;
}

std::string TimeUtils::get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string TimeUtils::get_date() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time), "%Y-%m-%d");
    return oss.str();
}

std::string TimeUtils::get_time() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time), "%H:%M:%S");
    return oss.str();
}

uint64_t TimeUtils::get_milliseconds() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

uint64_t TimeUtils::get_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

std::string TimeUtils::duration_to_string(uint64_t seconds) {
    uint64_t days = seconds / 86400;
    seconds %= 86400;
    uint64_t hours = seconds / 3600;
    seconds %= 3600;
    uint64_t minutes = seconds / 60;
    seconds %= 60;
    
    std::ostringstream oss;
    if (days > 0) oss << days << "d ";
    if (hours > 0) oss << hours << "h ";
    if (minutes > 0) oss << minutes << "m ";
    oss << seconds << "s";
    return oss.str();
}

std::string CryptoUtils::hash_md5(const std::string& data) {
    unsigned char digest[16];
    // Simple hash implementation for demo
    uint32_t hash1 = 0x12345678;
    uint32_t hash2 = 0x9ABCDEF0;
    
    for (char c : data) {
        hash1 = ((hash1 << 5) + hash1) + c;
        hash2 = ((hash2 << 7) + hash2) ^ c;
    }
    
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(8) << hash1
        << std::setw(8) << hash2;
    return oss.str();
}

std::string CryptoUtils::hash_sha256(const std::string& data) {
    uint32_t hashes[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    for (char c : data) {
        for (int i = 0; i < 8; i++) {
            hashes[i] = ((hashes[i] << 3) + hashes[i]) ^ (c << (i % 4));
        }
    }
    
    std::ostringstream oss;
    for (uint32_t h : hashes) {
        oss << std::hex << std::setfill('0') << std::setw(8) << h;
    }
    return oss.str();
}

std::string CryptoUtils::base64_encode(const std::string& data) {
    static const char table[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    std::string result;
    int val = 0, valb = -6;
    
    for (unsigned char c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            result.push_back(table[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    
    if (valb > -6) result.push_back(table[((val << 8) >> (valb + 8)) & 0x3F]);
    while (result.size() % 4) result.push_back('=');
    
    return result;
}

std::string CryptoUtils::base64_decode(const std::string& data) {
    static const int table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    
    std::string result;
    int val = 0, valb = -8;
    
    for (unsigned char c : data) {
        if (table[c] == -1) break;
        val = (val << 6) + table[c];
        valb += 6;
        if (valb >= 0) {
            result.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    
    return result;
}

std::unordered_map<std::string, std::string> g_config;

bool ConfigParser::load_config(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return false;
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        
        size_t eq = line.find('=');
        if (eq != std::string::npos) {
            std::string key = line.substr(0, eq);
            std::string value = line.substr(eq + 1);
            
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            
            g_config[key] = value;
        }
    }
    return true;
}

std::string ConfigParser::get(const std::string& key, const std::string& default_value) {
    auto it = g_config.find(key);
    return (it != g_config.end()) ? it->second : default_value;
}

int ConfigParser::get_int(const std::string& key, int default_value) {
    auto it = g_config.find(key);
    return (it != g_config.end()) ? std::stoi(it->second) : default_value;
}

bool ConfigParser::get_bool(const std::string& key, bool default_value) {
    auto it = g_config.find(key);
    if (it == g_config.end()) return default_value;
    
    std::string val = it->second;
    std::transform(val.begin(), val.end(), val.begin(), ::tolower);
    return val == "true" || val == "1" || val == "yes";
}

std::vector<std::string> ConfigParser::get_list(const std::string& key) {
    std::vector<std::string> result;
    auto it = g_config.find(key);
    if (it == g_config.end()) return result;
    
    std::istringstream iss(it->second);
    std::string item;
    while (std::getline(iss, item, ',')) {
        item.erase(0, item.find_first_not_of(" \t"));
        item.erase(item.find_last_not_of(" \t") + 1);
        if (!item.empty()) {
            result.push_back(item);
        }
    }
    return result;
}

void ConfigParser::set(const std::string& key, const std::string& value) {
    g_config[key] = value;
}

} // namespace utils
} // namespace antiddos