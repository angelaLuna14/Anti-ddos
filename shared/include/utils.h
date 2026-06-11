#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <cstdint>
#include <chrono>

namespace antiddos {
namespace utils {

struct CIDRRange {
    uint32_t network;
    uint32_t prefix;
    uint32_t mask;
};

class IPUtils {
public:
    static bool is_valid_ip(const std::string& ip);
    static bool is_private_ip(const std::string& ip);
    static bool is_loopback(const std::string& ip);
    static std::string get_ip_class(const std::string& ip);
    static uint32_t ip_to_int(const std::string& ip);
    static std::string int_to_ip(uint32_t ip_int);
    static std::string get_network_address(const std::string& ip, int cidr);
    static std::string get_broadcast_address(const std::string& ip, int cidr);
    
    static CIDRRange parse_cidr(const std::string& cidr);
    static bool is_ip_in_cidr(const std::string& ip, const std::string& cidr);
    static bool is_ip_in_cidr(const std::string& ip, const CIDRRange& range);
    static bool do_ips_share_subnet(const std::string& ip1, const std::string& ip2, int prefix);
    static std::string get_subnet_key(const std::string& ip, int prefix);
    static std::vector<std::string> expand_cidr(const std::string& cidr, uint32_t max_ips = 1024);
};

class FileUtils {
public:
    static bool file_exists(const std::string& path);
    static std::string read_file(const std::string& path);
    static bool write_file(const std::string& path, const std::string& content);
    static std::vector<std::string> read_lines(const std::string& path);
    static bool append_line(const std::string& path, const std::string& line);
    static std::string get_directory(const std::string& path);
    static std::string get_filename(const std::string& path);
};

class TimeUtils {
public:
    static std::string get_timestamp();
    static std::string get_date();
    static std::string get_time();
    static uint64_t get_milliseconds();
    static uint64_t get_seconds();
    static std::string duration_to_string(uint64_t seconds);
};

class CryptoUtils {
public:
    static std::string hash_md5(const std::string& data);
    static std::string hash_sha256(const std::string& data);
    static std::string base64_encode(const std::string& data);
    static std::string base64_decode(const std::string& data);
};

class ConfigParser {
public:
    static bool load_config(const std::string& path);
    static std::string get(const std::string& key, const std::string& default_value = "");
    static int get_int(const std::string& key, int default_value = 0);
    static bool get_bool(const std::string& key, bool default_value = false);
    static std::vector<std::string> get_list(const std::string& key);
    static void set(const std::string& key, const std::string& value);
};

} // namespace utils
} // namespace antiddos

#endif // UTILS_H