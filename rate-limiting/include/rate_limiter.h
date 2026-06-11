#ifndef RATE_LIMITER_H
#define RATE_LIMITER_H

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <chrono>
#include <mutex>
#include <functional>
#include "utils.h"

namespace antiddos {

enum class RateLimitAction {
    ALLOW,
    DROP,
    THROTTLE,
    CAPTCHA,
    REDIRECT,
    BLOCK_TEMPORARY,
    BLOCK_PERMANENT
};

struct RateLimitConfig {
    uint32_t max_requests_per_second = 100;
    uint32_t max_requests_per_minute = 1000;
    uint32_t max_requests_per_hour = 10000;
    uint32_t burst_size = 50;
    uint32_t window_size_seconds = 60;
    uint32_t block_duration_seconds = 300;
    bool enable_adaptive = true;
    float sensitivity = 0.5f;
};

struct TokenBucket {
    double tokens;
    double max_tokens;
    double refill_rate;
    std::chrono::steady_clock::time_point last_refill;
    
    bool consume(double tokens);
    void refill();
};

struct SlidingWindow {
    std::vector<std::chrono::steady_clock::time_point> timestamps;
    uint32_t window_size_ms = 60000;
    uint32_t max_requests = 100;
    
    bool allow_request();
    void cleanup();
    uint32_t get_request_count() const;
};

struct ConnectionFingerprint {
    std::string user_agent;
    std::string accept_language;
    std::string accept_encoding;
    bool supports_websocket;
    bool supports_http2;
    std::string tls_fingerprint;
    float anomaly_score = 0.0f;
};

using BlockCallback = std::function<void(const std::string&, uint32_t, RateLimitAction)>;
using WhitelistCallback = std::function<bool(const std::string&)>;

class RateLimiter {
public:
    RateLimiter();
    ~RateLimiter();
    
    void set_config(const RateLimitConfig& config);
    RateLimitConfig get_config() const;
    
    RateLimitAction check_request(const std::string& src_ip, const std::string& endpoint = "");
    
    void add_whitelist(const std::string& ip);
    void remove_whitelist(const std::string& ip);
    bool is_whitelisted(const std::string& ip) const;
    
    void add_blacklist(const std::string& ip, uint32_t duration_seconds = 0);
    void remove_blacklist(const std::string& ip);
    bool is_blacklisted(const std::string& ip) const;
    
    void add_blocked_cidr(const std::string& cidr, uint32_t duration_seconds = 0);
    void remove_blocked_cidr(const std::string& cidr);
    bool is_ip_in_blocked_cidr(const std::string& ip) const;
    std::vector<std::string> get_blocked_cidrs() const;
    
    void set_subnet_rate_limit(const std::string& cidr, uint32_t max_rps);
    void remove_subnet_rate_limit(const std::string& cidr);
    
    void set_endpoint_limit(const std::string& endpoint, uint32_t max_rps);
    void remove_endpoint_limit(const std::string& endpoint);
    
    void update_fingerprint(const std::string& ip, const ConnectionFingerprint& fp);
    float get_anomaly_score(const std::string& ip) const;
    
    void set_block_callback(BlockCallback callback);
    void set_whitelist_check(WhitelistCallback callback);
    
    void enable_ddos_protection(bool enable);
    void set_sensitivity(float sensitivity);
    
    struct Stats {
        uint64_t total_requests = 0;
        uint64_t allowed_requests = 0;
        uint64_t blocked_requests = 0;
        uint64_t throttled_requests = 0;
        uint32_t active_blocks = 0;
        uint32_t whitelisted_ips = 0;
        uint32_t blacklisted_ips = 0;
    };
    
    Stats get_stats() const;
    void reset_stats();
    
    std::vector<std::string> get_blocked_ips() const;
    std::vector<std::string> get_suspicious_ips() const;
    
private:
    mutable std::mutex mutex_;
    RateLimitConfig config_;
    
    std::unordered_map<std::string, TokenBucket> token_buckets_;
    std::unordered_map<std::string, SlidingWindow> sliding_windows_;
    std::unordered_map<std::string, ConnectionFingerprint> fingerprints_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> blocked_ips_;
    std::unordered_set<std::string> whitelisted_ips_;
    std::unordered_set<std::string> blacklisted_ips_;
    std::unordered_map<std::string, uint32_t> endpoint_limits_;
    
    struct CIDRBlockEntry {
        utils::CIDRRange range;
        uint32_t duration_seconds;
        std::chrono::steady_clock::time_point blocked_at;
    };
    std::vector<CIDRBlockEntry> blocked_cidrs_;
    
    struct SubnetRateLimit {
        utils::CIDRRange range;
        uint32_t max_rps;
        TokenBucket bucket;
    };
    std::vector<SubnetRateLimit> subnet_rate_limits_;
    std::unordered_map<std::string, uint32_t> subnet_request_counts_;
    std::chrono::steady_clock::time_point subnet_window_start_;
    
    Stats stats_;
    bool ddos_protection_enabled_ = true;
    
    BlockCallback block_callback_;
    WhitelistCallback whitelist_callback_;
    
    RateLimitAction evaluate_request(const std::string& src_ip);
    RateLimitAction check_token_bucket(const std::string& src_ip);
    RateLimitAction check_sliding_window(const std::string& src_ip);
    RateLimitAction check_fingerprint_anomaly(const std::string& src_ip);
    
    void adaptive_adjust(const std::string& src_ip, RateLimitAction action);
    void trigger_block(const std::string& src_ip, uint32_t duration, RateLimitAction action);
    
    void cleanup_expired_blocks();
};

} // namespace antiddos

#endif // RATE_LIMITER_H