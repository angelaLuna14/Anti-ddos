#include "rate_limiter.h"
#include <algorithm>
#include <cmath>

namespace antiddos {

bool TokenBucket::consume(double tokens) {
    refill();
    if (this->tokens >= tokens) {
        this->tokens -= tokens;
        return true;
    }
    return false;
}

void TokenBucket::refill() {
    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - last_refill).count();
    tokens = std::min(max_tokens, tokens + elapsed * refill_rate);
    last_refill = now;
}

bool SlidingWindow::allow_request() {
    cleanup();
    if (timestamps.size() < max_requests) {
        timestamps.push_back(std::chrono::steady_clock::now());
        return true;
    }
    return false;
}

void SlidingWindow::cleanup() {
    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - std::chrono::milliseconds(window_size_ms);
    
    timestamps.erase(
        std::remove_if(timestamps.begin(), timestamps.end(),
            [cutoff](const std::chrono::steady_clock::time_point& tp) {
                return tp < cutoff;
            }),
        timestamps.end()
    );
}

uint32_t SlidingWindow::get_request_count() const {
    return static_cast<uint32_t>(timestamps.size());
}

RateLimiter::RateLimiter() = default;
RateLimiter::~RateLimiter() = default;

void RateLimiter::set_config(const RateLimitConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
}

RateLimitConfig RateLimiter::get_config() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

RateLimitAction RateLimiter::check_request(const std::string& src_ip, const std::string& endpoint) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    cleanup_expired_blocks();
    
    stats_.total_requests++;
    
    if (whitelist_callback_ && whitelist_callback_(src_ip)) {
        stats_.allowed_requests++;
        return RateLimitAction::ALLOW;
    }
    
    if (is_whitelisted(src_ip)) {
        stats_.allowed_requests++;
        return RateLimitAction::ALLOW;
    }
    
    if (is_ip_in_blocked_cidr(src_ip)) {
        stats_.blocked_requests++;
        return RateLimitAction::BLOCK_PERMANENT;
    }
    
    if (is_blacklisted(src_ip)) {
        stats_.blocked_requests++;
        return RateLimitAction::BLOCK_PERMANENT;
    }
    
    if (blocked_ips_.count(src_ip)) {
        stats_.blocked_requests++;
        return RateLimitAction::BLOCK_TEMPORARY;
    }
    
    auto action = evaluate_request(src_ip);
    
    switch (action) {
        case RateLimitAction::ALLOW:
            stats_.allowed_requests++;
            break;
        case RateLimitAction::BLOCK_TEMPORARY:
        case RateLimitAction::BLOCK_PERMANENT:
            stats_.blocked_requests++;
            trigger_block(src_ip, config_.block_duration_seconds, action);
            break;
        case RateLimitAction::THROTTLE:
        case RateLimitAction::CAPTCHA:
        case RateLimitAction::REDIRECT:
            stats_.throttled_requests++;
            break;
        default:
            break;
    }
    
    return action;
}

RateLimitAction RateLimiter::evaluate_request(const std::string& src_ip) {
    for (auto& sl : subnet_rate_limits_) {
        if (utils::IPUtils::is_ip_in_cidr(src_ip, sl.range)) {
            if (!sl.bucket.consume(1.0)) {
                return RateLimitAction::THROTTLE;
            }
        }
    }
    
    auto action = check_token_bucket(src_ip);
    if (action != RateLimitAction::ALLOW) return action;
    
    action = check_sliding_window(src_ip);
    if (action != RateLimitAction::ALLOW) return action;
    
    action = check_fingerprint_anomaly(src_ip);
    if (action != RateLimitAction::ALLOW) return action;
    
    return RateLimitAction::ALLOW;
}

RateLimitAction RateLimiter::check_token_bucket(const std::string& src_ip) {
    if (token_buckets_.find(src_ip) == token_buckets_.end()) {
        TokenBucket bucket;
        bucket.tokens = config_.burst_size;
        bucket.max_tokens = config_.burst_size;
        bucket.refill_rate = config_.max_requests_per_second;
        bucket.last_refill = std::chrono::steady_clock::now();
        token_buckets_[src_ip] = bucket;
    }
    
    auto& bucket = token_buckets_[src_ip];
    if (bucket.consume(1.0)) {
        return RateLimitAction::ALLOW;
    }
    
    if (config_.enable_adaptive) {
        float anomaly = get_anomaly_score(src_ip);
        if (anomaly > 0.8f) {
            return RateLimitAction::BLOCK_TEMPORARY;
        } else if (anomaly > 0.5f) {
            return RateLimitAction::THROTTLE;
        }
    }
    
    return RateLimitAction::THROTTLE;
}

RateLimitAction RateLimiter::check_sliding_window(const std::string& src_ip) {
    if (sliding_windows_.find(src_ip) == sliding_windows_.end()) {
        SlidingWindow window;
        window.window_size_ms = config_.window_size_seconds * 1000;
        window.max_requests = config_.max_requests_per_minute;
        sliding_windows_[src_ip] = window;
    }
    
    auto& window = sliding_windows_[src_ip];
    if (window.allow_request()) {
        return RateLimitAction::ALLOW;
    }
    
    return RateLimitAction::THROTTLE;
}

RateLimitAction RateLimiter::check_fingerprint_anomaly(const std::string& src_ip) {
    if (!config_.enable_adaptive) return RateLimitAction::ALLOW;
    
    auto it = fingerprints_.find(src_ip);
    if (it == fingerprints_.end()) return RateLimitAction::ALLOW;
    
    const auto& fp = it->second;
    
    if (fp.anomaly_score > 0.9f) {
        return RateLimitAction::BLOCK_TEMPORARY;
    }
    
    if (fp.user_agent.empty() || fp.user_agent == "bot" || fp.user_agent == "spider") {
        return RateLimitAction::CAPTCHA;
    }
    
    return RateLimitAction::ALLOW;
}

void RateLimiter::adaptive_adjust(const std::string& src_ip, RateLimitAction action) {
    if (!config_.enable_adaptive) return;
    
    auto it = fingerprints_.find(src_ip);
    if (it != fingerprints_.end()) {
        if (action == RateLimitAction::BLOCK_TEMPORARY || action == RateLimitAction::THROTTLE) {
            it->second.anomaly_score = std::min(1.0f, it->second.anomaly_score + 0.1f);
        } else {
            it->second.anomaly_score = std::max(0.0f, it->second.anomaly_score - 0.01f);
        }
    }
}

void RateLimiter::trigger_block(const std::string& src_ip, uint32_t duration, RateLimitAction action) {
    blocked_ips_[src_ip] = std::chrono::steady_clock::now() + std::chrono::seconds(duration);
    
    if (block_callback_) {
        block_callback_(src_ip, duration, action);
    }
}

void RateLimiter::cleanup_expired_blocks() {
    auto now = std::chrono::steady_clock::now();
    
    for (auto it = blocked_ips_.begin(); it != blocked_ips_.end();) {
        if (now > it->second) {
            it = blocked_ips_.erase(it);
        } else {
            ++it;
        }
    }
    
    blocked_cidrs_.erase(
        std::remove_if(blocked_cidrs_.begin(), blocked_cidrs_.end(),
            [&now](const CIDRBlockEntry& e) {
                if (e.duration_seconds == 0) return false;
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - e.blocked_at).count();
                return static_cast<uint32_t>(elapsed) > e.duration_seconds;
            }),
        blocked_cidrs_.end()
    );
}

void RateLimiter::add_whitelist(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    whitelisted_ips_.insert(ip);
}

void RateLimiter::remove_whitelist(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    whitelisted_ips_.erase(ip);
}

bool RateLimiter::is_whitelisted(const std::string& ip) const {
    return whitelisted_ips_.count(ip) > 0;
}

void RateLimiter::add_blacklist(const std::string& ip, uint32_t duration_seconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    blacklisted_ips_.insert(ip);
    if (duration_seconds > 0) {
        blocked_ips_[ip] = std::chrono::steady_clock::now() + std::chrono::seconds(duration_seconds);
    }
}

void RateLimiter::remove_blacklist(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    blacklisted_ips_.erase(ip);
    blocked_ips_.erase(ip);
}

bool RateLimiter::is_blacklisted(const std::string& ip) const {
    return blacklisted_ips_.count(ip) > 0;
}

void RateLimiter::add_blocked_cidr(const std::string& cidr, uint32_t duration_seconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    CIDRBlockEntry entry;
    entry.range = utils::IPUtils::parse_cidr(cidr);
    entry.duration_seconds = duration_seconds;
    entry.blocked_at = std::chrono::steady_clock::now();
    blocked_cidrs_.push_back(entry);
}

void RateLimiter::remove_blocked_cidr(const std::string& cidr) {
    std::lock_guard<std::mutex> lock(mutex_);
    utils::CIDRRange target = utils::IPUtils::parse_cidr(cidr);
    blocked_cidrs_.erase(
        std::remove_if(blocked_cidrs_.begin(), blocked_cidrs_.end(),
            [&target](const CIDRBlockEntry& e) {
                return e.range.network == target.network && e.range.prefix == target.prefix;
            }),
        blocked_cidrs_.end()
    );
}

bool RateLimiter::is_ip_in_blocked_cidr(const std::string& ip) const {
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

std::vector<std::string> RateLimiter::get_blocked_cidrs() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (const auto& entry : blocked_cidrs_) {
        result.push_back(utils::IPUtils::int_to_ip(entry.range.network) + "/" + std::to_string(entry.range.prefix));
    }
    return result;
}

void RateLimiter::set_subnet_rate_limit(const std::string& cidr, uint32_t max_rps) {
    std::lock_guard<std::mutex> lock(mutex_);
    utils::CIDRRange range = utils::IPUtils::parse_cidr(cidr);
    
    for (auto& sl : subnet_rate_limits_) {
        if (sl.range.network == range.network && sl.range.prefix == range.prefix) {
            sl.max_rps = max_rps;
            sl.bucket.max_tokens = max_rps;
            sl.bucket.refill_rate = max_rps;
            return;
        }
    }
    
    SubnetRateLimit sl;
    sl.range = range;
    sl.max_rps = max_rps;
    sl.bucket.tokens = max_rps;
    sl.bucket.max_tokens = max_rps;
    sl.bucket.refill_rate = max_rps;
    sl.bucket.last_refill = std::chrono::steady_clock::now();
    subnet_rate_limits_.push_back(sl);
}

void RateLimiter::remove_subnet_rate_limit(const std::string& cidr) {
    std::lock_guard<std::mutex> lock(mutex_);
    utils::CIDRRange target = utils::IPUtils::parse_cidr(cidr);
    subnet_rate_limits_.erase(
        std::remove_if(subnet_rate_limits_.begin(), subnet_rate_limits_.end(),
            [&target](const SubnetRateLimit& sl) {
                return sl.range.network == target.network && sl.range.prefix == target.prefix;
            }),
        subnet_rate_limits_.end()
    );
}

void RateLimiter::set_endpoint_limit(const std::string& endpoint, uint32_t max_rps) {
    std::lock_guard<std::mutex> lock(mutex_);
    endpoint_limits_[endpoint] = max_rps;
}

void RateLimiter::remove_endpoint_limit(const std::string& endpoint) {
    std::lock_guard<std::mutex> lock(mutex_);
    endpoint_limits_.erase(endpoint);
}

void RateLimiter::update_fingerprint(const std::string& ip, const ConnectionFingerprint& fp) {
    std::lock_guard<std::mutex> lock(mutex_);
    fingerprints_[ip] = fp;
}

float RateLimiter::get_anomaly_score(const std::string& ip) const {
    auto it = fingerprints_.find(ip);
    return (it != fingerprints_.end()) ? it->second.anomaly_score : 0.0f;
}

void RateLimiter::set_block_callback(BlockCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    block_callback_ = callback;
}

void RateLimiter::set_whitelist_check(WhitelistCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    whitelist_callback_ = callback;
}

void RateLimiter::enable_ddos_protection(bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);
    ddos_protection_enabled_ = enable;
}

void RateLimiter::set_sensitivity(float sensitivity) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.sensitivity = std::max(0.0f, std::min(1.0f, sensitivity));
}

RateLimiter::Stats RateLimiter::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    Stats s = stats_;
    s.active_blocks = static_cast<uint32_t>(blocked_ips_.size());
    s.whitelisted_ips = static_cast<uint32_t>(whitelisted_ips_.size());
    s.blacklisted_ips = static_cast<uint32_t>(blacklisted_ips_.size());
    return s;
}

void RateLimiter::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = Stats{};
}

std::vector<std::string> RateLimiter::get_blocked_ips() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    auto now = std::chrono::steady_clock::now();
    for (const auto& [ip, unblock_time] : blocked_ips_) {
        if (now <= unblock_time) {
            result.push_back(ip);
        }
    }
    return result;
}

std::vector<std::string> RateLimiter::get_suspicious_ips() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (const auto& [ip, fp] : fingerprints_) {
        if (fp.anomaly_score > 0.5f) {
            result.push_back(ip);
        }
    }
    return result;
}

} // namespace antiddos