#ifndef BEHAVIORAL_ANALYZER_H
#define BEHAVIORAL_ANALYZER_H

#include <string>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <mutex>
#include <deque>
#include <functional>

namespace antiddos {

enum class BehaviorType {
    NORMAL,
    BOT,
    SCRAPER,
    SCANNER,
    DDOS,
    CREDENTIAL_STUFFING,
    API_ABUSE,
    SLOWLORIS,
    HTTP_FLOOD,
    DNS_AMPLIFICATION,
    NTP_AMPLIFICATION,
    SSDP_AMPLIFICATION,
    MEMCACHED_AMPLIFICATION
};

struct BehaviorProfile {
    std::string ip;
    BehaviorType primary_type = BehaviorType::NORMAL;
    float confidence = 0.0f;
    
    uint64_t total_requests = 0;
    uint64_t unique_endpoints = 0;
    uint64_t error_count = 0;
    
    double avg_request_interval_ms = 0.0f;
    double request_regularity_score = 0.0f;
    double payload_entropy = 0.0f;
    double header_consistency_score = 0.0f;
    double timing_pattern_score = 0.0f;
    
    std::vector<std::string> visited_endpoints;
    std::vector<double> request_intervals;
    std::vector<size_t> payload_sizes;
    
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    
    bool is_human_like() const;
    bool is_bot_like() const;
    bool is_attack_like() const;
};

struct RequestPattern {
    std::string method;
    std::string endpoint;
    size_t payload_size;
    std::unordered_map<std::string, std::string> headers;
    std::chrono::steady_clock::time_point timestamp;
};

class BehavioralAnalyzer {
public:
    BehavioralAnalyzer();
    ~BehavioralAnalyzer();
    
    void analyze_request(const std::string& src_ip, const RequestPattern& pattern);
    BehaviorProfile get_profile(const std::string& ip) const;
    
    void set_bot_threshold(double threshold);
    void set_attack_threshold(double threshold);
    
    std::vector<std::string> detect_bots(double min_confidence = 0.7f) const;
    std::vector<std::string> detect_attackers(double min_confidence = 0.8f) const;
    
    void load_known_bots(const std::string& filepath);
    void load_known_attackers(const std::string& filepath);
    
    void set_learning_mode(bool enable, uint32_t min_samples = 1000);
    bool is_learning() const;
    
    void set_callback(std::function<void(const std::string&, BehaviorType, float)> callback);
    
    struct Analytics {
        uint64_t total_analyzed = 0;
        uint32_t bots_detected = 0;
        uint32_t attackers_detected = 0;
        uint32_t normal_traffic = 0;
        double avg_request_rate = 0.0;
        double detection_accuracy = 0.0;
    };
    
    Analytics get_analytics() const;
    void reset_analytics();
    
    void add_allowed_endpoint(const std::string& endpoint);
    void add_blocked_endpoint(const std::string& endpoint);
    
    void set_rate_limit_per_second(uint32_t limit);
    void set_rate_limit_per_minute(uint32_t limit);
    
private:
    mutable std::mutex mutex_;
    
    std::unordered_map<std::string, BehaviorProfile> profiles_;
    std::unordered_map<std::string, std::deque<RequestPattern>> request_history_;
    
    std::vector<std::string> known_bots_;
    std::vector<std::string> known_attackers_;
    std::vector<std::string> allowed_endpoints_;
    std::vector<std::string> blocked_endpoints_;
    
    double bot_threshold_ = 0.7;
    double attack_threshold_ = 0.8;
    bool learning_mode_ = true;
    uint32_t min_samples_ = 1000;
    
    uint32_t rate_limit_per_second_ = 100;
    uint32_t rate_limit_per_minute_ = 1000;
    
    Analytics analytics_;
    std::function<void(const std::string&, BehaviorType, float)> callback_;
    
    void update_profile(const std::string& src_ip, const RequestPattern& pattern);
    void analyze_timing_patterns(const std::string& src_ip, BehaviorProfile& profile);
    void analyze_payload_patterns(const std::string& src_ip, BehaviorProfile& profile);
    void analyze_header_patterns(const std::string& src_ip, BehaviorProfile& profile);
    void analyze_endpoint_patterns(const std::string& src_ip, BehaviorProfile& profile);
    
    BehaviorType classify_behavior(BehaviorProfile& profile);
    double calculate_entropy(const std::vector<double>& values) const;
    double calculate_regularity_score(const std::vector<double>& intervals) const;
    
    bool is_known_bot(const std::string& ua) const;
    bool is_known_attacker(const std::string& ip) const;
};

} // namespace antiddos

#endif // BEHAVIORAL_ANALYZER_H