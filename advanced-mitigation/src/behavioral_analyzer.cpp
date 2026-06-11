#include "behavioral_analyzer.h"
#include <algorithm>
#include <cmath>
#include <numeric>
#include <fstream>
#include <sstream>

namespace antiddos {

bool BehaviorProfile::is_human_like() const {
    return confidence < 0.3f && 
           request_regularity_score < 0.3f &&
           timing_pattern_score < 0.4f;
}

bool BehaviorProfile::is_bot_like() const {
    return primary_type == BehaviorType::BOT || 
           primary_type == BehaviorType::SCRAPER ||
           primary_type == BehaviorType::SCANNER;
}

bool BehaviorProfile::is_attack_like() const {
    return primary_type == BehaviorType::DDOS ||
           primary_type == BehaviorType::HTTP_FLOOD ||
           primary_type == BehaviorType::SLOWLORIS ||
           primary_type == BehaviorType::DNS_AMPLIFICATION ||
           primary_type == BehaviorType::NTP_AMPLIFICATION;
}

BehavioralAnalyzer::BehavioralAnalyzer() = default;
BehavioralAnalyzer::~BehavioralAnalyzer() = default;

void BehavioralAnalyzer::analyze_request(const std::string& src_ip, const RequestPattern& pattern) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    analytics_.total_analyzed++;
    
    if (is_known_attacker(src_ip)) {
        BehaviorProfile& profile = profiles_[src_ip];
        profile.primary_type = BehaviorType::DDOS;
        profile.confidence = 1.0f;
        analytics_.attackers_detected++;
        if (callback_) callback_(src_ip, BehaviorType::DDOS, 1.0f);
        return;
    }
    
    if (is_known_bot(pattern.headers.at("User-Agent"))) {
        BehaviorProfile& profile = profiles_[src_ip];
        profile.primary_type = BehaviorType::BOT;
        profile.confidence = 0.9f;
        analytics_.bots_detected++;
        if (callback_) callback_(src_ip, BehaviorType::BOT, 0.9f);
        return;
    }
    
    update_profile(src_ip, pattern);
    BehaviorProfile& profile = profiles_[src_ip];
    
    if (!learning_mode_ || profile.total_requests >= min_samples_) {
        analyze_timing_patterns(src_ip, profile);
        analyze_payload_patterns(src_ip, profile);
        analyze_header_patterns(src_ip, profile);
        analyze_endpoint_patterns(src_ip, profile);
        
        BehaviorType new_type = classify_behavior(profile);
        
        if (new_type != profile.primary_type) {
            profile.primary_type = new_type;
            
            if (new_type == BehaviorType::BOT) {
                analytics_.bots_detected++;
            } else if (new_type != BehaviorType::NORMAL) {
                analytics_.attackers_detected++;
            } else {
                analytics_.normal_traffic++;
            }
            
            if (callback_) callback_(src_ip, new_type, profile.confidence);
        }
    }
    
    request_history_[src_ip].push_back(pattern);
    if (request_history_[src_ip].size() > 1000) {
        request_history_[src_ip].pop_front();
    }
}

void BehavioralAnalyzer::update_profile(const std::string& src_ip, const RequestPattern& pattern) {
    auto& profile = profiles_[src_ip];
    
    if (profile.total_requests == 0) {
        profile.first_seen = pattern.timestamp;
        profile.ip = src_ip;
    }
    profile.last_seen = pattern.timestamp;
    profile.total_requests++;
    
    if (!pattern.endpoint.empty()) {
        bool found = false;
        for (const auto& ep : profile.visited_endpoints) {
            if (ep == pattern.endpoint) {
                found = true;
                break;
            }
        }
        if (!found) {
            profile.visited_endpoints.push_back(pattern.endpoint);
            profile.unique_endpoints++;
        }
    }
    
    profile.payload_sizes.push_back(pattern.payload_size);
    
    if (!request_history_[src_ip].empty()) {
        auto& last = request_history_[src_ip].back();
        double interval = std::chrono::duration<double, std::milli>(
            pattern.timestamp - last.timestamp
        ).count();
        profile.request_intervals.push_back(interval);
        
        double total = 0;
        for (double i : profile.request_intervals) total += i;
        profile.avg_request_interval_ms = total / profile.request_intervals.size();
    }
}

void BehavioralAnalyzer::analyze_timing_patterns(const std::string& src_ip, BehaviorProfile& profile) {
    if (profile.request_intervals.size() < 10) return;
    
    profile.request_regularity_score = calculate_regularity_score(profile.request_intervals);
    profile.timing_pattern_score = calculate_entropy(profile.request_intervals);
}

void BehavioralAnalyzer::analyze_payload_patterns(const std::string& src_ip, BehaviorProfile& profile) {
    if (profile.payload_sizes.empty()) return;
    
    profile.payload_entropy = calculate_entropy(
        std::vector<double>(profile.payload_sizes.begin(), profile.payload_sizes.end())
    );
}

void BehavioralAnalyzer::analyze_header_patterns(const std::string& src_ip, BehaviorProfile& profile) {
    uint32_t consistency_count = 0;
    uint32_t total_headers = 0;
    
    for (const auto& [ip, history] : request_history_) {
        if (ip == src_ip && history.size() > 1) {
            const auto& first = history.front();
            const auto& last = history.back();
            
            if (first.headers.count("User-Agent") && last.headers.count("User-Agent")) {
                total_headers++;
                if (first.headers.at("User-Agent") == last.headers.at("User-Agent")) {
                    consistency_count++;
                }
            }
        }
    }
    
    if (total_headers > 0) {
        profile.header_consistency_score = static_cast<double>(consistency_count) / total_headers;
    }
}

void BehavioralAnalyzer::analyze_endpoint_patterns(const std::string& src_ip, BehaviorProfile& profile) {
    if (profile.total_requests == 0) return;
    
    double unique_ratio = static_cast<double>(profile.unique_endpoints) / profile.total_requests;
    
    if (unique_ratio > 0.8f) {
        profile.confidence = std::min(1.0f, profile.confidence + 0.1f);
    }
}

BehaviorType BehavioralAnalyzer::classify_behavior(BehaviorProfile& profile) {
    if (profile.total_requests < 10) {
        return BehaviorType::NORMAL;
    }
    
    double bot_score = 0.0;
    double attack_score = 0.0;
    
    if (profile.request_regularity_score > 0.7) {
        bot_score += 0.3;
    }
    if (profile.timing_pattern_score < 0.3) {
        bot_score += 0.2;
    }
    if (profile.header_consistency_score > 0.9) {
        bot_score += 0.2;
    }
    if (profile.total_requests > rate_limit_per_minute_) {
        attack_score += 0.4;
    }
    if (profile.avg_request_interval_ms < 10) {
        attack_score += 0.3;
    }
    if (profile.unique_endpoints > profile.total_requests * 0.9) {
        attack_score += 0.2;
    }
    if (profile.payload_entropy > 0.8) {
        attack_score += 0.1;
    }
    
    if (attack_score >= attack_threshold_) {
        profile.confidence = static_cast<float>(attack_score);
        return BehaviorType::DDOS;
    }
    
    if (bot_score >= bot_threshold_) {
        profile.confidence = static_cast<float>(bot_score);
        return BehaviorType::BOT;
    }
    
    if (profile.avg_request_interval_ms < 100 && profile.total_requests > 500) {
        return BehaviorType::HTTP_FLOOD;
    }
    
    profile.confidence = static_cast<float>(std::max(bot_score, attack_score));
    return BehaviorType::NORMAL;
}

double BehavioralAnalyzer::calculate_entropy(const std::vector<double>& values) const {
    if (values.empty()) return 0.0;
    
    double min_val = *std::min_element(values.begin(), values.end());
    double max_val = *std::max_element(values.begin(), values.end());
    
    if (max_val - min_val < 0.0001) return 0.0;
    
    std::vector<double> normalized(values.size());
    for (size_t i = 0; i < values.size(); i++) {
        normalized[i] = (values[i] - min_val) / (max_val - min_val);
    }
    
    const int bins = 10;
    std::vector<int> histogram(bins, 0);
    for (double v : normalized) {
        int bin = std::min(bins - 1, static_cast<int>(v * bins));
        histogram[bin]++;
    }
    
    double entropy = 0.0;
    int total = normalized.size();
    for (int count : histogram) {
        if (count > 0) {
            double p = static_cast<double>(count) / total;
            entropy -= p * std::log2(p);
        }
    }
    
    return entropy / std::log2(bins);
}

double BehavioralAnalyzer::calculate_regularity_score(const std::vector<double>& intervals) const {
    if (intervals.size() < 2) return 0.0;
    
    double mean = std::accumulate(intervals.begin(), intervals.end(), 0.0) / intervals.size();
    
    double variance = 0.0;
    for (double v : intervals) {
        variance += (v - mean) * (v - mean);
    }
    variance /= intervals.size();
    
    double std_dev = std::sqrt(variance);
    double cv = std_dev / mean;
    
    return 1.0 - std::min(1.0, cv);
}

BehaviorProfile BehavioralAnalyzer::get_profile(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = profiles_.find(ip);
    return (it != profiles_.end()) ? it->second : BehaviorProfile{};
}

std::vector<std::string> BehavioralAnalyzer::detect_bots(double min_confidence) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    
    for (const auto& [ip, profile] : profiles_) {
        if (profile.is_bot_like() && profile.confidence >= min_confidence) {
            result.push_back(ip);
        }
    }
    return result;
}

std::vector<std::string> BehavioralAnalyzer::detect_attackers(double min_confidence) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    
    for (const auto& [ip, profile] : profiles_) {
        if (profile.is_attack_like() && profile.confidence >= min_confidence) {
            result.push_back(ip);
        }
    }
    return result;
}

void BehavioralAnalyzer::load_known_bots(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ifstream file(filepath);
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            known_bots_.push_back(line);
        }
    }
}

void BehavioralAnalyzer::load_known_attackers(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ifstream file(filepath);
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            known_attackers_.push_back(line);
        }
    }
}

void BehavioralAnalyzer::set_learning_mode(bool enable, uint32_t min_samples) {
    std::lock_guard<std::mutex> lock(mutex_);
    learning_mode_ = enable;
    min_samples_ = min_samples;
}

bool BehavioralAnalyzer::is_learning() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return learning_mode_;
}

void BehavioralAnalyzer::set_callback(std::function<void(const std::string&, BehaviorType, float)> callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = callback;
}

BehavioralAnalyzer::Analytics BehavioralAnalyzer::get_analytics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return analytics_;
}

void BehavioralAnalyzer::reset_analytics() {
    std::lock_guard<std::mutex> lock(mutex_);
    analytics_ = Analytics{};
}

void BehavioralAnalyzer::add_allowed_endpoint(const std::string& endpoint) {
    std::lock_guard<std::mutex> lock(mutex_);
    allowed_endpoints_.push_back(endpoint);
}

void BehavioralAnalyzer::add_blocked_endpoint(const std::string& endpoint) {
    std::lock_guard<std::mutex> lock(mutex_);
    blocked_endpoints_.push_back(endpoint);
}

void BehavioralAnalyzer::set_rate_limit_per_second(uint32_t limit) {
    std::lock_guard<std::mutex> lock(mutex_);
    rate_limit_per_second_ = limit;
}

void BehavioralAnalyzer::set_rate_limit_per_minute(uint32_t limit) {
    std::lock_guard<std::mutex> lock(mutex_);
    rate_limit_per_minute_ = limit;
}

bool BehavioralAnalyzer::is_known_bot(const std::string& ua) const {
    std::string lower_ua = ua;
    std::transform(lower_ua.begin(), lower_ua.end(), lower_ua.begin(), ::tolower);
    
    for (const auto& bot : known_bots_) {
        std::string lower_bot = bot;
        std::transform(lower_bot.begin(), lower_bot.end(), lower_bot.begin(), ::tolower);
        if (lower_ua.find(lower_bot) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool BehavioralAnalyzer::is_known_attacker(const std::string& ip) const {
    return std::find(known_attackers_.begin(), known_attackers_.end(), ip) != known_attackers_.end();
}

} // namespace antiddos