#include "attack_correlator.h"
#include <algorithm>
#include <cmath>
#include <sstream>
#include <numeric>

namespace antiddos {
namespace correlator {

double BehaviorVector::distance_to(const BehaviorVector& other) const {
    double d_regularity = std::abs(request_regularity - other.request_regularity);
    double d_entropy = std::abs(payload_entropy - other.payload_entropy);
    double d_header = std::abs(header_consistency - other.header_consistency);
    double d_timing = std::abs(timing_regularity - other.timing_regularity);
    double d_endpoint = std::abs(endpoint_diversity - other.endpoint_diversity);
    
    double rps_diff = std::abs(static_cast<double>(requests_per_second) - static_cast<double>(other.requests_per_second));
    double rps_normalized = std::min(1.0, rps_diff / 1000.0);
    
    double d_method = (primary_method == other.primary_method) ? 0.0 : 0.2;
    double d_ua = (primary_user_agent == other.primary_user_agent) ? 0.0 : 0.15;
    
    return (d_regularity * 0.2 + d_entropy * 0.15 + d_header * 0.15 + 
            d_timing * 0.2 + d_endpoint * 0.1 + rps_normalized * 0.1 + 
            d_method + d_ua);
}

bool BehaviorVector::is_similar(const BehaviorVector& other, double threshold) const {
    return distance_to(other) < threshold;
}

AttackCorrelator::AttackCorrelator() {
    config_ = CorrelatorConfig{};
    stats_ = CorrelatorStats{};
    current_volume_ = AggregateVolume{};
}

AttackCorrelator::~AttackCorrelator() = default;

void AttackCorrelator::set_config(const CorrelatorConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
}

CorrelatorConfig AttackCorrelator::get_config() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

void AttackCorrelator::add_snapshot(const IPBehaviorSnapshot& snapshot) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    recent_snapshots_.push_back(snapshot);
    correlated_ips_.insert(snapshot.ip);
    stats_.total_snapshots++;
    stats_.total_ips_correlated = correlated_ips_.size();
    
    auto cutoff = std::chrono::steady_clock::now() - std::chrono::seconds(config_.clustering_interval_seconds * 3);
    while (!recent_snapshots_.empty() && recent_snapshots_.front().timestamp < cutoff) {
        recent_snapshots_.pop_front();
    }
    
    packet_history_.push_back({snapshot.timestamp, 1});
    ip_history_.push_back({snapshot.timestamp, 1});
    
    auto now = std::chrono::steady_clock::now();
    while (!packet_history_.empty()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - packet_history_.front().first).count();
        if (static_cast<uint32_t>(elapsed) > config_.aggregate_window_seconds) {
            packet_history_.pop_front();
        } else {
            break;
        }
    }
    
    while (!ip_history_.empty()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - ip_history_.front().first).count();
        if (static_cast<uint32_t>(elapsed) > config_.aggregate_window_seconds * 10) {
            ip_history_.pop_front();
        } else {
            break;
        }
    }
    
    if (config_.enable_behavioral_clustering) {
        assign_snapshot_to_cluster(snapshot);
    }
    
    if (config_.enable_temporal_clustering) {
        detect_waves();
    }
    
    if (config_.enable_aggregate_volume) {
        update_volume();
    }
}

void AttackCorrelator::add_snapshot(const std::string& ip, uint32_t port, const BehaviorVector& behavior,
                                    bool is_vpn, const std::string& asn) {
    IPBehaviorSnapshot snapshot;
    snapshot.ip = ip;
    snapshot.vector = behavior;
    snapshot.timestamp = std::chrono::steady_clock::now();
    snapshot.port = port;
    snapshot.asn = asn;
    snapshot.is_vpn = is_vpn;
    
    add_snapshot(snapshot);
}

std::vector<AttackCluster> AttackCorrelator::get_active_clusters() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<AttackCluster> result;
    for (const auto& [id, cluster] : clusters_) {
        if (cluster.is_active) {
            result.push_back(cluster);
        }
    }
    return result;
}

std::vector<TemporalWave> AttackCorrelator::get_active_waves() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<TemporalWave> result;
    for (const auto& [id, wave] : waves_) {
        result.push_back(wave);
    }
    return result;
}

std::vector<AttackCampaign> AttackCorrelator::get_active_campaigns() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<AttackCampaign> result;
    for (const auto& [id, campaign] : campaigns_) {
        result.push_back(campaign);
    }
    return result;
}

AggregateVolume AttackCorrelator::get_current_volume() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_volume_;
}

AttackCluster AttackCorrelator::get_cluster(const std::string& cluster_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = clusters_.find(cluster_id);
    return (it != clusters_.end()) ? it->second : AttackCluster{};
}

TemporalWave AttackCorrelator::get_wave(const std::string& wave_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = waves_.find(wave_id);
    return (it != waves_.end()) ? it->second : TemporalWave{};
}

AttackCampaign AttackCorrelator::get_campaign(const std::string& campaign_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = campaigns_.find(campaign_id);
    return (it != campaigns_.end()) ? it->second : AttackCampaign{};
}

std::vector<std::string> AttackCorrelator::get_correlated_ips() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::vector<std::string>(correlated_ips_.begin(), correlated_ips_.end());
}

std::vector<std::string> AttackCorrelator::get_cluster_ips(const std::string& cluster_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = clusters_.find(cluster_id);
    if (it != clusters_.end()) {
        return it->second.ips;
    }
    return {};
}

bool AttackCorrelator::is_ip_correlated(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return correlated_ips_.count(ip) > 0;
}

void AttackCorrelator::set_cluster_callback(ClusterCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    cluster_callback_ = callback;
}

void AttackCorrelator::set_wave_callback(WaveCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    wave_callback_ = callback;
}

void AttackCorrelator::set_campaign_callback(CampaignCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    campaign_callback_ = callback;
}

void AttackCorrelator::set_volume_callback(VolumeCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    volume_callback_ = callback;
}

CorrelatorStats AttackCorrelator::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void AttackCorrelator::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = CorrelatorStats{};
}

void AttackCorrelator::cleanup_expired() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto campaign_timeout = std::chrono::seconds(config_.campaign_timeout_seconds);
    
    for (auto& [id, campaign] : campaigns_) {
        if (now - campaign.last_activity > campaign_timeout) {
            campaign.is_persistent = false;
        }
    }
}

BehaviorVector AttackCorrelator::create_vector(double regularity, double entropy, double header_consistency,
                                                double timing_regularity, double endpoint_diversity,
                                                uint32_t rps, uint32_t unique_endpoints,
                                                const std::string& method, const std::string& user_agent) {
    BehaviorVector v;
    v.request_regularity = regularity;
    v.payload_entropy = entropy;
    v.header_consistency = header_consistency;
    v.timing_regularity = timing_regularity;
    v.endpoint_diversity = endpoint_diversity;
    v.requests_per_second = rps;
    v.unique_endpoints = unique_endpoints;
    v.primary_method = method;
    v.primary_user_agent = user_agent;
    return v;
}

void AttackCorrelator::perform_clustering() {
    if (recent_snapshots_.size() < config_.min_ips_for_cluster) return;
    
    std::vector<IPBehaviorSnapshot> unique_snapshots;
    std::unordered_set<std::string> seen_ips;
    
    for (const auto& snap : recent_snapshots_) {
        if (seen_ips.find(snap.ip) == seen_ips.end()) {
            unique_snapshots.push_back(snap);
            seen_ips.insert(snap.ip);
        }
    }
    
    if (unique_snapshots.size() < config_.min_ips_for_cluster) return;
    
    std::unordered_map<std::string, std::vector<IPBehaviorSnapshot>> candidate_clusters;
    
    for (size_t i = 0; i < unique_snapshots.size(); i++) {
        for (size_t j = i + 1; j < unique_snapshots.size(); j++) {
            double dist = unique_snapshots[i].vector.distance_to(unique_snapshots[j].vector);
            if (dist < config_.similarity_threshold) {
                candidate_clusters[unique_snapshots[i].ip].push_back(unique_snapshots[j]);
            }
        }
    }
    
    for (auto& [anchor_ip, members] : candidate_clusters) {
        if (members.size() + 1 < config_.min_ips_for_cluster) continue;
        
        std::vector<IPBehaviorSnapshot> cluster_snaps;
        cluster_snaps.push_back(*std::find_if(unique_snapshots.begin(), unique_snapshots.end(),
            [&anchor_ip](const IPBehaviorSnapshot& s) { return s.ip == anchor_ip; }));
        cluster_snaps.insert(cluster_snaps.end(), members.begin(), members.end());
        
        BehaviorVector centroid = calculate_centroid(cluster_snaps);
        double avg_dist = calculate_avg_distance(cluster_snaps, centroid);
        
        bool found_existing = false;
        for (auto& [id, cluster] : clusters_) {
            if (!cluster.is_active) continue;
            
            double centroid_dist = cluster.centroid.distance_to(centroid);
            if (centroid_dist < config_.similarity_threshold * 2) {
                for (const auto& snap : cluster_snaps) {
                    if (std::find(cluster.ips.begin(), cluster.ips.end(), snap.ip) == cluster.ips.end()) {
                        cluster.ips.push_back(snap.ip);
                    }
                }
                cluster.centroid = centroid;
                cluster.avg_distance = avg_dist;
                cluster.last_seen = std::chrono::steady_clock::now();
                cluster.confidence = std::min(1.0, cluster.confidence + 0.1);
                found_existing = true;
                break;
            }
        }
        
        if (!found_existing) {
            AttackCluster cluster;
            cluster.id = generate_cluster_id();
            for (const auto& snap : cluster_snaps) {
                cluster.ips.push_back(snap.ip);
            }
            cluster.centroid = centroid;
            cluster.avg_distance = avg_dist;
            cluster.confidence = 0.5;
            cluster.min_samples = cluster_snaps.size();
            cluster.first_seen = std::chrono::steady_clock::now();
            cluster.last_seen = cluster.first_seen;
            cluster.is_active = true;
            
            bool has_vpn = false;
            for (const auto& snap : cluster_snaps) {
                if (snap.is_vpn) {
                    has_vpn = true;
                    break;
                }
            }
            cluster.attack_type = has_vpn ? "VPN_COORDINATED" : "COORDINATED";
            cluster.description = "Coordinated attack cluster with " + std::to_string(cluster.ips.size()) + " IPs";
            
            clusters_[cluster.id] = cluster;
            stats_.total_clusters_detected++;
            
            if (cluster_callback_) {
                cluster_callback_(cluster);
            }
        }
    }
}

void AttackCorrelator::detect_waves() {
    auto now = std::chrono::steady_clock::now();
    auto window_start = now - std::chrono::seconds(config_.wave_detection_window_seconds);
    
    std::unordered_map<std::string, uint32_t> ip_counts;
    for (const auto& snap : recent_snapshots_) {
        if (snap.timestamp >= window_start) {
            ip_counts[snap.ip]++;
        }
    }
    
    if (ip_counts.size() < config_.min_ips_for_wave) return;
    
    TemporalWave wave;
    wave.id = generate_wave_id();
    for (const auto& [ip, count] : ip_counts) {
        wave.ips.push_back(ip);
    }
    wave.wave_start = window_start;
    wave.wave_end = now;
    wave.peak_ips_per_second = ip_counts.size();
    wave.is_rotating = ip_counts.size() > 10;
    wave.description = "Temporal wave with " + std::to_string(ip_counts.size()) + " unique IPs";
    
    waves_[wave.id] = wave;
    stats_.total_waves_detected++;
    
    if (wave_callback_) {
        wave_callback_(wave);
    }
    
    if (config_.enable_campaign_tracking) {
        track_campaigns();
    }
}

void AttackCorrelator::track_campaigns() {
    auto active_clusters = get_active_clusters();
    auto active_waves = get_active_waves();
    
    if (active_clusters.empty() && active_waves.empty()) return;
    
    AttackCampaign campaign;
    campaign.id = generate_campaign_id();
    campaign.name = "Campaign " + campaign.id;
    campaign.started_at = std::chrono::steady_clock::now();
    campaign.last_activity = campaign.started_at;
    
    std::unordered_set<std::string> all_ips;
    
    for (const auto& cluster : active_clusters) {
        campaign.cluster_ids.push_back(cluster.id);
        for (const auto& ip : cluster.ips) {
            all_ips.insert(ip);
        }
    }
    
    for (const auto& wave : active_waves) {
        campaign.wave_ids.push_back(wave.id);
        for (const auto& ip : wave.ips) {
            all_ips.insert(ip);
        }
    }
    
    campaign.all_ips.assign(all_ips.begin(), all_ips.end());
    campaign.total_unique_ips = all_ips.size();
    campaign.estimated_vpn_rotations = campaign.total_unique_ips / 10;
    campaign.threat_level = std::min(1.0, campaign.total_unique_ips / 100.0);
    campaign.is_persistent = true;
    
    campaigns_[campaign.id] = campaign;
    stats_.total_campaigns_detected++;
    
    if (campaign_callback_) {
        campaign_callback_(campaign);
    }
}

void AttackCorrelator::update_volume() {
    auto now = std::chrono::steady_clock::now();
    
    uint64_t total_packets = 0;
    uint32_t unique_ips = 0;
    std::unordered_set<std::string> seen_ips;
    
    for (const auto& snap : recent_snapshots_) {
        total_packets++;
        seen_ips.insert(snap.ip);
    }
    unique_ips = seen_ips.size();
    
    auto window_start = now - std::chrono::seconds(config_.aggregate_window_seconds);
    uint64_t recent_packets = 0;
    for (const auto& [ts, count] : packet_history_) {
        if (ts >= window_start) {
            recent_packets += count;
        }
    }
    
    double pps = static_cast<double>(recent_packets) / config_.aggregate_window_seconds;
    
    current_volume_.total_packets = total_packets;
    current_volume_.unique_ips = unique_ips;
    current_volume_.packets_per_second = pps;
    current_volume_.window_start = window_start;
    current_volume_.window_end = now;
    
    static double avg_pps = 0;
    avg_pps = avg_pps * 0.95 + pps * 0.05;
    
    current_volume_.is_spike = pps > avg_pps * config_.spike_threshold_multiplier;
    current_volume_.is_distributed_attack = unique_ips > config_.min_ips_for_wave && pps > avg_pps * 2;
    
    if (current_volume_.is_spike) {
        stats_.aggregate_spikes_detected++;
        if (volume_callback_) {
            volume_callback_(current_volume_);
        }
    }
}

std::string AttackCorrelator::generate_cluster_id() const {
    static uint32_t counter = 0;
    return "CLUSTER-" + std::to_string(++counter);
}

std::string AttackCorrelator::generate_wave_id() const {
    static uint32_t counter = 0;
    return "WAVE-" + std::to_string(++counter);
}

std::string AttackCorrelator::generate_campaign_id() const {
    static uint32_t counter = 0;
    return "CAMPAIGN-" + std::to_string(++counter);
}

BehaviorVector AttackCorrelator::calculate_centroid(const std::vector<IPBehaviorSnapshot>& snapshots) const {
    if (snapshots.empty()) return BehaviorVector{};
    
    BehaviorVector centroid;
    double sum_regularity = 0, sum_entropy = 0, sum_header = 0, sum_timing = 0, sum_endpoint = 0;
    uint32_t sum_rps = 0, sum_unique = 0;
    
    for (const auto& snap : snapshots) {
        sum_regularity += snap.vector.request_regularity;
        sum_entropy += snap.vector.payload_entropy;
        sum_header += snap.vector.header_consistency;
        sum_timing += snap.vector.timing_regularity;
        sum_endpoint += snap.vector.endpoint_diversity;
        sum_rps += snap.vector.requests_per_second;
        sum_unique += snap.vector.unique_endpoints;
    }
    
    uint32_t n = snapshots.size();
    centroid.request_regularity = sum_regularity / n;
    centroid.payload_entropy = sum_entropy / n;
    centroid.header_consistency = sum_header / n;
    centroid.timing_regularity = sum_timing / n;
    centroid.endpoint_diversity = sum_endpoint / n;
    centroid.requests_per_second = sum_rps / n;
    centroid.unique_endpoints = sum_unique / n;
    centroid.primary_method = snapshots[0].vector.primary_method;
    centroid.primary_user_agent = snapshots[0].vector.primary_user_agent;
    
    return centroid;
}

double AttackCorrelator::calculate_avg_distance(const std::vector<IPBehaviorSnapshot>& snapshots, const BehaviorVector& centroid) const {
    if (snapshots.empty()) return 0.0;
    
    double total_dist = 0;
    for (const auto& snap : snapshots) {
        total_dist += snap.vector.distance_to(centroid);
    }
    return total_dist / snapshots.size();
}

void AttackCorrelator::merge_clusters(const std::string& id1, const std::string& id2) {
    auto it1 = clusters_.find(id1);
    auto it2 = clusters_.find(id2);
    if (it1 == clusters_.end() || it2 == clusters_.end()) return;
    
    for (const auto& ip : it2->second.ips) {
        if (std::find(it1->second.ips.begin(), it1->second.ips.end(), ip) == it1->second.ips.end()) {
            it1->second.ips.push_back(ip);
        }
    }
    
    it1->second.confidence = std::min(1.0, it1->second.confidence + 0.2);
    it1->second.last_seen = std::chrono::steady_clock::now();
    
    clusters_.erase(id2);
}

void AttackCorrelator::assign_snapshot_to_cluster(const IPBehaviorSnapshot& snapshot) {
    for (auto& [id, cluster] : clusters_) {
        if (!cluster.is_active) continue;
        
        double dist = snapshot.vector.distance_to(cluster.centroid);
        if (dist < config_.similarity_threshold * 2) {
            if (std::find(cluster.ips.begin(), cluster.ips.end(), snapshot.ip) == cluster.ips.end()) {
                cluster.ips.push_back(snapshot.ip);
                cluster.last_seen = std::chrono::steady_clock::now();
                cluster.confidence = std::min(1.0, cluster.confidence + 0.05);
            }
            return;
        }
    }
}

} // namespace correlator
} // namespace antiddos
