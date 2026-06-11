#ifndef ATTACK_CORRELATOR_H
#define ATTACK_CORRELATOR_H

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <chrono>
#include <mutex>
#include <functional>
#include <deque>

namespace antiddos {
namespace correlator {

struct BehaviorVector {
    double request_regularity = 0.0;
    double payload_entropy = 0.0;
    double header_consistency = 0.0;
    double timing_regularity = 0.0;
    double endpoint_diversity = 0.0;
    uint32_t requests_per_second = 0;
    uint32_t unique_endpoints = 0;
    std::string primary_method;
    std::string primary_user_agent;
    
    double distance_to(const BehaviorVector& other) const;
    bool is_similar(const BehaviorVector& other, double threshold = 0.3) const;
};

struct IPBehaviorSnapshot {
    std::string ip;
    BehaviorVector vector;
    std::chrono::steady_clock::time_point timestamp;
    uint32_t port;
    std::string asn;
    bool is_vpn;
};

struct AttackCluster {
    std::string id;
    std::vector<std::string> ips;
    BehaviorVector centroid;
    double avg_distance = 0.0;
    double confidence = 0.0;
    uint32_t min_samples = 0;
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    bool is_active = true;
    std::string attack_type;
    std::string description;
};

struct TemporalWave {
    std::string id;
    std::vector<std::string> ips;
    std::chrono::steady_clock::time_point wave_start;
    std::chrono::steady_clock::time_point wave_end;
    uint32_t peak_ips_per_second = 0;
    double avg_session_duration_ms = 0.0;
    bool is_rotating = false;
    std::string description;
};

struct AttackCampaign {
    std::string id;
    std::string name;
    std::vector<std::string> cluster_ids;
    std::vector<std::string> wave_ids;
    std::vector<std::string> all_ips;
    std::chrono::steady_clock::time_point started_at;
    std::chrono::steady_clock::time_point last_activity;
    uint32_t total_unique_ips = 0;
    uint32_t estimated_vpn_rotations = 0;
    std::string estimated_vpn_provider;
    double threat_level = 0.0;
    bool is_persistent = false;
};

struct AggregateVolume {
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    uint32_t unique_ips = 0;
    double packets_per_second = 0.0;
    double bytes_per_second = 0.0;
    double ip_growth_rate = 0.0;
    bool is_spike = false;
    bool is_distributed_attack = false;
    std::chrono::steady_clock::time_point window_start;
    std::chrono::steady_clock::time_point window_end;
};

struct CorrelatorConfig {
    uint32_t min_ips_for_cluster = 3;
    double similarity_threshold = 0.3;
    uint32_t clustering_interval_seconds = 30;
    uint32_t wave_detection_window_seconds = 60;
    uint32_t min_ips_for_wave = 5;
    double spike_threshold_multiplier = 3.0;
    uint32_t aggregate_window_seconds = 10;
    uint32_t campaign_timeout_seconds = 3600;
    bool enable_behavioral_clustering = true;
    bool enable_temporal_clustering = true;
    bool enable_campaign_tracking = true;
    bool enable_aggregate_volume = true;
};

struct CorrelatorStats {
    uint64_t total_snapshots = 0;
    uint32_t active_clusters = 0;
    uint32_t active_waves = 0;
    uint32_t active_campaigns = 0;
    uint32_t total_clusters_detected = 0;
    uint32_t total_waves_detected = 0;
    uint32_t total_campaigns_detected = 0;
    uint32_t total_ips_correlated = 0;
    uint32_t vpn_rotations_detected = 0;
    uint32_t aggregate_spikes_detected = 0;
};

using ClusterCallback = std::function<void(const AttackCluster&)>;
using WaveCallback = std::function<void(const TemporalWave&)>;
using CampaignCallback = std::function<void(const AttackCampaign&)>;
using VolumeCallback = std::function<void(const AggregateVolume&)>;

class AttackCorrelator {
public:
    AttackCorrelator();
    ~AttackCorrelator();
    
    void set_config(const CorrelatorConfig& config);
    CorrelatorConfig get_config() const;
    
    void add_snapshot(const IPBehaviorSnapshot& snapshot);
    void add_snapshot(const std::string& ip, uint32_t port, const BehaviorVector& behavior,
                     bool is_vpn = false, const std::string& asn = "");
    
    std::vector<AttackCluster> get_active_clusters() const;
    std::vector<TemporalWave> get_active_waves() const;
    std::vector<AttackCampaign> get_active_campaigns() const;
    AggregateVolume get_current_volume() const;
    
    AttackCluster get_cluster(const std::string& cluster_id) const;
    TemporalWave get_wave(const std::string& wave_id) const;
    AttackCampaign get_campaign(const std::string& campaign_id) const;
    
    std::vector<std::string> get_correlated_ips() const;
    std::vector<std::string> get_cluster_ips(const std::string& cluster_id) const;
    bool is_ip_correlated(const std::string& ip) const;
    
    void set_cluster_callback(ClusterCallback callback);
    void set_wave_callback(WaveCallback callback);
    void set_campaign_callback(CampaignCallback callback);
    void set_volume_callback(VolumeCallback callback);
    
    CorrelatorStats get_stats() const;
    void reset_stats();
    
    void cleanup_expired();
    
    static BehaviorVector create_vector(double regularity, double entropy, double header_consistency,
                                        double timing_regularity, double endpoint_diversity,
                                        uint32_t rps, uint32_t unique_endpoints,
                                        const std::string& method, const std::string& user_agent);
    
private:
    mutable std::mutex mutex_;
    CorrelatorConfig config_;
    CorrelatorStats stats_;
    
    std::deque<IPBehaviorSnapshot> recent_snapshots_;
    std::unordered_map<std::string, AttackCluster> clusters_;
    std::unordered_map<std::string, TemporalWave> waves_;
    std::unordered_map<std::string, AttackCampaign> campaigns_;
    std::unordered_set<std::string> correlated_ips_;
    
    AggregateVolume current_volume_;
    std::deque<std::pair<std::chrono::steady_clock::time_point, uint64_t>> packet_history_;
    std::deque<std::pair<std::chrono::steady_clock::time_point, uint32_t>> ip_history_;
    
    ClusterCallback cluster_callback_;
    WaveCallback wave_callback_;
    CampaignCallback campaign_callback_;
    VolumeCallback volume_callback_;
    
    void perform_clustering();
    void detect_waves();
    void track_campaigns();
    void update_volume();
    
    std::string generate_cluster_id() const;
    std::string generate_wave_id() const;
    std::string generate_campaign_id() const;
    
    BehaviorVector calculate_centroid(const std::vector<IPBehaviorSnapshot>& snapshots) const;
    double calculate_avg_distance(const std::vector<IPBehaviorSnapshot>& snapshots, const BehaviorVector& centroid) const;
    
    void merge_clusters(const std::string& id1, const std::string& id2);
    void assign_snapshot_to_cluster(const IPBehaviorSnapshot& snapshot);
};

} // namespace correlator
} // namespace antiddos

#endif // ATTACK_CORRELATOR_H
