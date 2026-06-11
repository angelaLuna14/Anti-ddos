#ifndef CLUSTER_MANAGER_H
#define CLUSTER_MANAGER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <functional>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>

namespace antiddos {
namespace distributed {

enum class NodeRole {
    LEADER,
    FOLLOWER,
    CANDIDATE,
    OBSERVER
};

enum class NodeState {
    ACTIVE,
    INACTIVE,
    SUSPECTED,
    FAILED,
    JOINING,
    LEAVING
};

struct ClusterNode {
    std::string node_id;
    std::string address;
    uint16_t port;
    NodeRole role;
    NodeState state;
    std::chrono::steady_clock::time_point last_heartbeat;
    uint64_t packets_processed;
    uint64_t threats_detected;
    uint32_t cpu_usage;
    uint32_t memory_usage;
    uint32_t network_usage;
    std::vector<std::string> capabilities;
};

struct ClusterConfig {
    std::string cluster_id;
    uint32_t heartbeat_interval_ms = 1000;
    uint32_t election_timeout_ms = 5000;
    uint32_t max_nodes = 100;
    bool auto_discover = true;
    std::string discovery_address = "224.0.0.1";
    uint16_t discovery_port = 9999;
};

struct SyncMessage {
    std::string type;
    std::string source_node;
    std::string target_node;
    std::string payload;
    uint64_t timestamp;
    uint32_t sequence;
};

struct ThreatSync {
    std::string attacker_ip;
    std::string source_node;
    uint32_t severity;
    std::string attack_type;
    std::chrono::steady_clock::time_point detected_at;
    std::chrono::steady_clock::time_point expires_at;
};

using MessageHandler = std::function<void(const SyncMessage&)>;

class ClusterManager {
public:
    struct ClusterStats {
        uint32_t active_nodes;
        uint32_t total_nodes;
        uint64_t total_packets;
        uint64_t total_threats;
        uint64_t sync_messages;
        uint32_t elections;
        std::string leader_node;
    };
    
    ClusterManager();
    ~ClusterManager();
    
    bool initialize(const ClusterConfig& config);
    void shutdown();
    
    bool join_cluster(const std::string& seed_address, uint16_t seed_port);
    bool leave_cluster();
    bool is_leader() const;
    
    std::string get_node_id() const;
    ClusterNode get_node(const std::string& node_id) const;
    std::vector<ClusterNode> get_all_nodes() const;
    std::vector<ClusterNode> get_active_nodes() const;
    
    bool send_message(const std::string& target_node, const std::string& type, const std::string& payload);
    bool broadcast_message(const std::string& type, const std::string& payload);
    
    void set_message_handler(MessageHandler handler);
    
    void sync_threat(const ThreatSync& threat);
    std::vector<ThreatSync> get_synced_threats() const;
    
    void update_node_stats(uint64_t packets, uint64_t threats, uint32_t cpu, uint32_t memory);
    
    bool elect_leader();
    bool step_down();
    
    void set_auto_discover(bool enable);
    void add_static_node(const std::string& address, uint16_t port);
    
    ClusterStats get_stats() const;
    void reset_stats();
    
    std::string export_cluster_json() const;
    
private:
    void heartbeat_loop();
    void discovery_loop();
    void handle_message(const SyncMessage& message);
    void process_heartbeat(const ClusterNode& node);
    
    void start_election();
    void become_leader();
    void become_follower(const std::string& leader_id);
    
    mutable std::mutex mutex_;
    ClusterConfig config_;
    
    std::string node_id_;
    ClusterNode self_;
    std::unordered_map<std::string, ClusterNode> nodes_;
    std::vector<ThreatSync> synced_threats_;
    
    bool running_ = false;
    NodeRole current_role_ = NodeRole::FOLLOWER;
    std::string leader_id_;
    uint64_t current_term_ = 0;
    uint64_t vote_count_ = 0;
    
    std::thread heartbeat_thread_;
    std::thread discovery_thread_;
    MessageHandler message_handler_;
    
    ClusterStats stats_;
    std::atomic<uint64_t> message_counter_{0};
};

} // namespace distributed
} // namespace antiddos

#endif // CLUSTER_MANAGER_H