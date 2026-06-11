#include "cluster_manager.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <random>

namespace antiddos {
namespace distributed {

ClusterManager::ClusterManager() = default;

ClusterManager::~ClusterManager() {
    shutdown();
}

bool ClusterManager::initialize(const ClusterConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (running_) return false;
    
    config_ = config;
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 999999);
    node_id_ = "node-" + std::to_string(dis(gen));
    
    self_.node_id = node_id_;
    self_.role = NodeRole::FOLLOWER;
    self_.state = NodeState::ACTIVE;
    self_.last_heartbeat = std::chrono::steady_clock::now();
    
    running_ = true;
    
    heartbeat_thread_ = std::thread(&ClusterManager::heartbeat_loop, this);
    
    if (config_.auto_discover) {
        discovery_thread_ = std::thread(&ClusterManager::discovery_loop, this);
    }
    
    return true;
}

void ClusterManager::shutdown() {
    running_ = false;
    
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.join();
    }
    
    if (discovery_thread_.joinable()) {
        discovery_thread_.join();
    }
}

bool ClusterManager::join_cluster(const std::string& seed_address, uint16_t seed_port) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    ClusterNode seed;
    seed.node_id = "seed-" + seed_address;
    seed.address = seed_address;
    seed.port = seed_port;
    seed.state = NodeState::ACTIVE;
    seed.last_heartbeat = std::chrono::steady_clock::now();
    
    nodes_[seed.node_id] = seed;
    
    return true;
}

bool ClusterManager::leave_cluster() {
    std::lock_guard<std::mutex> lock(mutex_);
    self_.state = NodeState::LEAVING;
    return true;
}

bool ClusterManager::is_leader() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_role_ == NodeRole::LEADER;
}

std::string ClusterManager::get_node_id() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return node_id_;
}

ClusterNode ClusterManager::get_node(const std::string& node_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = nodes_.find(node_id);
    return (it != nodes_.end()) ? it->second : ClusterNode{};
}

std::vector<ClusterNode> ClusterManager::get_all_nodes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ClusterNode> result;
    for (const auto& [id, node] : nodes_) {
        result.push_back(node);
    }
    return result;
}

std::vector<ClusterNode> ClusterManager::get_active_nodes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ClusterNode> result;
    for (const auto& [id, node] : nodes_) {
        if (node.state == NodeState::ACTIVE) {
            result.push_back(node);
        }
    }
    return result;
}

bool ClusterManager::send_message(const std::string& target_node, const std::string& type, const std::string& payload) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    SyncMessage msg;
    msg.type = type;
    msg.source_node = node_id_;
    msg.target_node = target_node;
    msg.payload = payload;
    msg.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
    msg.sequence = message_counter_++;
    
    stats_.sync_messages++;
    
    return true;
}

bool ClusterManager::broadcast_message(const std::string& type, const std::string& payload) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& [id, node] : nodes_) {
        if (id != node_id_ && node.state == NodeState::ACTIVE) {
            SyncMessage msg;
            msg.type = type;
            msg.source_node = node_id_;
            msg.target_node = id;
            msg.payload = payload;
            msg.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()
            ).count();
            msg.sequence = message_counter_++;
            
            stats_.sync_messages++;
        }
    }
    
    return true;
}

void ClusterManager::set_message_handler(MessageHandler handler) {
    std::lock_guard<std::mutex> lock(mutex_);
    message_handler_ = handler;
}

void ClusterManager::sync_threat(const ThreatSync& threat) {
    std::lock_guard<std::mutex> lock(mutex_);
    synced_threats_.push_back(threat);
    
    if (synced_threats_.size() > 10000) {
        synced_threats_.erase(synced_threats_.begin());
    }
}

std::vector<ThreatSync> ClusterManager::get_synced_threats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return synced_threats_;
}

void ClusterManager::update_node_stats(uint64_t packets, uint64_t threats, uint32_t cpu, uint32_t memory) {
    std::lock_guard<std::mutex> lock(mutex_);
    self_.packets_processed = packets;
    self_.threats_detected = threats;
    self_.cpu_usage = cpu;
    self_.memory_usage = memory;
    self_.last_heartbeat = std::chrono::steady_clock::now();
}

bool ClusterManager::elect_leader() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    current_term_++;
    current_role_ = NodeRole::CANDIDATE;
    leader_id_ = "";
    vote_count_ = 1;
    
    stats_.elections++;
    
    auto active_nodes = get_active_nodes();
    if (vote_count_ > active_nodes.size() / 2) {
        become_leader();
        return true;
    }
    
    return false;
}

bool ClusterManager::step_down() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (current_role_ != NodeRole::LEADER) return false;
    
    current_role_ = NodeRole::FOLLOWER;
    leader_id_ = "";
    
    return true;
}

void ClusterManager::set_auto_discover(bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.auto_discover = enable;
}

void ClusterManager::add_static_node(const std::string& address, uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    ClusterNode node;
    node.node_id = "static-" + address;
    node.address = address;
    node.port = port;
    node.state = NodeState::ACTIVE;
    node.last_heartbeat = std::chrono::steady_clock::now();
    
    nodes_[node.node_id] = node;
}

ClusterManager::ClusterStats ClusterManager::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    ClusterStats s = stats_;
    s.active_nodes = 0;
    s.total_nodes = nodes_.size();
    s.leader_node = leader_id_;
    
    for (const auto& [id, node] : nodes_) {
        if (node.state == NodeState::ACTIVE) {
            s.active_nodes++;
            s.total_packets += node.packets_processed;
            s.total_threats += node.threats_detected;
        }
    }
    
    return s;
}

void ClusterManager::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = ClusterStats{};
}

std::string ClusterManager::export_cluster_json() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream oss;
    
    oss << "{\"cluster_id\":\"" << config_.cluster_id << "\","
        << "\"node_id\":\"" << node_id_ << "\","
        << "\"role\":\"" << (current_role_ == NodeRole::LEADER ? "leader" : "follower") << "\","
        << "\"leader\":\"" << leader_id_ << "\","
        << "\"term\":" << current_term_ << ","
        << "\"nodes\":[";
    
    bool first = true;
    for (const auto& [id, node] : nodes_) {
        if (!first) oss << ",";
        first = false;
        
        oss << "{\"id\":\"" << node.node_id << "\","
            << "\"address\":\"" << node.address << "\","
            << "\"state\":\"" << (node.state == NodeState::ACTIVE ? "active" : "inactive") << "\","
            << "\"packets\":" << node.packets_processed << ","
            << "\"threats\":" << node.threats_detected << "}";
    }
    
    oss << "]}";
    return oss.str();
}

void ClusterManager::heartbeat_loop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.heartbeat_interval_ms));
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto now = std::chrono::steady_clock::now();
        
        for (auto& [id, node] : nodes_) {
            if (id != node_id_) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - node.last_heartbeat
                ).count();
                
                if (elapsed > config_.election_timeout_ms * 3) {
                    node.state = NodeState::FAILED;
                } else if (elapsed > config_.election_timeout_ms) {
                    node.state = NodeState::SUSPECTED;
                }
            }
        }
        
        self_.last_heartbeat = now;
    }
}

void ClusterManager::discovery_loop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        for (auto& [id, node] : nodes_) {
            if (id != node_id_ && node.state != NodeState::ACTIVE) {
                node.state = NodeState::ACTIVE;
            }
        }
    }
}

void ClusterManager::handle_message(const SyncMessage& message) {
    if (message_handler_) {
        message_handler_(message);
    }
}

void ClusterManager::process_heartbeat(const ClusterNode& node) {
    nodes_[node.node_id] = node;
}

void ClusterManager::start_election() {
    elect_leader();
}

void ClusterManager::become_leader() {
    current_role_ = NodeRole::LEADER;
    leader_id_ = node_id_;
    self_.role = NodeRole::LEADER;
}

void ClusterManager::become_follower(const std::string& leader_id) {
    current_role_ = NodeRole::FOLLOWER;
    leader_id_ = leader_id;
    self_.role = NodeRole::FOLLOWER;
}

} // namespace distributed
} // namespace antiddos