#include "game_protector.h"
#include <algorithm>
#include <cstring>
#include <sstream>

namespace antiddos {
namespace game {

GameProtector::GameProtector() {
    game_ports_ = {
        {27015, GameType::HALF_LIFE},
        {27015, GameType::COUNTER_STRIKE_16},
        {27015, GameType::SVEN_COOP},
        {27015, GameType::COUNTER_STRIKE_SOURCE},
        {27015, GameType::GARRYS_MOD},
        {27015, GameType::COUNTER_STRIKE_GO},
        {27005, GameType::COUNTER_STRIKE_16},
        {27006, GameType::HALF_LIFE},
        {27010, GameType::HALF_LIFE},
        {27011, GameType::SVEN_COOP},
        {27012, GameType::COUNTER_STRIKE_16},
        {27013, GameType::DAY_OF_DEFEAT},
        {27014, GameType::TEAM_FORTRESS_CLASSIC},
        {27016, GameType::COUNTER_STRIKE_2},
        {27017, GameType::COUNTER_STRIKE_2},
        {27018, GameType::COUNTER_STRIKE_2},
        {27019, GameType::COUNTER_STRIKE_2},
        {27020, GameType::COUNTER_STRIKE_2},
        {27021, GameType::COUNTER_STRIKE_2},
        {27022, GameType::COUNTER_STRIKE_2},
        {27023, GameType::COUNTER_STRIKE_2},
        {27024, GameType::COUNTER_STRIKE_2},
        {27025, GameType::COUNTER_STRIKE_2},
        {27026, GameType::COUNTER_STRIKE_2},
        {27027, GameType::COUNTER_STRIKE_2},
        {27028, GameType::COUNTER_STRIKE_2},
        {27029, GameType::COUNTER_STRIKE_2},
        {27030, GameType::COUNTER_STRIKE_2},
        {3478, GameType::COUNTER_STRIKE_GO},
        {4379, GameType::COUNTER_STRIKE_GO},
        {4380, GameType::COUNTER_STRIKE_GO},
        {27036, GameType::COUNTER_STRIKE_GO},
        {27037, GameType::COUNTER_STRIKE_GO},
    };
}

GameProtector::~GameProtector() = default;

void GameProtector::set_config(const GameProtectionConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
}

GameProtectionConfig GameProtector::get_config() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

void GameProtector::add_game_server(uint16_t port, GameType game) {
    std::lock_guard<std::mutex> lock(mutex_);
    game_ports_[port] = game;
}

void GameProtector::remove_game_server(uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex_);
    game_ports_.erase(port);
}

void GameProtector::set_server_info(uint16_t port, const GameServerInfo& info) {
    std::lock_guard<std::mutex> lock(mutex_);
    server_infos_[port] = info;
}

bool GameProtector::analyze_packet(const std::string& src_ip, uint16_t src_port,
                                   uint16_t dst_port, const std::vector<uint8_t>& payload,
                                   uint32_t packet_size) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    cleanup_expired_blocks();
    stats_.total_packets_analyzed++;
    
    if (trusted_ips_.count(src_ip)) return true;
    
    if (is_blocked(src_ip)) {
        stats_.total_attacks_detected++;
        return false;
    }
    
    auto game_it = game_ports_.find(dst_port);
    if (game_it == game_ports_.end()) return true;
    
    GameType game = game_it->second;
    stats_.packets_by_game[game]++;
    
    bool is_query = detect_a2s_info(payload) || detect_a2s_player(payload) || 
                    detect_a2s_rules(payload) || detect_a2s_challenge(payload);
    
    bool is_connection = detect_connect_request(payload);
    bool is_rcon = detect_rcon(payload);
    
    if (!is_query && !is_connection && !is_rcon) {
        if (payload.size() > 0 && payload[0] == 0xFF) {
            is_query = true;
        }
    }
    
    if (is_query && config_.enable_query_flood_protection) {
        if (check_query_flood(src_ip, dst_port)) {
            AttackType attack = is_rcon ? AttackType::LOGIN_FLOOD : AttackType::QUERY_FLOOD;
            float confidence = 0.9f;
            
            if (callback_) callback_(src_ip, game, attack, confidence);
            
            stats_.total_attacks_detected++;
            stats_.attacks_by_type[attack]++;
            stats_.total_queries_blocked++;
            
            if (config_.auto_block_attacker) {
                trigger_block(src_ip, config_.auto_block_duration_seconds, 
                             attack_type_to_string(attack));
            }
            
            return false;
        }
        update_tracker(src_ip, dst_port, true);
    }
    
    if (is_connection && config_.enable_connection_flood_protection) {
        if (check_connection_flood(src_ip, dst_port)) {
            if (callback_) callback_(src_ip, game, AttackType::CONNECTION_FLOOD, 0.85f);
            
            stats_.total_attacks_detected++;
            stats_.attacks_by_type[AttackType::CONNECTION_FLOOD]++;
            stats_.total_connections_blocked++;
            
            if (config_.auto_block_attacker) {
                trigger_block(src_ip, config_.auto_block_duration_seconds, "Connection flood");
            }
            
            return false;
        }
        update_tracker(src_ip, dst_port, false);
    }
    
    return true;
}

bool GameProtector::check_query_flood(const std::string& src_ip, uint16_t dst_port) {
    std::string key = src_ip + ":" + std::to_string(dst_port);
    auto& tracker = query_trackers_[key];
    
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - tracker.window_start).count();
    
    if (elapsed >= 1) {
        if (tracker.query_count > config_.max_queries_per_second) {
            return true;
        }
        tracker.query_count = 0;
        tracker.window_start = now;
    }
    
    if (elapsed >= 60) {
        if (tracker.query_count > config_.max_queries_per_minute) {
            return true;
        }
    }
    
    return false;
}

bool GameProtector::check_connection_flood(const std::string& src_ip, uint16_t dst_port) {
    std::string key = src_ip + ":" + std::to_string(dst_port);
    auto& tracker = query_trackers_[key];
    
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - tracker.window_start).count();
    
    if (elapsed >= 1) {
        if (tracker.connection_count > config_.max_connections_per_second) {
            return true;
        }
        tracker.connection_count = 0;
        tracker.window_start = now;
    }
    
    return false;
}

void GameProtector::update_tracker(const std::string& src_ip, uint16_t dst_port, bool is_query) {
    std::string key = src_ip + ":" + std::to_string(dst_port);
    auto& tracker = query_trackers_[key];
    
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - tracker.window_start).count();
    
    if (elapsed >= 60) {
        tracker.query_count = 0;
        tracker.connection_count = 0;
        tracker.window_start = now;
    }
    
    if (is_query) {
        tracker.query_count++;
    } else {
        tracker.connection_count++;
    }
    tracker.last_query = now;
}

void GameProtector::trigger_block(const std::string& src_ip, uint32_t duration, const std::string& reason) {
    BlockedEntry entry;
    entry.ip = src_ip;
    entry.blocked_at = std::chrono::steady_clock::now();
    entry.duration_seconds = duration;
    entry.reason = reason;
    blocked_ips_.push_back(entry);
    stats_.blocked_ips++;
}

void GameProtector::cleanup_expired_blocks() {
    auto now = std::chrono::steady_clock::now();
    blocked_ips_.erase(
        std::remove_if(blocked_ips_.begin(), blocked_ips_.end(),
            [&now](const BlockedEntry& e) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - e.blocked_at).count();
                return static_cast<uint32_t>(elapsed) > e.duration_seconds;
            }),
        blocked_ips_.end()
    );
}

bool GameProtector::detect_a2s_info(const std::vector<uint8_t>& payload) const {
    if (payload.size() < 4) return false;
    if (payload[0] != 0xFF || payload[1] != 0xFF || payload[2] != 0xFF || payload[3] != 0xFF) return false;
    
    if (payload.size() >= 5) {
        uint8_t header = payload[4];
        if (header == 0x49 || header == 0x54) return true;
    }
    return false;
}

bool GameProtector::detect_a2s_player(const std::vector<uint8_t>& payload) const {
    if (payload.size() < 5) return false;
    if (payload[0] != 0xFF || payload[1] != 0xFF || payload[2] != 0xFF || payload[3] != 0xFF) return false;
    return payload[4] == 0x55;
}

bool GameProtector::detect_a2s_rules(const std::vector<uint8_t>& payload) const {
    if (payload.size() < 5) return false;
    if (payload[0] != 0xFF || payload[1] != 0xFF || payload[2] != 0xFF || payload[3] != 0xFF) return false;
    return payload[4] == 0x56;
}

bool GameProtector::detect_a2s_challenge(const std::vector<uint8_t>& payload) const {
    if (payload.size() < 5) return false;
    if (payload[0] != 0xFF || payload[1] != 0xFF || payload[2] != 0xFF || payload[3] != 0xFF) return false;
    return payload[4] == 0x41;
}

bool GameProtector::detect_connect_request(const std::vector<uint8_t>& payload) const {
    if (payload.size() < 5) return false;
    if (payload[0] != 0xFF || payload[1] != 0xFF || payload[2] != 0xFF || payload[3] != 0xFF) return false;
    
    uint8_t header = payload[4];
    if (header == 0x09 || header == 0x0C) return true;
    
    if (payload.size() >= 6) {
        if (payload[4] == 0x01 && payload[5] == 0x00) return true;
    }
    
    return false;
}

bool GameProtector::detect_rcon(const std::vector<uint8_t>& payload) const {
    if (payload.size() < 12) return false;
    if (payload[0] != 0xFF || payload[1] != 0xFF || payload[2] != 0xFF || payload[3] != 0xFF) return false;
    return payload[4] == 0x63;
}

void GameProtector::block_ip(const std::string& ip, uint32_t duration_seconds, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    trigger_block(ip, duration_seconds, reason);
}

void GameProtector::unblock_ip(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    blocked_ips_.erase(
        std::remove_if(blocked_ips_.begin(), blocked_ips_.end(),
            [&ip](const BlockedEntry& e) { return e.ip == ip; }),
        blocked_ips_.end()
    );
}

bool GameProtector::is_blocked(const std::string& ip) const {
    auto now = std::chrono::steady_clock::now();
    for (const auto& entry : blocked_ips_) {
        if (entry.ip != ip) continue;
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - entry.blocked_at).count();
        if (static_cast<uint32_t>(elapsed) <= entry.duration_seconds) {
            return true;
        }
    }
    return false;
}

void GameProtector::add_trusted_ip(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    trusted_ips_.insert(ip);
}

void GameProtector::remove_trusted_ip(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    trusted_ips_.erase(ip);
}

bool GameProtector::is_trusted(const std::string& ip) const {
    return trusted_ips_.count(ip) > 0;
}

void GameProtector::set_attack_callback(AttackCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = callback;
}

GameProtectionStats GameProtector::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void GameProtector::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = GameProtectionStats{};
}

std::vector<std::string> GameProtector::get_blocked_ips() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    auto now = std::chrono::steady_clock::now();
    for (const auto& entry : blocked_ips_) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - entry.blocked_at).count();
        if (static_cast<uint32_t>(elapsed) <= entry.duration_seconds) {
            result.push_back(entry.ip);
        }
    }
    return result;
}

std::vector<std::string> GameProtector::get_active_connections() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (const auto& [key, tracker] : query_trackers_) {
        result.push_back(key);
    }
    return result;
}

GameType GameProtector::detect_game_from_payload(const std::vector<uint8_t>& payload, uint16_t port) {
    if (payload.size() < 5) return GameType::UNKNOWN;
    if (payload[0] != 0xFF || payload[1] != 0xFF || payload[2] != 0xFF || payload[3] != 0xFF) return GameType::UNKNOWN;
    
    if (payload.size() >= 6) {
        if (payload[4] == 0x49 && payload[5] == 'S') {
            if (payload.size() > 25) {
                std::string game_str;
                for (size_t i = 25; i < payload.size() && payload[i] != 0; i++) {
                    game_str += static_cast<char>(payload[i]);
                }
                
                if (game_str.find("counter-strike") != std::string::npos || 
                    game_str.find("Counter-Strike") != std::string::npos) {
                    if (game_str.find("Source") != std::string::npos) return GameType::COUNTER_STRIKE_SOURCE;
                    if (game_str.find("Global Offensive") != std::string::npos) return GameType::COUNTER_STRIKE_GO;
                    return GameType::COUNTER_STRIKE_16;
                }
                if (game_str.find("sven") != std::string::npos || game_str.find("Sven") != std::string::npos) {
                    return GameType::SVEN_COOP;
                }
                if (game_str.find("half-life") != std::string::npos || game_str.find("Half-Life") != std::string::npos) {
                    return GameType::HALF_LIFE;
                }
                if (game_str.find("Garry") != std::string::npos) {
                    return GameType::GARRYS_MOD;
                }
            }
        }
    }
    
    static const std::unordered_map<uint16_t, GameType> default_ports = {
        {27015, GameType::COUNTER_STRIKE_16},
        {27011, GameType::SVEN_COOP},
        {27006, GameType::HALF_LIFE},
        {27010, GameType::HALF_LIFE},
    };
    
    auto it = default_ports.find(port);
    if (it != default_ports.end()) {
        return it->second;
    }
    
    return GameType::UNKNOWN;
}

bool GameProtector::is_game_query(const std::vector<uint8_t>& payload) {
    if (payload.size() < 5) return false;
    if (payload[0] != 0xFF || payload[1] != 0xFF || payload[2] != 0xFF || payload[3] != 0xFF) return false;
    
    uint8_t header = payload[4];
    return header == 0x49 || header == 0x54 || header == 0x55 || 
           header == 0x56 || header == 0x41 || header == 0x63;
}

bool GameProtector::is_source_engine_challenge(const std::vector<uint8_t>& payload) {
    if (payload.size() < 5) return false;
    if (payload[0] != 0xFF || payload[1] != 0xFF || payload[2] != 0xFF || payload[3] != 0xFF) return false;
    return payload[4] == 0x41;
}

std::vector<GameSignature> GameProtector::get_known_signatures() {
    return {
        {GameType::HALF_LIFE, "Half-Life A2S_INFO", {0xFF, 0xFF, 0xFF, 0xFF, 0x49}, {0,0,0,0,0xFF}, 27015, 47, "Half-Life server query"},
        {GameType::COUNTER_STRIKE_16, "CS 1.6 A2S_INFO", {0xFF, 0xFF, 0xFF, 0xFF, 0x49}, {0,0,0,0,0xFF}, 27015, 47, "Counter-Strike 1.6 server query"},
        {GameType::SVEN_COOP, "Sven Co-op A2S_INFO", {0xFF, 0xFF, 0xFF, 0xFF, 0x49}, {0,0,0,0,0xFF}, 27015, 47, "Sven Co-op server query"},
        {GameType::COUNTER_STRIKE_SOURCE, "CS:S A2S_INFO", {0xFF, 0xFF, 0xFF, 0xFF, 0x49}, {0,0,0,0,0xFF}, 27015, 47, "Counter-Strike: Source server query"},
        {GameType::COUNTER_STRIKE_GO, "CS:GO A2S_INFO", {0xFF, 0xFF, 0xFF, 0xFF, 0x49}, {0,0,0,0,0xFF}, 27015, 47, "Counter-Strike: Global Offensive server query"},
        {GameType::COUNTER_STRIKE_2, "CS2 A2S_INFO", {0xFF, 0xFF, 0xFF, 0xFF, 0x49}, {0,0,0,0,0xFF}, 27015, 47, "Counter-Strike 2 server query"},
        {GameType::GARRYS_MOD, "GMod A2S_INFO", {0xFF, 0xFF, 0xFF, 0xFF, 0x49}, {0,0,0,0,0xFF}, 27015, 47, "Garry's Mod server query"},
        {GameType::UNKNOWN, "A2S_PLAYER", {0xFF, 0xFF, 0xFF, 0xFF, 0x55}, {0,0,0,0,0xFF}, 0, 47, "Player list query"},
        {GameType::UNKNOWN, "A2S_RULES", {0xFF, 0xFF, 0xFF, 0xFF, 0x56}, {0,0,0,0,0xFF}, 0, 47, "Server rules query"},
        {GameType::UNKNOWN, "A2S_CHALLENGE", {0xFF, 0xFF, 0xFF, 0xFF, 0x41}, {0,0,0,0,0xFF}, 0, 47, "Challenge request"},
        {GameType::UNKNOWN, "RCON_COMMAND", {0xFF, 0xFF, 0xFF, 0xFF, 0x63}, {0,0,0,0,0xFF}, 0, 47, "RCON command"},
    };
}

std::string GameProtector::game_type_to_string(GameType game) {
    switch (game) {
        case GameType::HALF_LIFE: return "Half-Life";
        case GameType::HALF_LIFE_BLUE_SHIFT: return "Half-Life: Blue Shift";
        case GameType::HALF_LIFE_OPPOSING_FORCE: return "Half-Life: Opposing Force";
        case GameType::SVEN_COOP: return "Sven Co-op";
        case GameType::COUNTER_STRIKE_16: return "Counter-Strike 1.6";
        case GameType::COUNTER_STRIKE_CONDITION_ZERO: return "Counter-Strike: Condition Zero";
        case GameType::DAY_OF_DEFEAT: return "Day of Defeat";
        case GameType::TEAM_FORTRESS_CLASSIC: return "Team Fortress Classic";
        case GameType::GARRYS_MOD: return "Garry's Mod";
        case GameType::COUNTER_STRIKE_SOURCE: return "Counter-Strike: Source";
        case GameType::COUNTER_STRIKE_GO: return "Counter-Strike: Global Offensive";
        case GameType::COUNTER_STRIKE_2: return "Counter-Strike 2";
        case GameType::LEFT_4_DEAD: return "Left 4 Dead";
        case GameType::LEFT_4_DEAD_2: return "Left 4 Dead 2";
        case GameType::HALF_LIFE_2_DM: return "Half-Life 2: Deathmatch";
        case GameType::HALO: return "Halo";
        default: return "Unknown";
    }
}

std::string GameProtector::attack_type_to_string(AttackType attack) {
    switch (attack) {
        case AttackType::QUERY_FLOOD: return "Query Flood";
        case AttackType::CONNECTION_FLOOD: return "Connection Flood";
        case AttackType::PLAYER_FLOOD: return "Player Flood";
        case AttackType::RULES_FLOOD: return "Rules Flood";
        case AttackType::LOGIN_FLOOD: return "Login Flood";
        case AttackType::UDP_AMPLIFICATION: return "UDP Amplification";
        case AttackType::STATUS_FLOOD: return "Status Flood";
        case AttackType::CHALLENGE_FLOOD: return "Challenge Flood";
        case AttackType::SERVER_INFO_FLOOD: return "Server Info Flood";
        default: return "None";
    }
}

} // namespace game
} // namespace antiddos
