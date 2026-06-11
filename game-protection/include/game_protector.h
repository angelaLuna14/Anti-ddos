#ifndef GAME_PROTECTOR_H
#define GAME_PROTECTOR_H

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>
#include <functional>
#include <mutex>
#include <chrono>

namespace antiddos {
namespace game {

enum class GameType {
    UNKNOWN,
    HALF_LIFE,
    HALF_LIFE_BLUE_SHIFT,
    HALF_LIFE_OPPOSING_FORCE,
    SVEN_COOP,
    COUNTER_STRIKE_16,
    COUNTER_STRIKE_CONDITION_ZERO,
    DAY_OF_DEFEAT,
    TEAM_FORTRESS_CLASSIC,
    GARRYS_MOD,
    COUNTER_STRIKE_SOURCE,
    COUNTER_STRIKE_GO,
    COUNTER_STRIKE_2,
    LEFT_4_DEAD,
    LEFT_4_DEAD_2,
    HALF_LIFE_2_DM,
    HALO
};

enum class AttackType {
    NONE,
    QUERY_FLOOD,
    CONNECTION_FLOOD,
    PLAYER_FLOOD,
    RULES_FLOOD,
    LOGIN_FLOOD,
    UDP_AMPLIFICATION,
    STATUS_FLOOD,
    CHALLENGE_FLOOD,
    SERVER_INFO_FLOOD
};

struct GameSignature {
    GameType game;
    std::string name;
    std::vector<uint8_t> pattern;
    std::vector<uint8_t> mask;
    uint16_t port;
    uint8_t protocol;
    std::string description;
};

struct GameServerInfo {
    GameType game;
    std::string name;
    std::string map;
    uint16_t max_players;
    uint16_t current_players;
    uint16_t bot_count;
    uint16_t game_port;
    uint16_t query_port;
    bool is_passworded;
    bool is_vac_secured;
    std::string version;
    std::string os;
};

struct ConnectionInfo {
    std::string src_ip;
    uint16_t src_port;
    uint16_t dst_port;
    GameType game;
    AttackType attack_type;
    float confidence;
    uint64_t packet_count;
    uint64_t byte_count;
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
};

struct GameProtectionConfig {
    uint32_t max_queries_per_second = 50;
    uint32_t max_queries_per_minute = 1000;
    uint32_t max_connections_per_second = 10;
    uint32_t max_players_per_ip = 1;
    uint32_t challenge_timeout_seconds = 30;
    uint32_t connection_timeout_seconds = 10;
    uint32_t auto_block_duration_seconds = 300;
    bool enable_query_flood_protection = true;
    bool enable_connection_flood_protection = true;
    bool enable_login_flood_protection = true;
    bool enable_amplification_protection = true;
    bool auto_block_attacker = true;
    float attack_confidence_threshold = 0.7f;
};

struct GameProtectionStats {
    uint64_t total_packets_analyzed = 0;
    uint64_t total_queries_blocked = 0;
    uint64_t total_connections_blocked = 0;
    uint64_t total_attacks_detected = 0;
    uint32_t active_connections = 0;
    uint32_t blocked_ips = 0;
    std::unordered_map<GameType, uint64_t> packets_by_game;
    std::unordered_map<AttackType, uint64_t> attacks_by_type;
};

using AttackCallback = std::function<void(const std::string& ip, GameType game, AttackType attack, float confidence)>;

class GameProtector {
public:
    GameProtector();
    ~GameProtector();
    
    void set_config(const GameProtectionConfig& config);
    GameProtectionConfig get_config() const;
    
    void add_game_server(uint16_t port, GameType game);
    void remove_game_server(uint16_t port);
    void set_server_info(uint16_t port, const GameServerInfo& info);
    
    bool analyze_packet(const std::string& src_ip, uint16_t src_port,
                       uint16_t dst_port, const std::vector<uint8_t>& payload,
                       uint32_t packet_size);
    
    bool is_query_flood(const std::string& src_ip, uint16_t dst_port) const;
    bool is_connection_flood(const std::string& src_ip, uint16_t dst_port) const;
    
    void block_ip(const std::string& ip, uint32_t duration_seconds, const std::string& reason);
    void unblock_ip(const std::string& ip);
    bool is_blocked(const std::string& ip) const;
    
    void add_trusted_ip(const std::string& ip);
    void remove_trusted_ip(const std::string& ip);
    bool is_trusted(const std::string& ip) const;
    
    void set_attack_callback(AttackCallback callback);
    
    GameProtectionStats get_stats() const;
    void reset_stats();
    
    std::vector<std::string> get_blocked_ips() const;
    std::vector<std::string> get_active_connections() const;
    
    static GameType detect_game_from_payload(const std::vector<uint8_t>& payload, uint16_t port);
    static bool is_game_query(const std::vector<uint8_t>& payload);
    static bool is_source_engine_challenge(const std::vector<uint8_t>& payload);
    
    static std::vector<GameSignature> get_known_signatures();
    static std::string game_type_to_string(GameType game);
    static std::string attack_type_to_string(AttackType attack);
    
private:
    struct QueryTracker {
        uint32_t query_count = 0;
        uint32_t connection_count = 0;
        std::chrono::steady_clock::time_point window_start;
        std::chrono::steady_clock::time_point last_query;
    };
    
    struct BlockedEntry {
        std::string ip;
        std::chrono::steady_clock::time_point blocked_at;
        uint32_t duration_seconds;
        std::string reason;
    };
    
    mutable std::mutex mutex_;
    GameProtectionConfig config_;
    GameProtectionStats stats_;
    
    std::unordered_map<uint16_t, GameType> game_ports_;
    std::unordered_map<uint16_t, GameServerInfo> server_infos_;
    std::unordered_map<std::string, QueryTracker> query_trackers_;
    std::vector<BlockedEntry> blocked_ips_;
    std::unordered_set<std::string> trusted_ips_;
    
    AttackCallback callback_;
    
    bool check_query_flood(const std::string& src_ip, uint16_t dst_port);
    bool check_connection_flood(const std::string& src_ip, uint16_t dst_port);
    void update_tracker(const std::string& src_ip, uint16_t dst_port, bool is_query);
    void trigger_block(const std::string& src_ip, uint32_t duration, const std::string& reason);
    void cleanup_expired_blocks();
    
    bool detect_a2s_info(const std::vector<uint8_t>& payload) const;
    bool detect_a2s_player(const std::vector<uint8_t>& payload) const;
    bool detect_a2s_rules(const std::vector<uint8_t>& payload) const;
    bool detect_a2s_challenge(const std::vector<uint8_t>& payload) const;
    bool detect_connect_request(const std::vector<uint8_t>& payload) const;
    bool detect_rcon(const std::vector<uint8_t>& payload) const;
};

} // namespace game
} // namespace antiddos

#endif // GAME_PROTECTOR_H
