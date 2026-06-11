#ifndef XDP_FILTER_H
#define XDP_FILTER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#define MAX_IP_ENTRIES 65536
#define MAX_PORT_ENTRIES 4096
#define MAX_RATE_LIMIT_ENTRIES 16384
#define MAX_BLACKLIST_ENTRIES 32768
#define MAX_CIDR_ENTRIES 8192

#define ACTION_PASS 0
#define ACTION_DROP 1
#define ACTION_REDIRECT 2
#define ACTION_TX 3

struct ip_entry {
    uint32_t ip;
    uint32_t mask;
    uint32_t action;
    uint64_t packets;
    uint64_t bytes;
    uint32_t timestamp;
    uint32_t flags;
};

struct port_entry {
    uint16_t port;
    uint16_t protocol;
    uint32_t action;
    uint64_t packets;
    uint32_t max_rate;
    uint32_t current_rate;
    uint32_t window_start;
};

struct rate_limit_entry {
    uint32_t ip;
    uint32_t token_count;
    uint32_t last_refill;
    uint32_t max_tokens;
    uint32_t refill_rate;
    uint32_t action;
};

struct blacklist_entry {
    uint32_t ip;
    uint32_t expire_time;
    uint32_t reason;
    uint64_t packets_dropped;
};

struct cidr_entry {
    uint32_t network;
    uint32_t prefix;
    uint32_t action;
    uint64_t packets;
    uint64_t bytes;
    uint32_t expire_time;
};

struct syn_flood_defense {
    uint32_t syn_count;
    uint32_t syn_ack_count;
    uint32_t window_start;
    uint32_t threshold;
    uint32_t action;
};

struct udp_flood_defense {
    uint32_t packet_count;
    uint32_t byte_count;
    uint32_t window_start;
    uint32_t pps_threshold;
    uint32_t bps_threshold;
    uint32_t action;
};

struct amplification_defense {
    uint32_t packet_count;
    uint32_t window_start;
    uint32_t threshold;
    uint16_t amp_ports[8];
    uint32_t action;
};

struct xdp_stats {
    uint64_t total_packets;
    uint64_t passed_packets;
    uint64_t dropped_packets;
    uint64_t redirected_packets;
    uint64_t syn_flood_drops;
    uint64_t udp_flood_drops;
    uint64_t amplification_drops;
    uint64_t blacklist_drops;
    uint64_t cidr_drops;
    uint64_t rate_limit_drops;
    uint32_t active_connections;
    uint32_t blocked_ips;
    uint32_t blocked_cidrs;
    uint32_t last_update;
};

struct xdp_config {
    uint32_t syn_threshold;
    uint32_t syn_window_ms;
    uint32_t udp_pps_threshold;
    uint32_t udp_bps_threshold;
    uint32_t amp_threshold;
    uint32_t rate_limit_pps;
    uint32_t blacklist_duration_sec;
    uint32_t enable_syn_defense;
    uint32_t enable_udp_defense;
    uint32_t enable_amp_defense;
    uint32_t enable_rate_limiting;
    uint32_t enable_blacklist;
    uint32_t default_action;
};

#ifdef __cplusplus
}
#endif

#endif // XDP_FILTER_H