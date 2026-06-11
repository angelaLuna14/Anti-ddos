// SPDX-License-Identifier: GPL-2.0
// Anti-DDoS XDP/eBPF Kernel Filter
// Runs in kernel space for real-time packet processing (<0.1ms)

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_filter.h"

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_IP_ENTRIES);
    __type(key, __u32);
    __type(value, struct ip_entry);
} ip_blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_RATE_LIMIT_ENTRIES);
    __type(key, __u32);
    __type(value, struct rate_limit_entry);
} rate_limit_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_PORT_ENTRIES);
    __type(key, __u32);
    __type(value, struct port_entry);
} port_filter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_stats);
} stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_IP_ENTRIES);
    __type(key, __u32);
    __type(value, struct syn_flood_defense);
} syn_tracker SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_IP_ENTRIES);
    __type(key, __u32);
    __type(value, struct udp_flood_defense);
} udp_tracker SEC(".maps");

static __always_inline void update_stats(__u32 action) {
    __u32 key = 0;
    struct xdp_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
    if (!stats) return;
    
    stats->total_packets++;
    
    switch (action) {
        case ACTION_PASS:
            stats->passed_packets++;
            break;
        case ACTION_DROP:
            stats->dropped_packets++;
            break;
        case ACTION_REDIRECT:
            stats->redirected_packets++;
            break;
    }
}

static __always_inline int check_blacklist(__u32 src_ip) {
    struct ip_entry *entry = bpf_map_lookup_elem(&ip_blacklist, &src_ip);
    if (entry) {
        if (entry->action == ACTION_DROP) {
            entry->packets++;
            return ACTION_DROP;
        }
    }
    return ACTION_PASS;
}

static __always_inline int check_rate_limit(__u32 src_ip, struct xdp_config *config) {
    if (!config->enable_rate_limiting) return ACTION_PASS;
    
    struct rate_limit_entry *entry = bpf_map_lookup_elem(&rate_limit_map, &src_ip);
    if (!entry) {
        struct rate_limit_entry new_entry = {
            .ip = src_ip,
            .token_count = config->rate_limit_pps,
            .last_refill = bpf_ktime_get_ns() / 1000000000,
            .max_tokens = config->rate_limit_pps,
            .refill_rate = config->rate_limit_pps,
            .action = ACTION_DROP,
        };
        bpf_map_update_elem(&rate_limit_map, &src_ip, &new_entry, BPF_ANY);
        return ACTION_PASS;
    }
    
    __u64 now = bpf_ktime_get_ns() / 1000000000;
    __u64 elapsed = now - entry->last_refill;
    
    if (elapsed > 1) {
        entry->token_count = entry->max_tokens;
        entry->last_refill = now;
    }
    
    if (entry->token_count == 0) {
        return entry->action;
    }
    
    entry->token_count--;
    return ACTION_PASS;
}

static __always_inline int check_syn_flood(__u32 src_ip, struct xdp_config *config) {
    if (!config->enable_syn_defense) return ACTION_PASS;
    
    struct syn_flood_defense *entry = bpf_map_lookup_elem(&syn_tracker, &src_ip);
    if (!entry) {
        struct syn_flood_defense new_entry = {
            .syn_count = 1,
            .syn_ack_count = 0,
            .window_start = bpf_ktime_get_ns() / 1000000000,
            .threshold = config->syn_threshold,
            .action = ACTION_DROP,
        };
        bpf_map_update_elem(&syn_tracker, &src_ip, &new_entry, BPF_ANY);
        return ACTION_PASS;
    }
    
    __u64 now = bpf_ktime_get_ns() / 1000000000;
    if (now - entry->window_start > config->syn_window_ms / 1000) {
        entry->syn_count = 1;
        entry->window_start = now;
        return ACTION_PASS;
    }
    
    entry->syn_count++;
    
    if (entry->syn_count > entry->threshold) {
        return entry->action;
    }
    
    return ACTION_PASS;
}

static __always_inline int check_udp_flood(__u32 src_ip, struct xdp_config *config) {
    if (!config->enable_udp_defense) return ACTION_PASS;
    
    struct udp_flood_defense *entry = bpf_map_lookup_elem(&udp_tracker, &src_ip);
    if (!entry) {
        struct udp_flood_defense new_entry = {
            .packet_count = 1,
            .byte_count = 0,
            .window_start = bpf_ktime_get_ns() / 1000000000,
            .pps_threshold = config->udp_pps_threshold,
            .bps_threshold = config->udp_bps_threshold,
            .action = ACTION_DROP,
        };
        bpf_map_update_elem(&udp_tracker, &src_ip, &new_entry, BPF_ANY);
        return ACTION_PASS;
    }
    
    __u64 now = bpf_ktime_get_ns() / 1000000000;
    if (now - entry->window_start > 1) {
        entry->packet_count = 0;
        entry->byte_count = 0;
        entry->window_start = now;
        return ACTION_PASS;
    }
    
    entry->packet_count++;
    
    if (entry->packet_count > entry->pps_threshold) {
        return entry->action;
    }
    
    return ACTION_PASS;
}

SEC("xdp")
int xdp_filter_main(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;
    
    __u32 src_ip = ip->saddr;
    
    __u32 config_key = 0;
    struct xdp_config *config = bpf_map_lookup_elem(&config_map, &config_key);
    if (!config) {
        return XDP_PASS;
    }
    
    int action = check_blacklist(src_ip);
    if (action == ACTION_DROP) {
        update_stats(ACTION_DROP);
        return XDP_DROP;
    }
    
    action = check_rate_limit(src_ip, config);
    if (action == ACTION_DROP) {
        update_stats(ACTION_DROP);
        return XDP_DROP;
    }
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);
        if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
            return XDP_PASS;
        
        if (tcp->syn && !tcp->ack) {
            action = check_syn_flood(src_ip, config);
            if (action == ACTION_DROP) {
                update_stats(ACTION_DROP);
                return XDP_DROP;
            }
        }
        
        __u32 port_key = (__u32)tcp->dest;
        struct port_entry *port = bpf_map_lookup_elem(&port_filter, &port_key);
        if (port && port->action == ACTION_DROP) {
            update_stats(ACTION_DROP);
            return XDP_DROP;
        }
    }
    
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip);
        if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
            return XDP_PASS;
        
        action = check_udp_flood(src_ip, config);
        if (action == ACTION_DROP) {
            update_stats(ACTION_DROP);
            return XDP_DROP;
        }
        
        __u32 port_key = (__u32)udp->dest;
        struct port_entry *port = bpf_map_lookup_elem(&port_filter, &port_key);
        if (port && port->action == ACTION_DROP) {
            update_stats(ACTION_DROP);
            return XDP_DROP;
        }
    }
    
    update_stats(ACTION_PASS);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";