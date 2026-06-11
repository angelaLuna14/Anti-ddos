#ifndef DPDK_ENGINE_H
#define DPDK_ENGINE_H

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <thread>
#include <atomic>

namespace antiddos {
namespace dpdk {

struct DPDKConfig {
    std::string interface = "eth0";
    uint32_t core_mask = 1;
    uint32_t memory_mb = 256;
    uint32_t rx_queues = 4;
    uint32_t tx_queues = 4;
    uint32_t rx_ring_size = 1024;
    uint32_t tx_ring_size = 1024;
    uint32_t burst_size = 32;
};

struct PacketBuffer {
    uint8_t* data;
    uint32_t length;
    uint16_t port;
    uint16_t queue;
    uint64_t timestamp;
};

using PacketCallback = std::function<void(PacketBuffer&)>;

class DPDKEngine {
public:
    DPDKEngine();
    ~DPDKEngine();
    
    bool initialize(const DPDKConfig& config);
    void shutdown();
    bool is_initialized() const;
    
    void set_packet_callback(PacketCallback callback);
    
    void start_capture();
    void stop_capture();
    
    void send_packet(const uint8_t* data, uint32_t length, uint16_t port);
    void send_bulk(const std::vector<PacketBuffer>& packets);
    
    struct Stats {
        uint64_t rx_packets = 0;
        uint64_t tx_packets = 0;
        uint64_t rx_bytes = 0;
        uint64_t tx_bytes = 0;
        uint64_t rx_dropped = 0;
        uint64_t tx_dropped = 0;
        uint64_t rx_errors = 0;
        uint64_t tx_errors = 0;
    };
    
    Stats get_stats() const;
    void reset_stats();
    
    static bool is_dpdk_available();
    static std::vector<std::string> get_available_ports();
    
private:
    void capture_loop();
    
    DPDKConfig config_;
    Stats stats_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> capturing_{false};
    std::thread capture_thread_;
    PacketCallback callback_;
};

} // namespace dpdk
} // namespace antiddos

#endif // DPDK_ENGINE_H