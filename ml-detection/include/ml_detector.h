#ifndef ML_DETECTOR_H
#define ML_DETECTOR_H

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <functional>
#include <mutex>
#include <memory>

namespace antiddos {
namespace ml {

enum class ModelType {
    ISOLATION_FOREST,
    RANDOM_FOREST,
    NEURAL_NETWORK,
    AUTOENCODER,
    SVM,
    DECISION_TREE
};

enum class ThreatClass {
    NORMAL,
    DDOS_SYN,
    DDOS_UDP,
    DDOS_HTTP,
    DDOS_DNS,
    SCANNER,
    BOT,
    BRUTE_FORCE,
    CREDENTIAL_STUFFING,
    WEB_SCRAPER,
    API_ABUSE,
    UNKNOWN
};

struct FeatureVector {
    double packets_per_second;
    double bytes_per_second;
    double syn_ratio;
    double ack_ratio;
    double fin_ratio;
    double rst_ratio;
    double avg_packet_size;
    double std_packet_size;
    double unique_ports;
    double unique_ips;
    double connection_duration;
    double payload_entropy;
    double header_consistency;
    double timing_regularity;
    double geo_dispersion;
    double protocol_distribution;
    
    std::vector<double> to_vector() const;
    static FeatureVector from_vector(const std::vector<double>& vec);
};

struct Prediction {
    ThreatClass threat_class;
    float confidence;
    float anomaly_score;
    std::string explanation;
    std::vector<double> feature_importance;
};

struct TrainingSample {
    FeatureVector features;
    ThreatClass label;
    std::string source;
};

class MLDetector {
public:
    MLDetector();
    ~MLDetector();
    
    bool load_model(const std::string& model_path, ModelType type);
    bool save_model(const std::string& model_path);
    bool train(const std::vector<TrainingSample>& samples);
    
    Prediction predict(const FeatureVector& features);
    std::vector<Prediction> predict_batch(const std::vector<FeatureVector>& features);
    
    void add_training_sample(const TrainingSample& sample);
    void clear_training_data();
    
    void set_threshold(float threshold);
    float get_accuracy() const;
    
    FeatureVector extract_features(
        uint64_t packets,
        uint64_t bytes,
        uint32_t syn_count,
        uint32_t ack_count,
        uint32_t fin_count,
        uint32_t rst_count,
        const std::vector<size_t>& packet_sizes,
        const std::vector<double>& intervals,
        uint32_t unique_ports,
        uint32_t unique_ips
    );
    
    void set_callback(std::function<void(const std::string&, ThreatClass, float)> callback);
    
    struct ModelStats {
        uint64_t predictions_made;
        uint32_t threats_detected;
        uint32_t false_positives;
        uint32_t false_negatives;
        float accuracy;
        float precision;
        float recall;
    };
    
    ModelStats get_stats() const;
    void reset_stats();
    
    void enable_online_learning(bool enable);
    void set_learning_rate(float rate);
    
private:
    struct IsolationForestImpl;
    struct NeuralNetworkImpl;
    
    std::unique_ptr<IsolationForestImpl> isolation_forest_;
    std::unique_ptr<NeuralNetworkImpl> neural_network_;
    
    mutable std::mutex mutex_;
    ModelType current_model_ = ModelType::ISOLATION_FOREST;
    float threshold_ = 0.5f;
    float learning_rate_ = 0.01f;
    bool online_learning_ = false;
    
    std::vector<TrainingSample> training_data_;
    std::unordered_map<ThreatClass, uint32_t> class_counts_;
    
    ModelStats stats_;
    std::function<void(const std::string&, ThreatClass, float)> callback_;
    
    void normalize_features(FeatureVector& features);
    ThreatClass classify_anomaly(float score);
    void update_stats(ThreatClass predicted, ThreatClass actual);
};

} // namespace ml
} // namespace antiddos

#endif // ML_DETECTOR_H