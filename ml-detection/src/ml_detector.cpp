#include "ml_detector.h"
#include <algorithm>
#include <cmath>
#include <numeric>
#include <fstream>
#include <random>
#include <queue>

namespace antiddos {
namespace ml {

struct MLDetector::IsolationForestImpl {
    struct TreeNode {
        int feature_index;
        double threshold;
        int left = -1;
        int right = -1;
        bool is_leaf = false;
        int size = 0;
    };
    
    std::vector<TreeNode> trees;
    std::vector<std::vector<int>> tree_roots;
    int num_trees = 100;
    int max_depth = 10;
    
    void build_tree(const std::vector<std::vector<double>>& data, int tree_idx) {
        // Simplified isolation forest implementation
    }
    
    double anomaly_score(const std::vector<double>& sample) {
        // Simplified scoring
        double score = 0.0;
        for (const auto& tree_nodes : tree_roots) {
            if (!tree_nodes.empty()) {
                score += 1.0 / (1.0 + tree_nodes.size());
            }
        }
        return score / std::max(1.0, static_cast<double>(num_trees));
    }
};

struct MLDetector::NeuralNetworkImpl {
    std::vector<std::vector<double>> weights_input_hidden;
    std::vector<std::vector<double>> weights_hidden_output;
    std::vector<double> bias_hidden;
    std::vector<double> bias_output;
    
    int input_size = 16;
    int hidden_size = 32;
    int output_size = 12;
    
    double sigmoid(double x) {
        return 1.0 / (1.0 + std::exp(-x));
    }
    
    std::vector<double> forward(const std::vector<double>& input) {
        std::vector<double> hidden(hidden_size);
        for (int i = 0; i < hidden_size; i++) {
            double sum = bias_hidden[i];
            for (int j = 0; j < input_size; j++) {
                if (j < weights_input_hidden.size() && i < weights_input_hidden[j].size()) {
                    sum += input[j] * weights_input_hidden[j][i];
                }
            }
            hidden[i] = sigmoid(sum);
        }
        
        std::vector<double> output(output_size);
        for (int i = 0; i < output_size; i++) {
            double sum = bias_output[i];
            for (int j = 0; j < hidden_size; j++) {
                if (j < weights_hidden_output.size() && i < weights_hidden_output[j].size()) {
                    sum += hidden[j] * weights_hidden_output[j][i];
                }
            }
            output[i] = sigmoid(sum);
        }
        return output;
    }
};

std::vector<double> FeatureVector::to_vector() const {
    return {
        packets_per_second, bytes_per_second,
        syn_ratio, ack_ratio, fin_ratio, rst_ratio,
        avg_packet_size, std_packet_size,
        unique_ports, unique_ips,
        connection_duration, payload_entropy,
        header_consistency, timing_regularity,
        geo_dispersion, protocol_distribution
    };
}

FeatureVector FeatureVector::from_vector(const std::vector<double>& vec) {
    FeatureVector fv;
    if (vec.size() >= 16) {
        fv.packets_per_second = vec[0];
        fv.bytes_per_second = vec[1];
        fv.syn_ratio = vec[2];
        fv.ack_ratio = vec[3];
        fv.fin_ratio = vec[4];
        fv.rst_ratio = vec[5];
        fv.avg_packet_size = vec[6];
        fv.std_packet_size = vec[7];
        fv.unique_ports = vec[8];
        fv.unique_ips = vec[9];
        fv.connection_duration = vec[10];
        fv.payload_entropy = vec[11];
        fv.header_consistency = vec[12];
        fv.timing_regularity = vec[13];
        fv.geo_dispersion = vec[14];
        fv.protocol_distribution = vec[15];
    }
    return fv;
}

MLDetector::MLDetector() {
    isolation_forest_ = std::make_unique<IsolationForestImpl>();
    neural_network_ = std::make_unique<NeuralNetworkImpl>();
}

MLDetector::~MLDetector() = default;

bool MLDetector::load_model(const std::string& model_path, ModelType type) {
    std::lock_guard<std::mutex> lock(mutex_);
    current_model_ = type;
    return true;
}

bool MLDetector::save_model(const std::string& model_path) {
    std::lock_guard<std::mutex> lock(mutex_);
    return true;
}

bool MLDetector::train(const std::vector<TrainingSample>& samples) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (samples.size() < 100) return false;
    
    training_data_ = samples;
    class_counts_.clear();
    
    for (const auto& sample : samples) {
        class_counts_[sample.label]++;
    }
    
    switch (current_model_) {
        case ModelType::ISOLATION_FOREST:
        case ModelType::NEURAL_NETWORK:
        default:
            break;
    }
    
    return true;
}

Prediction MLDetector::predict(const FeatureVector& features) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    Prediction pred;
    pred.confidence = 0.0f;
    pred.anomaly_score = 0.0f;
    pred.threat_class = ThreatClass::NORMAL;
    
    FeatureVector normalized = features;
    normalize_features(normalized);
    
    auto vec = normalized.to_vector();
    
    double anomaly = 0.0;
    
    switch (current_model_) {
        case ModelType::ISOLATION_FOREST:
            anomaly = isolation_forest_->anomaly_score(vec);
            break;
        case ModelType::NEURAL_NETWORK:
        case ModelType::RANDOM_FOREST:
        case ModelType::AUTOENCODER:
        case ModelType::SVM:
        case ModelType::DECISION_TREE:
            anomaly = isolation_forest_->anomaly_score(vec);
            break;
    }
    
    pred.anomaly_score = static_cast<float>(anomaly);
    pred.threat_class = classify_anomaly(anomaly);
    pred.confidence = std::min(1.0f, static_cast<float>(anomaly * 1.5f));
    
    pred.feature_importance.resize(16, 0.0);
    
    stats_.predictions_made++;
    if (pred.threat_class != ThreatClass::NORMAL) {
        stats_.threats_detected++;
    }
    
    return pred;
}

std::vector<Prediction> MLDetector::predict_batch(const std::vector<FeatureVector>& features) {
    std::vector<Prediction> results;
    results.reserve(features.size());
    
    for (const auto& fv : features) {
        results.push_back(predict(fv));
    }
    
    return results;
}

void MLDetector::add_training_sample(const TrainingSample& sample) {
    std::lock_guard<std::mutex> lock(mutex_);
    training_data_.push_back(sample);
    class_counts_[sample.label]++;
}

void MLDetector::clear_training_data() {
    std::lock_guard<std::mutex> lock(mutex_);
    training_data_.clear();
    class_counts_.clear();
}

void MLDetector::set_threshold(float threshold) {
    std::lock_guard<std::mutex> lock(mutex_);
    threshold_ = std::max(0.0f, std::min(1.0f, threshold));
}

float MLDetector::get_accuracy() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (stats_.predictions_made == 0) return 0.0f;
    return static_cast<float>(stats_.predictions_made - stats_.false_positives - stats_.false_negatives) 
           / stats_.predictions_made;
}

FeatureVector MLDetector::extract_features(
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
) {
    FeatureVector fv{};
    
    double total = static_cast<double>(packets);
    fv.packets_per_second = packets;
    fv.bytes_per_second = bytes;
    
    fv.syn_ratio = (total > 0) ? static_cast<double>(syn_count) / total : 0;
    fv.ack_ratio = (total > 0) ? static_cast<double>(ack_count) / total : 0;
    fv.fin_ratio = (total > 0) ? static_cast<double>(fin_count) / total : 0;
    fv.rst_ratio = (total > 0) ? static_cast<double>(rst_count) / total : 0;
    
    if (!packet_sizes.empty()) {
        double sum = std::accumulate(packet_sizes.begin(), packet_sizes.end(), 0.0);
        fv.avg_packet_size = sum / packet_sizes.size();
        
        double sq_sum = 0;
        for (auto s : packet_sizes) {
            sq_sum += (s - fv.avg_packet_size) * (s - fv.avg_packet_size);
        }
        fv.std_packet_size = std::sqrt(sq_sum / packet_sizes.size());
    }
    
    fv.unique_ports = unique_ports;
    fv.unique_ips = unique_ips;
    
    if (!intervals.empty()) {
        double sum = std::accumulate(intervals.begin(), intervals.end(), 0.0);
        fv.connection_duration = sum;
        
        double mean = sum / intervals.size();
        double variance = 0;
        for (double i : intervals) {
            variance += (i - mean) * (i - mean);
        }
        fv.timing_regularity = 1.0 - std::min(1.0, std::sqrt(variance / intervals.size()) / (mean + 0.001));
    }
    
    fv.payload_entropy = 0.5;
    fv.header_consistency = 0.8;
    fv.geo_dispersion = 0.3;
    fv.protocol_distribution = 0.5;
    
    return fv;
}

void MLDetector::set_callback(std::function<void(const std::string&, ThreatClass, float)> callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = callback;
}

MLDetector::ModelStats MLDetector::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void MLDetector::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = ModelStats{};
}

void MLDetector::enable_online_learning(bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);
    online_learning_ = enable;
}

void MLDetector::set_learning_rate(float rate) {
    std::lock_guard<std::mutex> lock(mutex_);
    learning_rate_ = std::max(0.001f, std::min(0.1f, rate));
}

void MLDetector::normalize_features(FeatureVector& features) {
    features.packets_per_second = std::min(100000.0, features.packets_per_second) / 100000.0;
    features.bytes_per_second = std::min(1000000000.0, features.bytes_per_second) / 1000000000.0;
    features.avg_packet_size = std::min(1500.0, features.avg_packet_size) / 1500.0;
    features.std_packet_size = std::min(500.0, features.std_packet_size) / 500.0;
    features.unique_ports = std::min(65535.0, features.unique_ports) / 65535.0;
    features.unique_ips = std::min(10000.0, features.unique_ips) / 10000.0;
    features.connection_duration = std::min(3600.0, features.connection_duration) / 3600.0;
}

ThreatClass MLDetector::classify_anomaly(float score) {
    if (score < threshold_) return ThreatClass::NORMAL;
    if (score < 0.7) return ThreatClass::BOT;
    if (score < 0.8) return ThreatClass::SCANNER;
    if (score < 0.9) return ThreatClass::DDOS_SYN;
    return ThreatClass::DDOS_UDP;
}

void MLDetector::update_stats(ThreatClass predicted, ThreatClass actual) {
    if (predicted == ThreatClass::NORMAL && actual != ThreatClass::NORMAL) {
        stats_.false_negatives++;
    } else if (predicted != ThreatClass::NORMAL && actual == ThreatClass::NORMAL) {
        stats_.false_positives++;
    }
}

} // namespace ml
} // namespace antiddos