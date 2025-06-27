#include "secure_exceptions.hpp"
#include "stealth_macros.hpp"
#include "secure_memory.hpp"
#include "stealth_macros.hpp"
#include "entropy_analysis.hpp"
#include "stealth_macros.hpp"
#include <cmath>
#include <algorithm>
#include <numeric>
#include <map>
#include <array>
#include "stealth_macros.hpp"
#include "stealth_macros.hpp"

double EntropyAnalysis::calculate_shannon_entropy(const std::vector<uint8_t>& data) {
    if (data.empty()) return 0.0;
    
    // Count byte frequencies
    std::array<size_t, 256> frequencies = {};
    for (uint8_t byte : data) {
        frequencies[byte]++;
    }
    
    // Calculate Shannon entropy
    double entropy = 0.0;
    double data_size = static_cast<double>(data.size());
    
    for (size_t freq : frequencies) {
        if (freq > 0) {
            double probability = static_cast<double>(freq) / data_size;
            entropy -= probability * std::log2(probability);
        }
    }
    
    return entropy;
}

std::map<std::string, double> EntropyAnalysis::analyze_entropy_distribution(const std::vector<uint8_t>& data) {
    std::map<std::string, double> analysis;
    
    if (data.empty()) {
        analysis["overall_entropy"] = 0.0;
        analysis["compression_ratio"] = 0.0;
        analysis["randomness_score"] = 0.0;
        return analysis;
    }
    
    // Overall entropy
    analysis["overall_entropy"] = calculate_shannon_entropy(data);
    
    // Block-wise entropy analysis
    const size_t block_size = 1024;
    std::vector<double> block_entropies;
    
    for (size_t i = 0; i < data.size(); i += block_size) {
        size_t end = std::min(i + block_size, data.size());
        std::vector<uint8_t> block(data.begin() + i, data.begin() + end);
        block_entropies.push_back(calculate_shannon_entropy(block));
    }
    
    // Calculate entropy variance
    if (!block_entropies.empty()) {
        double mean_entropy = std::accumulate(block_entropies.begin(), block_entropies.end(), 0.0) / block_entropies.size();
        double variance = 0.0;
        
        for (double entropy : block_entropies) {
            variance += (entropy - mean_entropy) * (entropy - mean_entropy);
        }
        variance /= block_entropies.size();
        
        analysis["entropy_variance"] = variance;
        analysis["entropy_stability"] = 1.0 / (1.0 + variance);
    }
    
    // Estimate compression ratio
    std::map<uint8_t, size_t> byte_counts;
    for (uint8_t byte : data) {
        byte_counts[byte]++;
    }
    
    double estimated_compressed_size = 0.0;
    for (const auto& kv : byte_counts) {
        if (kv.second > 0) {
            double probability = static_cast<double>(kv.second) / data.size();
            estimated_compressed_size += kv.second * (-std::log2(probability));
        }
    }
    estimated_compressed_size /= 8.0; // Convert bits to bytes
    
    analysis["compression_ratio"] = estimated_compressed_size / data.size();
    analysis["randomness_score"] = analysis["overall_entropy"] / 8.0; // Normalize to 0-1
    
    return analysis;
}

std::vector<double> EntropyAnalysis::calculate_block_entropies(const std::vector<uint8_t>& data, size_t block_size) {
    std::vector<double> block_entropies;
    
    for (size_t i = 0; i < data.size(); i += block_size) {
        size_t end = std::min(i + block_size, data.size());
        std::vector<uint8_t> block(data.begin() + i, data.begin() + end);
        block_entropies.push_back(calculate_shannon_entropy(block));
    }
    
    return block_entropies;
}

double EntropyAnalysis::calculate_conditional_entropy(const std::vector<uint8_t>& data) {
    if (data.size() < 2) return 0.0;
    
    // Calculate conditional entropy H(X|Y) where Y is the previous byte
    std::map<std::pair<uint8_t, uint8_t>, size_t> pair_counts;
    std::map<uint8_t, size_t> single_counts;
    
    for (size_t i = 1; i < data.size(); ++i) {
        uint8_t prev = data[i-1];
        uint8_t curr = data[i];
        
        pair_counts[{prev, curr}]++;
        single_counts[prev]++;
    }
    
    double conditional_entropy = 0.0;
    size_t total_pairs = data.size() - 1;
    
    for (const auto& pair : pair_counts) {
        uint8_t prev_byte = pair.first.first;
        size_t pair_count = pair.second;
        size_t prev_count = single_counts[prev_byte];
        
        if (pair_count > 0 && prev_count > 0) {
            double joint_prob = static_cast<double>(pair_count) / total_pairs;
            double conditional_prob = static_cast<double>(pair_count) / prev_count;
            
            conditional_entropy -= joint_prob * std::log2(conditional_prob);
        }
    }
    
    return conditional_entropy;
}

std::vector<double> EntropyAnalysis::calculate_mutual_information(const std::vector<uint8_t>& data) {
    std::vector<double> mi_values;
    
    if (data.size() < 2) return mi_values;
    
    // Calculate mutual information between consecutive bytes
    double joint_entropy = calculate_joint_entropy(data, 1);
    double marginal_entropy = calculate_shannon_entropy(data);
    
    // MI(X,Y) = H(X) + H(Y) - H(X,Y)
    double mutual_info = 2 * marginal_entropy - joint_entropy;
    mi_values.push_back(mutual_info);
    
    return mi_values;
}

double EntropyAnalysis::calculate_joint_entropy(const std::vector<uint8_t>& data, size_t lag) {
    if (data.size() <= lag) return 0.0;
    
    std::map<std::pair<uint8_t, uint8_t>, size_t> pair_counts;
    
    for (size_t i = lag; i < data.size(); ++i) {
        uint8_t x = data[i - lag];
        uint8_t y = data[i];
        pair_counts[{x, y}]++;
    }
    
    double joint_entropy = 0.0;
    size_t total_pairs = data.size() - lag;
    
    for (const auto& pair : pair_counts) {
        size_t count = pair.second;
        if (count > 0) {
            double probability = static_cast<double>(count) / total_pairs;
            joint_entropy -= probability * std::log2(probability);
        }
    }
    
    return joint_entropy;
}

std::map<uint8_t, double> EntropyAnalysis::calculate_byte_frequency_distribution(const std::vector<uint8_t>& data) {
    std::map<uint8_t, double> distribution;
    
    if (data.empty()) return distribution;
    
    std::map<uint8_t, size_t> counts;
    for (uint8_t byte : data) {
        counts[byte]++;
    }
    
    double total = static_cast<double>(data.size());
    for (const auto& kv : counts) {
        distribution[kv.first] = static_cast<double>(kv.second) / total;
    }
    
    return distribution;
}

double EntropyAnalysis::estimate_kolmogorov_complexity(const std::vector<uint8_t>& data) {
    if (data.empty()) return 0.0;
    
    // Simple approximation using compression-based complexity
    std::map<std::vector<uint8_t>, size_t> pattern_counts;
    
    // Count patterns of different lengths
    for (size_t pattern_len = 1; pattern_len <= std::min(data.size(), size_t(8)); ++pattern_len) {
        for (size_t i = 0; i <= data.size() - pattern_len; ++i) {
            std::vector<uint8_t> pattern(data.begin() + i, data.begin() + i + pattern_len);
            pattern_counts[pattern]++;
        }
    }
    
    // Estimate complexity based on unique patterns
    double complexity = 0.0;
    for (const auto& pattern : pattern_counts) {
        if (pattern.second == 1) { // Unique patterns contribute more to complexity
            complexity += pattern.first.size();
        }
    }
    
    return complexity / data.size(); // Normalize by data size
}

std::vector<double> EntropyAnalysis::calculate_autocorrelation_coefficients(const std::vector<uint8_t>& data, size_t max_lag) {
    std::vector<double> coefficients;
    
    if (data.size() <= max_lag) return coefficients;
    
    // Convert to double for calculations
    std::vector<double> signal(data.begin(), data.end());
    
    // Calculate mean
    double mean = std::accumulate(signal.begin(), signal.end(), 0.0) / signal.size();
    
    // Center the signal
    for (double& val : signal) {
        val -= mean;
    }
    
    // Calculate autocorrelation for each lag
    for (size_t lag = 1; lag <= max_lag && lag < signal.size(); ++lag) {
        double numerator = 0.0;
        double denominator = 0.0;
        
        for (size_t i = 0; i < signal.size() - lag; ++i) {
            numerator += signal[i] * signal[i + lag];
        }
        
        for (size_t i = 0; i < signal.size(); ++i) {
            denominator += signal[i] * signal[i];
        }
        
        if (denominator > 0) {
            coefficients.push_back(numerator / denominator);
        } else {
            coefficients.push_back(0.0);
        }
    }
    
    return coefficients;
}

double EntropyAnalysis::calculate_chi_square_statistic(const std::vector<uint8_t>& data) {
    if (data.empty()) return 0.0;
    
    // Calculate observed frequencies
    std::array<size_t, 256> observed = {};
    for (uint8_t byte : data) {
        observed[byte]++;
    }
    
    // Expected frequency for uniform distribution
    double expected = static_cast<double>(data.size()) / 256.0;
    
    // Calculate chi-square statistic
    double chi_square = 0.0;
    for (size_t freq : observed) {
        double diff = static_cast<double>(freq) - expected;
        chi_square += (diff * diff) / expected;
    }
    
    return chi_square;
}