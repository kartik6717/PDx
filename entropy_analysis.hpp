#pragma once

#include <vector>
#include <map>
#include <string>
#include <cstdint>

class EntropyAnalysis {
public:
    // Core entropy calculation methods
    static double calculate_shannon_entropy(const std::vector<uint8_t>& data);
    static std::map<std::string, double> analyze_entropy_distribution(const std::vector<uint8_t>& data);
    
    // Block-based analysis
    static std::vector<double> calculate_block_entropies(const std::vector<uint8_t>& data, size_t block_size = 1024);
    
    // Advanced entropy measures
    static double calculate_conditional_entropy(const std::vector<uint8_t>& data);
    static std::vector<double> calculate_mutual_information(const std::vector<uint8_t>& data);
    static double calculate_joint_entropy(const std::vector<uint8_t>& data, size_t lag);
    
    // Statistical analysis
    static std::map<uint8_t, double> calculate_byte_frequency_distribution(const std::vector<uint8_t>& data);
    static double estimate_kolmogorov_complexity(const std::vector<uint8_t>& data);
    static std::vector<double> calculate_autocorrelation_coefficients(const std::vector<uint8_t>& data, size_t max_lag = 10);
    static double calculate_chi_square_statistic(const std::vector<uint8_t>& data);
};
