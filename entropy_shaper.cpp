#include "entropy_shaper.hpp"
#include "stealth_macros.hpp"
#include "secure_memory.hpp"
#include "stealth_macros.hpp"
#include "secure_exceptions.hpp"
#include "stealth_macros.hpp"
#include "utils.hpp"
#include "stealth_macros.hpp"
#include <algorithm>
#include <random>
#include <chrono>
#include <cmath>
#include <regex>
#include <iostream>
#include <sstream>
#include <numeric>
#include <cstring>
#include <mutex>
#include <thread>
#include <limits>
#include "stealth_macros.hpp"
#include "stealth_macros.hpp"

// Thread safety constants
namespace {
    const size_t MAX_CACHE_SIZE = 100;
    const size_t MAX_CACHE_MEMORY = 50 * 1024 * 1024; // 50MB limit
}

EntropyShaper::EntropyShaper()
    : entropy_matching_precision_(0.95)
    , preserve_visual_content_(true)
    , aggressive_shaping_(false)
    , noise_injection_level_(0.1)
    , enable_anti_analysis_(true)
    , use_steganographic_techniques_(false)
    , enable_caching_(true)
    , enable_fast_mode_(false)
    , enable_parallel_(false) {
    
    reset_statistics();
}

EntropyShaper::~EntropyShaper() {
    // Thread-safe cleanup of sensitive cached data
    std::lock_guard<std::mutex> lock(cache_mutex_);
    entropy_cache_.clear();
    reset_statistics();
}

std::vector<uint8_t> EntropyShaper::shape_pdf_entropy(const std::vector<uint8_t>& pdf_data,
                                                     const EntropyProfile& target_profile) {
    
    // Complete silence enforcement - all debug output removed
    
    std::vector<uint8_t> shaped_data = pdf_data;
    
    // Analyze current entropy
    EntropyProfile current_profile = analyze_entropy(pdf_data);
    
    // Complete silence enforcement - all debug output removed
    // Complete silence enforcement - all debug output removed
    
    // Process PDF streams to match target entropy
    process_pdf_streams(shaped_data, target_profile);
    
    // Apply noise injection if needed
    if (noise_injection_level_ > 0.0) {
        std::vector<NoisePattern> patterns = generate_noise_patterns(target_profile);
        for (const auto& pattern : patterns) {
            shaped_data = inject_entropy_noise(shaped_data, pattern);
        }
    }
    
    // Balance byte frequencies
    shaped_data = balance_byte_frequencies(shaped_data, target_profile.byte_frequencies);
    
    // Apply anti-forensic techniques
    if (enable_anti_analysis_) {
        apply_anti_entropy_analysis(shaped_data);
        break_entropy_patterns(shaped_data);
        randomize_entropy_clusters(shaped_data);
    }
    
    // Validate the result
    if (!validate_entropy_match(shaped_data, target_profile)) {
        // Complete silence enforcement - all debug output removed
    }
    
    // Check visual integrity
    if (preserve_visual_content_ && !check_visual_integrity(pdf_data, shaped_data)) {
        // Complete silence enforcement - all debug output removed
    }
    
    // Complete silence enforcement - all debug output removed
    update_shaping_statistics("entropy_shaping", shaped_data.size());
    
    return shaped_data;
}

std::vector<uint8_t> EntropyShaper::match_compression_patterns(const std::vector<uint8_t>& pdf_data,
                                                             const CompressionProfile& target_profile) {
    
    // Complete silence enforcement - all debug output removed
    
    std::vector<uint8_t> result = pdf_data;
    
    // Adjust stream compression to match target profile
    adjust_stream_compression(result, target_profile);
    
    // Complete silence enforcement - all debug output removed
    update_shaping_statistics("compression_matching", result.size());
    
    return result;
}

EntropyProfile EntropyShaper::analyze_entropy(const std::vector<uint8_t>& pdf_data) {
    EntropyProfile profile;
    
    if (pdf_data.empty()) {
        return profile;
    }
    
    // Calculate overall entropy
    profile.average_entropy = calculate_shannon_entropy(pdf_data);
    profile.total_bytes = pdf_data.size();
    
    // Calculate block entropies for variance analysis
    size_t block_size = std::min(static_cast<size_t>(1024), pdf_data.size() / 10);
    if (block_size < 16) block_size = 16;
    
    for (size_t i = 0; i < pdf_data.size(); i += block_size) {
        size_t end = std::min(i + block_size, pdf_data.size());
        std::vector<uint8_t> block(pdf_data.begin() + i, pdf_data.begin() + end);
        double block_entropy = calculate_shannon_entropy(block);
        profile.block_entropies.push_back(block_entropy);
    }
    
    // Calculate min, max, and variance
    if (!profile.block_entropies.empty()) {
        profile.min_entropy = *std::min_element(profile.block_entropies.begin(), profile.block_entropies.end());
        profile.max_entropy = *std::max_element(profile.block_entropies.begin(), profile.block_entropies.end());
        profile.entropy_variance = calculate_entropy_variance(profile.block_entropies);
    }
    
    // Analyze byte frequencies
    profile.byte_frequencies = analyze_byte_frequencies(pdf_data);
    
    // Generate entropy signature
    profile.entropy_signature = generate_entropy_signature(pdf_data);
    
    // Analyze patterns
    profile.pattern_densities = analyze_pattern_densities(pdf_data);
    
    // Estimate compression ratio
    std::vector<uint8_t> compressed = PDFUtils::deflate_stream(pdf_data);
    profile.compression_ratio = static_cast<double>(compressed.size()) / pdf_data.size();
    
    return profile;
}

CompressionProfile EntropyShaper::analyze_compression(const std::vector<uint8_t>& pdf_data) {
    CompressionProfile profile;
    
    std::string pdf_str = PDFUtils::bytes_to_string(pdf_data);
    
    // Find all stream objects and analyze their compression
    std::vector<size_t> stream_locations = find_stream_locations(pdf_data);
    
    double total_compression = 0.0;
    int stream_count = 0;
    
    for (size_t stream_pos : stream_locations) {
        auto [start, end] = extract_stream_bounds(pdf_data, stream_pos);
        
        if (end > start) {
            std::vector<uint8_t> stream_data(pdf_data.begin() + start, pdf_data.begin() + end);
            profile.stream_sizes.push_back(stream_data.size());
            
            // Try to identify compression filter
            size_t obj_start = pdf_str.rfind("obj", stream_pos);
            if (obj_start != std::string::npos) {
                size_t filter_pos = pdf_str.find("/Filter", obj_start);
                if (filter_pos != std::string::npos && filter_pos < stream_pos) {
                    size_t filter_end = pdf_str.find_first_of(" \t\n\r]>", filter_pos + 7);
                    if (filter_end != std::string::npos) {
                        std::string filter = pdf_str.substr(filter_pos + 7, filter_end - filter_pos - 7);
                        profile.filter_usage[filter]++;
                        
                        if (profile.primary_filter.empty()) {
                            profile.primary_filter = filter;
                        }
                    }
                }
            }
            
            // Estimate compression ratio for this stream
            try {
                std::vector<uint8_t> compressed = PDFUtils::deflate_stream(stream_data);
                double ratio = static_cast<double>(compressed.size()) / stream_data.size();
                total_compression += ratio;
                stream_count++;
            } catch (...) {
                // Stream might already be compressed or use different format
            }
        }
    }
    
    if (stream_count > 0) {
        profile.average_compression_ratio = total_compression / stream_count;
    }
    
    return profile;
}

double EntropyShaper::calculate_shannon_entropy(const std::vector<uint8_t>& data) {
    if (data.empty()) return 0.0;
    
    // Count byte frequencies
    int freq[256] = {};
    for (uint8_t byte : data) {
        freq[byte]++;
    }
    
    // Calculate entropy
    double entropy = 0.0;
    double total = static_cast<double>(data.size());
    
    for (int count : freq) {
        if (count > 0) {
            double p = count / total;
            entropy -= p * std::log2(p);
        }
    }
    
    return entropy;
}

double EntropyShaper::calculate_block_entropy(const std::vector<uint8_t>& data, size_t block_size) {
    if (data.size() < block_size) {
        return calculate_shannon_entropy(data);
    }
    
    double total_entropy = 0.0;
    size_t block_count = 0;
    
    for (size_t i = 0; i + block_size <= data.size(); i += block_size) {
        std::vector<uint8_t> block(data.begin() + i, data.begin() + i + block_size);
        total_entropy += calculate_shannon_entropy(block);
        block_count++;
    }
    
    return block_count > 0 ? total_entropy / block_count : 0.0;
}

std::vector<double> EntropyShaper::calculate_sliding_entropy(const std::vector<uint8_t>& data, size_t window_size) {
    std::vector<double> entropies;
    
    if (data.size() < window_size) {
        entropies.push_back(calculate_shannon_entropy(data));
        return entropies;
    }
    
    for (size_t i = 0; i + window_size <= data.size(); i++) {
        std::vector<uint8_t> window(data.begin() + i, data.begin() + i + window_size);
        entropies.push_back(calculate_shannon_entropy(window));
    }
    
    return entropies;
}

std::map<uint8_t, double> EntropyShaper::analyze_byte_frequencies(const std::vector<uint8_t>& data) {
    std::map<uint8_t, double> frequencies;
    
    if (data.empty()) return frequencies;
    
    int counts[256] = {};
    for (uint8_t byte : data) {
        counts[byte]++;
    }
    
    double total = static_cast<double>(data.size());
    for (int i = 0; i < 256; ++i) {
        if (counts[i] > 0) {
            frequencies[static_cast<uint8_t>(i)] = counts[i] / total;
        }
    }
    
    return frequencies;
}

std::vector<uint8_t> EntropyShaper::generate_entropy_signature(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> signature;
    
    // Create a fingerprint based on entropy characteristics
    double entropy = calculate_shannon_entropy(data);
    
    // Convert entropy to bytes (safe entropy-to-byte conversion)
    uint64_t entropy_bits;
    // SECURITY FIX: Replace unsafe memcpy with safe bounds-checked copy
    if (!SecureMemory::SafeMemory::safe_memcpy(
        &entropy_bits, sizeof(entropy_bits),
        &entropy, sizeof(uint64_t))) {
        throw SecureExceptions::BufferOverflowException("entropy bits copy");
    }
    for (int i = 0; i < 8; ++i) {
        signature.push_back((entropy_bits >> (i * 8)) & 0xFF);
    }
    
    // Add byte frequency signature
    auto frequencies = analyze_byte_frequencies(data);
    for (const auto& pair : frequencies) {
        if (pair.second > 0.01) { // Only significant frequencies
            signature.push_back(pair.first);
            uint32_t freq_bits = static_cast<uint32_t>(pair.second * 1000000);
            for (int i = 0; i < 4; ++i) {
                signature.push_back((freq_bits >> (i * 8)) & 0xFF);
            }
        }
        if (signature.size() > 64) break; // Limit signature size
    }
    
    return signature;
}

double EntropyShaper::calculate_entropy_variance(const std::vector<double>& entropies) {
    if (entropies.empty()) return 0.0;
    
    double mean = std::accumulate(entropies.begin(), entropies.end(), 0.0) / entropies.size();
    
    double variance = 0.0;
    for (double entropy : entropies) {
        variance += (entropy - mean) * (entropy - mean);
    }
    
    return variance / entropies.size();
}

std::map<std::string, double> EntropyShaper::analyze_pattern_densities(const std::vector<uint8_t>& data) {
    std::map<std::string, double> densities;
    
    // Analyze common PDF patterns
    std::string data_str = PDFUtils::bytes_to_string(data);
    
    // Calculate densities of various patterns
    densities["whitespace"] = static_cast<double>(std::count_if(data.begin(), data.end(), 
                                                               [](uint8_t b) { return std::isspace(b); })) / data.size();
    
    densities["printable"] = static_cast<double>(std::count_if(data.begin(), data.end(),
                                                              [](uint8_t b) { return b >= 32 && b <= 126; })) / data.size();
    
    densities["null_bytes"] = static_cast<double>(std::count(data.begin(), data.end(), 0)) / data.size();
    
    densities["high_entropy"] = static_cast<double>(std::count_if(data.begin(), data.end(),
                                                                 [](uint8_t b) { return b > 128; })) / data.size();
    
    // PDF-specific patterns
    size_t obj_count = std::count(data_str.begin(), data_str.end(), '\n');
    densities["line_density"] = static_cast<double>(obj_count) / data.size();
    
    return densities;
}

std::vector<uint8_t> EntropyShaper::adjust_stream_entropy(const std::vector<uint8_t>& stream_data,
                                                         double target_entropy) {
    
    std::vector<uint8_t> adjusted_data = stream_data;
    double current_entropy = calculate_shannon_entropy(adjusted_data);
    
    if (std::abs(current_entropy - target_entropy) < 0.1) {
        return adjusted_data; // Already close enough
    }
    
    if (current_entropy < target_entropy) {
        // Need to increase entropy - inject random noise
        size_t noise_amount = static_cast<size_t>(adjusted_data.size() * 0.05); // 5% noise
        std::vector<uint8_t> noise = create_entropy_noise(noise_amount, target_entropy);
        
        // Insert noise at strategic positions
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, adjusted_data.size());
        
        for (uint8_t byte : noise) {
            size_t pos = dis(gen);
            if (pos < adjusted_data.size()) {
                adjusted_data.insert(adjusted_data.begin() + pos, byte);
            }
        }
    } else {
        // Need to decrease entropy - reduce randomness
        // Replace some random bytes with more predictable patterns
        std::map<uint8_t, double> frequencies = analyze_byte_frequencies(adjusted_data);
        
        // Find most common byte
        uint8_t most_common = 0;
        double max_freq = 0.0;
        for (const auto& pair : frequencies) {
            if (pair.second > max_freq) {
                max_freq = pair.second;
                most_common = pair.first;
            }
        }
        
        // Replace some random bytes with the most common byte
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, adjusted_data.size() - 1);
        
        size_t replacements = static_cast<size_t>(adjusted_data.size() * 0.1);
        for (size_t i = 0; i < replacements; ++i) {
            size_t pos = dis(gen);
            adjusted_data[pos] = most_common;
        }
    }
    
    return adjusted_data;
}

std::vector<uint8_t> EntropyShaper::inject_entropy_noise(const std::vector<uint8_t>& data,
                                                        const NoisePattern& pattern) {
    
    std::vector<uint8_t> result = data;
    
    if (pattern.pattern_data.empty()) return result;
    
    // Calculate injection points based on frequency and strategy
    size_t injection_count = static_cast<size_t>(result.size() * pattern.frequency);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    
    for (size_t i = 0; i < injection_count; ++i) {
        size_t pattern_size = pattern.min_size;
        if (pattern.max_size > pattern.min_size) {
            std::uniform_int_distribution<> size_dis(pattern.min_size, pattern.max_size);
            pattern_size = size_dis(gen);
        }
        
        // Generate noise chunk
        std::vector<uint8_t> noise_chunk;
        for (size_t j = 0; j < pattern_size; ++j) {
            noise_chunk.push_back(pattern.pattern_data[j % pattern.pattern_data.size()]);
        }
        
        // Insert at random position or according to strategy
        std::uniform_int_distribution<> pos_dis(0, result.size());
        size_t insert_pos = pos_dis(gen);
        
        if (pattern.insertion_strategy == "whitespace") {
            // Insert only at whitespace positions
            while (insert_pos < result.size() && !std::isspace(result[insert_pos])) {
                insert_pos = (insert_pos + 1) % result.size();
            }
        } else if (pattern.insertion_strategy == "stream_padding") {
            // Insert only in stream data areas
            std::string result_str = PDFUtils::bytes_to_string(result);
            size_t stream_pos = result_str.find("stream", insert_pos);
            if (stream_pos != std::string::npos) {
                size_t stream_end = result_str.find("endstream", stream_pos);
                if (stream_end != std::string::npos) {
                    std::uniform_int_distribution<> stream_dis(stream_pos + 6, stream_end);
                    insert_pos = stream_dis(gen);
                }
            }
        }
        
        if (insert_pos < result.size()) {
            result.insert(result.begin() + insert_pos, noise_chunk.begin(), noise_chunk.end());
        }
    }
    
    return result;
}

std::vector<uint8_t> EntropyShaper::balance_byte_frequencies(const std::vector<uint8_t>& data,
                                                           const std::map<uint8_t, double>& target_frequencies) {
    
    std::vector<uint8_t> result = data;
    
    if (target_frequencies.empty()) return result;
    
    // Analyze current frequencies
    auto current_frequencies = analyze_byte_frequencies(result);
    
    // Adjust frequencies to match target
    for (const auto& target_pair : target_frequencies) {
        uint8_t byte_val = target_pair.first;
        double target_freq = target_pair.second;
        
        auto current_it = current_frequencies.find(byte_val);
        double current_freq = (current_it != current_frequencies.end()) ? current_it->second : 0.0;
        
        if (current_freq < target_freq) {
            // Need to add more instances of this byte
            size_t needed = static_cast<size_t>((target_freq - current_freq) * result.size());
            
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> pos_dis(0, result.size());
            
            for (size_t i = 0; i < needed; ++i) {
                size_t pos = pos_dis(gen);
                result.insert(result.begin() + pos, byte_val);
            }
        } else if (current_freq > target_freq) {
            // Need to remove instances of this byte
            size_t to_remove = static_cast<size_t>((current_freq - target_freq) * result.size());
            
            auto it = result.begin();
            size_t removed = 0;
            while (it != result.end() && removed < to_remove) {
                if (*it == byte_val) {
                    it = result.erase(it);
                    removed++;
                } else {
                    ++it;
                }
            }
        }
    }
    
    return result;
}

void EntropyShaper::process_pdf_streams(std::vector<uint8_t>& pdf_data, const EntropyProfile& target) {
    std::vector<size_t> stream_locations = find_stream_locations(pdf_data);
    
    for (size_t stream_pos : stream_locations) {
        auto [start, end] = extract_stream_bounds(pdf_data, stream_pos);
        
        if (end > start) {
            std::vector<uint8_t> stream_data(pdf_data.begin() + start, pdf_data.begin() + end);
            
            // Adjust stream entropy
            std::vector<uint8_t> adjusted_stream = adjust_stream_entropy(stream_data, target.average_entropy);
            
            // Replace stream data
            pdf_data.erase(pdf_data.begin() + start, pdf_data.begin() + end);
            pdf_data.insert(pdf_data.begin() + start, adjusted_stream.begin(), adjusted_stream.end());
            
            stats_.streams_shaped++;
        }
    }
}

void EntropyShaper::adjust_stream_compression(std::vector<uint8_t>& pdf_data, const CompressionProfile& target) {
    std::vector<size_t> stream_locations = find_stream_locations(pdf_data);
    
    for (size_t stream_pos : stream_locations) {
        auto [start, end] = extract_stream_bounds(pdf_data, stream_pos);
        
        if (end > start) {
            std::vector<uint8_t> stream_data(pdf_data.begin() + start, pdf_data.begin() + end);
            
            // Apply target compression filters
            if (!target.primary_filter.empty()) {
                std::vector<std::string> filters = {target.primary_filter};
                std::vector<uint8_t> compressed_stream = apply_compression_filters(stream_data, filters);
                
                // Replace stream data
                pdf_data.erase(pdf_data.begin() + start, pdf_data.begin() + end);
                pdf_data.insert(pdf_data.begin() + start, compressed_stream.begin(), compressed_stream.end());
            }
        }
    }
}

std::vector<size_t> EntropyShaper::find_stream_locations(const std::vector<uint8_t>& pdf_data) {
    std::vector<size_t> locations;
    std::string pdf_str = PDFUtils::bytes_to_string(pdf_data);
    
    size_t pos = 0;
    while ((pos = pdf_str.find("stream", pos)) != std::string::npos) {
        locations.push_back(pos);
        pos += 6;
    }
    
    return locations;
}

std::pair<size_t, size_t> EntropyShaper::extract_stream_bounds(const std::vector<uint8_t>& pdf_data, 
                                                              size_t stream_start) {
    
    std::string pdf_str = PDFUtils::bytes_to_string(pdf_data);
    
    size_t start = pdf_str.find("stream", stream_start) + 6;
    
    // Skip whitespace after "stream"
    while (start < pdf_str.length() && std::isspace(pdf_str[start])) {
        start++;
    }
    
    size_t end = pdf_str.find("endstream", start);
    if (end == std::string::npos) {
        end = pdf_str.length();
    }
    
    return {start, end};
}

std::vector<uint8_t> EntropyShaper::apply_compression_filters(const std::vector<uint8_t>& data,
                                                            const std::vector<std::string>& filters) {
    
    std::vector<uint8_t> result = data;
    
    for (const std::string& filter : filters) {
        if (filter == "/FlateDecode") {
            try {
                result = PDFUtils::deflate_stream(result);
            } catch (...) {
                // Keep original data if compression fails
            }
        }
        // Additional filters would be implemented here
    }
    
    return result;
}

std::vector<NoisePattern> EntropyShaper::generate_noise_patterns(const EntropyProfile& target) {
    std::vector<NoisePattern> patterns;
    
    // Create whitespace noise pattern
    NoisePattern whitespace_pattern;
    whitespace_pattern.pattern_data = {' ', '\t', '\n', '\r'};
    whitespace_pattern.frequency = noise_injection_level_ * 0.3;
    whitespace_pattern.min_size = 1;
    whitespace_pattern.max_size = 5;
    whitespace_pattern.insertion_strategy = "whitespace";
    whitespace_pattern.preserve_visual_content = preserve_visual_content_;
    patterns.push_back(whitespace_pattern);
    
    // Create entropy padding pattern
    NoisePattern entropy_pattern;
    entropy_pattern.pattern_data = create_entropy_noise(64, target.average_entropy);
    entropy_pattern.frequency = noise_injection_level_ * 0.5;
    entropy_pattern.min_size = 8;
    entropy_pattern.max_size = 32;
    entropy_pattern.insertion_strategy = "stream_padding";
    entropy_pattern.preserve_visual_content = preserve_visual_content_;
    patterns.push_back(entropy_pattern);
    
    // Create comment noise pattern
    NoisePattern comment_pattern;
    std::string comment_base = "% ";
    std::vector<uint8_t> comment_noise = create_entropy_noise(32, target.average_entropy);
    comment_pattern.pattern_data = PDFUtils::string_to_bytes(comment_base);
    comment_pattern.pattern_data.insert(comment_pattern.pattern_data.end(), 
                                       comment_noise.begin(), comment_noise.end());
    comment_pattern.pattern_data.push_back('\n');
    comment_pattern.frequency = noise_injection_level_ * 0.2;
    comment_pattern.min_size = comment_pattern.pattern_data.size();
    comment_pattern.max_size = comment_pattern.pattern_data.size();
    comment_pattern.insertion_strategy = "line_start";
    comment_pattern.preserve_visual_content = true;
    patterns.push_back(comment_pattern);
    
    return patterns;
}

// Missing method implementations for entropy shaper

bool EntropyShaper::match_entropy_distribution(const std::vector<uint8_t>& data, 
                                               const EntropyProfile& target_distribution) {
    EntropyProfile current = analyze_entropy(data);
    
    double entropy_diff = std::abs(current.average_entropy - target_distribution.average_entropy);
    double variance_diff = std::abs(current.entropy_variance - target_distribution.entropy_variance);
    
    // Check if entropy distribution matches within acceptable tolerance
    bool entropy_match = entropy_diff < (1.0 - entropy_matching_precision_);
    bool variance_match = variance_diff < 0.5; // 0.5 variance tolerance
    
    // Compare byte frequency distributions
    double frequency_similarity = 0.0;
    for (const auto& [byte, freq] : target_distribution.byte_frequencies) {
        auto it = current.byte_frequencies.find(byte);
        if (it != current.byte_frequencies.end()) {
            frequency_similarity += std::min(freq, it->second);
        }
    }
    
    bool frequency_match = frequency_similarity > 0.8; // 80% similarity threshold
    
    return entropy_match && variance_match && frequency_match;
}

std::vector<uint8_t> EntropyShaper::match_entropy_distribution(const std::vector<uint8_t>& data,
                                                              const std::vector<double>& target_distribution) {
    if (data.empty() || target_distribution.size() != 256) {
        return data;
    }
    
    std::vector<uint8_t> result = data;
    std::map<uint8_t, double> current_freq = analyze_byte_frequencies(data);
    
    // Convert target distribution to frequency map
    std::map<uint8_t, double> target_freq;
    for (size_t i = 0; i < 256; ++i) {
        target_freq[static_cast<uint8_t>(i)] = target_distribution[i];
    }
    
    // Adjust byte frequencies to match target distribution
    result = balance_byte_frequencies(result, target_freq);
    
    return result;
}

// Compression-specific shaping implementations
std::vector<uint8_t> EntropyShaper::shape_deflate_entropy(const std::vector<uint8_t>& data, 
                                                          const EntropyProfile& target) {
    std::vector<uint8_t> shaped_data = data;
    
    // Analyze current deflate characteristics
    size_t block_size = 32768; // Standard deflate block size
    
    for (size_t i = 0; i < shaped_data.size(); i += block_size) {
        size_t current_block_size = std::min(block_size, shaped_data.size() - i);
        std::vector<uint8_t> block(shaped_data.begin() + i, 
                                  shaped_data.begin() + i + current_block_size);
        
        // Calculate current block entropy
        double block_entropy = calculate_shannon_entropy(block);
        
        if (std::abs(block_entropy - target.average_entropy) > 0.5) {
            // Adjust block entropy by modifying least significant bits
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);
            
            size_t modifications = static_cast<size_t>(current_block_size * 0.05); // 5% modification
            
            for (size_t j = 0; j < modifications; ++j) {
                size_t pos = gen() % current_block_size;
                
                if (block_entropy < target.average_entropy) {
                    // Increase entropy - make data more random
                    block[pos] ^= (dis(gen) & 0x0F); // Modify lower 4 bits
                } else {
                    // Decrease entropy - make data more structured
                    block[pos] = (block[pos] & 0xF0) | (block[pos % 16] & 0x0F);
                }
            }
            
            // Copy modified block back
            std::copy(block.begin(), block.end(), shaped_data.begin() + i);
        }
    }
    
    return shaped_data;
}

std::vector<uint8_t> EntropyShaper::shape_lzw_entropy(const std::vector<uint8_t>& data, 
                                                      const EntropyProfile& target) {
    std::vector<uint8_t> shaped_data = data;
    
    // LZW works better with patterns, so adjust data to create or remove patterns
    double current_entropy = calculate_shannon_entropy(data);
    
    if (current_entropy < target.average_entropy) {
        // Need to increase entropy - break existing patterns
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        // Insert random bytes to break patterns
        size_t insertions = static_cast<size_t>(data.size() * 0.02); // 2% insertions
        
        for (size_t i = 0; i < insertions; ++i) {
            size_t pos = gen() % shaped_data.size();
            shaped_data.insert(shaped_data.begin() + pos, dis(gen));
        }
    } else if (current_entropy > target.average_entropy) {
        // Need to decrease entropy - create patterns
        
        // Find most common byte sequences and replicate them
        std::map<std::vector<uint8_t>, size_t> pattern_counts;
        size_t pattern_length = 3;
        
        for (size_t i = 0; i <= data.size() - pattern_length; ++i) {
            std::vector<uint8_t> pattern(data.begin() + i, data.begin() + i + pattern_length);
            pattern_counts[pattern]++;
        }
        
        // Find most common pattern
        auto max_pattern = std::max_element(pattern_counts.begin(), pattern_counts.end(),
            [](const auto& a, const auto& b) { return a.second < b.second; });
        
        if (max_pattern != pattern_counts.end()) {
            // Insert the most common pattern at regular intervals
            const auto& common_pattern = max_pattern->first;
            size_t interval = shaped_data.size() / 20; // Every 5% of data
            
            for (size_t i = interval; i < shaped_data.size(); i += interval) {
                shaped_data.insert(shaped_data.begin() + i, 
                                 common_pattern.begin(), common_pattern.end());
                i += common_pattern.size(); // Skip inserted pattern
            }
        }
    }
    
    return shaped_data;
}

std::vector<uint8_t> EntropyShaper::shape_ascii_entropy(const std::vector<uint8_t>& data, 
                                                        const EntropyProfile& target) {
    std::vector<uint8_t> shaped_data = data;
    
    // ASCII data should stay in printable range (32-126)
    for (size_t i = 0; i < shaped_data.size(); ++i) {
        if (shaped_data[i] < 32 || shaped_data[i] > 126) {
            // Map non-ASCII to ASCII range while preserving some entropy characteristics
            shaped_data[i] = 32 + (shaped_data[i] % 95); // Map to printable ASCII
        }
    }
    
    double current_entropy = calculate_shannon_entropy(shaped_data);
    
    if (std::abs(current_entropy - target.average_entropy) > 0.3) {
        std::random_device rd;
        std::mt19937 gen(rd());
        
        if (current_entropy < target.average_entropy) {
            // Increase entropy within ASCII range
            std::uniform_int_distribution<> ascii_dis(33, 126); // Skip space for readability
            
            size_t modifications = static_cast<size_t>(shaped_data.size() * 0.1);
            for (size_t i = 0; i < modifications; ++i) {
                size_t pos = gen() % shaped_data.size();
                shaped_data[pos] = ascii_dis(gen);
            }
        } else {
            // Decrease entropy by creating ASCII patterns
            std::uniform_int_distribution<> pattern_dis(0, 3);
            char patterns[] = {'a', 'e', 'i', 'o'}; // Common vowels
            
            size_t modifications = static_cast<size_t>(shaped_data.size() * 0.15);
            for (size_t i = 0; i < modifications; ++i) {
                size_t pos = gen() % shaped_data.size();
                shaped_data[pos] = patterns[pattern_dis(gen)];
            }
        }
    }
    
    return shaped_data;
}

std::vector<uint8_t> EntropyShaper::optimize_huffman_tables(const std::vector<uint8_t>& data) {
    // Create frequency table
    std::map<uint8_t, size_t> frequencies;
    for (uint8_t byte : data) {
        frequencies[byte]++;
    }
    
    // Optimize by adjusting least frequent bytes to match Huffman efficiency
    std::vector<uint8_t> optimized_data = data;
    
    // Find least and most frequent bytes
    auto min_freq = std::min_element(frequencies.begin(), frequencies.end(),
        [](const auto& a, const auto& b) { return a.second < b.second; });
    auto max_freq = std::max_element(frequencies.begin(), frequencies.end(),
        [](const auto& a, const auto& b) { return a.second < b.second; });
    
    if (min_freq != frequencies.end() && max_freq != frequencies.end()) {
        // Replace some instances of least frequent with most frequent
        // This improves Huffman compression efficiency
        uint8_t rare_byte = min_freq->first;
        uint8_t common_byte = max_freq->first;
        
        size_t replacements = min_freq->second / 4; // Replace 25% of rare bytes
        size_t replaced = 0;
        
        for (size_t i = 0; i < optimized_data.size() && replaced < replacements; ++i) {
            if (optimized_data[i] == rare_byte) {
                optimized_data[i] = common_byte;
                replaced++;
            }
        }
    }
    
    return optimized_data;
}

std::vector<uint8_t> EntropyShaper::adjust_lz_dictionary(const std::vector<uint8_t>& data, 
                                                         const EntropyProfile& target) {
    std::vector<uint8_t> adjusted_data = data;
    
    // Analyze existing patterns for LZ77/LZ78 optimization
    std::map<std::vector<uint8_t>, std::vector<size_t>> pattern_positions;
    size_t min_pattern_length = 3;
    size_t max_pattern_length = 32;
    
    // Find all patterns and their positions
    for (size_t len = min_pattern_length; len <= max_pattern_length && len <= data.size(); ++len) {
        for (size_t i = 0; i <= data.size() - len; ++i) {
            std::vector<uint8_t> pattern(data.begin() + i, data.begin() + i + len);
            pattern_positions[pattern].push_back(i);
        }
    }
    
    // Optimize dictionary usage based on target entropy
    if (calculate_shannon_entropy(data) > target.average_entropy) {
        // Create more dictionary matches by duplicating effective patterns
        for (const auto& [pattern, positions] : pattern_positions) {
            if (positions.size() >= 3 && pattern.size() >= 4) { // Pattern appears 3+ times
                // Insert pattern at strategic locations
                size_t insertion_interval = adjusted_data.size() / (positions.size() + 2);
                
                for (size_t i = 1; i < positions.size(); ++i) {
                    size_t insert_pos = insertion_interval * i;
                    if (insert_pos < adjusted_data.size()) {
                        adjusted_data.insert(adjusted_data.begin() + insert_pos,
                                           pattern.begin(), pattern.end());
                    }
                }
                break; // Only optimize one pattern to avoid over-modification
            }
        }
    }
    
    return adjusted_data;
}

// Advanced statistical manipulation
std::vector<uint8_t> EntropyShaper::adjust_statistical_properties(const std::vector<uint8_t>& data,
                                                                  const EntropyProfile& target) {
    std::vector<uint8_t> adjusted_data = data;
    
    // Calculate current statistical properties
    std::map<uint8_t, double> current_frequencies = analyze_byte_frequencies(data);
    
    // Adjust byte frequencies to match target distribution
    for (const auto& [target_byte, target_freq] : target.byte_frequencies) {
        double current_freq = current_frequencies[target_byte];
        double freq_diff = target_freq - current_freq;
        
        if (std::abs(freq_diff) > 0.01) { // 1% threshold
            size_t target_count = static_cast<size_t>(target_freq * data.size());
            size_t current_count = static_cast<size_t>(current_freq * data.size());
            
            if (target_count > current_count) {
                // Need to increase frequency of this byte
                size_t additions = target_count - current_count;
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<> pos_dis(0, adjusted_data.size() - 1);
                
                for (size_t i = 0; i < additions && i < adjusted_data.size() * 0.1; ++i) {
                    size_t pos = pos_dis(gen);
                    adjusted_data[pos] = target_byte;
                }
            }
        }
    }
    
    return adjusted_data;
}

bool EntropyShaper::match_chi_square_distribution(const std::vector<uint8_t>& data, 
                                                  double target_chi_square) {
    // Calculate chi-square statistic for byte distribution
    std::map<uint8_t, size_t> observed_counts;
    for (uint8_t byte : data) {
        observed_counts[byte]++;
    }
    
    double expected_count = static_cast<double>(data.size()) / 256.0;
    double chi_square = 0.0;
    
    for (int i = 0; i < 256; ++i) {
        uint8_t byte = static_cast<uint8_t>(i);
        size_t observed = observed_counts[byte];
        double diff = observed - expected_count;
        chi_square += (diff * diff) / expected_count;
    }
    
    return std::abs(chi_square - target_chi_square) < 10.0; // Tolerance of 10
}

std::vector<uint8_t> EntropyShaper::adjust_autocorrelation(const std::vector<uint8_t>& data, 
                                                           double target_correlation) {
    std::vector<uint8_t> adjusted_data = data;
    
    // Calculate current autocorrelation at lag 1
    if (data.size() < 2) return adjusted_data;
    
    double sum_xy = 0.0, sum_x = 0.0, sum_y = 0.0, sum_x2 = 0.0, sum_y2 = 0.0;
    size_t n = data.size() - 1;
    
    for (size_t i = 0; i < n; ++i) {
        double x = static_cast<double>(data[i]);
        double y = static_cast<double>(data[i + 1]);
        
        sum_xy += x * y;
        sum_x += x;
        sum_y += y;
        sum_x2 += x * x;
        sum_y2 += y * y;
    }
    
    double mean_x = sum_x / n;
    double mean_y = sum_y / n;
    
    double numerator = sum_xy - n * mean_x * mean_y;
    double denominator = std::sqrt((sum_x2 - n * mean_x * mean_x) * (sum_y2 - n * mean_y * mean_y));
    
    double current_correlation = (denominator != 0.0) ? numerator / denominator : 0.0;
    
    // Adjust correlation by modifying byte relationships
    if (std::abs(current_correlation - target_correlation) > 0.1) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> byte_dis(0, 255);
        
        size_t modifications = static_cast<size_t>(data.size() * 0.05); // 5% modifications
        
        for (size_t i = 0; i < modifications && i < data.size() - 1; ++i) {
            size_t pos = gen() % (data.size() - 1);
            
            if (current_correlation < target_correlation) {
                // Increase correlation - make adjacent bytes more similar
                adjusted_data[pos + 1] = adjusted_data[pos] + (byte_dis(gen) % 16) - 8;
            } else {
                // Decrease correlation - make adjacent bytes more different
                adjusted_data[pos + 1] = byte_dis(gen);
            }
        }
    }
    
    return adjusted_data;
}

std::vector<uint8_t> EntropyShaper::balance_bit_distribution(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> balanced_data = data;
    
    // Count bits in each position
    std::vector<size_t> bit_counts(8, 0);
    
    for (uint8_t byte : data) {
        for (int bit = 0; bit < 8; ++bit) {
            if (byte & (1 << bit)) {
                bit_counts[bit]++;
            }
        }
    }
    
    // Target is roughly 50% for each bit position
    size_t target_count = data.size() / 2;
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> pos_dis(0, balanced_data.size() - 1);
    
    // Adjust bits that are significantly off-balance
    for (int bit = 0; bit < 8; ++bit) {
        size_t current_count = bit_counts[bit];
        
        if (std::abs(static_cast<long>(current_count) - static_cast<long>(target_count)) > data.size() * 0.1) {
            bool need_more_ones = current_count < target_count;
            size_t adjustments_needed = std::abs(static_cast<long>(current_count) - static_cast<long>(target_count)) / 2;
            
            for (size_t i = 0; i < adjustments_needed && i < data.size() * 0.2; ++i) {
                size_t pos = pos_dis(gen);
                
                if (need_more_ones) {
                    balanced_data[pos] |= (1 << bit); // Set bit
                } else {
                    balanced_data[pos] &= ~(1 << bit); // Clear bit
                }
            }
        }
    }
    
    return balanced_data;
}

std::vector<uint8_t> EntropyShaper::create_entropy_noise(size_t length, double target_entropy) {
    std::vector<uint8_t> noise(length);
    
    if (target_entropy < 4.0) {
        // Low entropy - use patterns
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 15); // Limited range
        
        for (size_t i = 0; i < length; ++i) {
            noise[i] = dis(gen);
        }
    } else if (target_entropy > 7.0) {
        // High entropy - use random data
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        for (size_t i = 0; i < length; ++i) {
            noise[i] = dis(gen);
        }
    } else {
        // Medium entropy - balanced approach
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(32, 126); // Printable ASCII
        
        for (size_t i = 0; i < length; ++i) {
            noise[i] = dis(gen);
        }
    }
    
    return noise;
}

// Advanced entropy manipulation functions
std::vector<uint8_t> EntropyShaper::create_entropy_gradient(const std::vector<uint8_t>& data,
                                                            double start_entropy, double end_entropy) {
    std::vector<uint8_t> gradient_data = data;
    size_t num_blocks = 20; // Divide data into blocks for gradient
    size_t block_size = gradient_data.size() / num_blocks;
    
    if (block_size == 0) return gradient_data;
    
    for (size_t block = 0; block < num_blocks; ++block) {
        double progress = static_cast<double>(block) / (num_blocks - 1);
        double target_entropy = start_entropy + progress * (end_entropy - start_entropy);
        
        size_t block_start = block * block_size;
        size_t block_end = (block == num_blocks - 1) ? gradient_data.size() : (block + 1) * block_size;
        
        std::vector<uint8_t> block_data(gradient_data.begin() + block_start, 
                                       gradient_data.begin() + block_end);
        
        // Adjust block entropy to match target
        double current_entropy = calculate_shannon_entropy(block_data);
        
        if (std::abs(current_entropy - target_entropy) > 0.2) {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);
            
            size_t modifications = static_cast<size_t>(block_data.size() * 0.1);
            
            for (size_t i = 0; i < modifications; ++i) {
                size_t pos = gen() % block_data.size();
                
                if (current_entropy < target_entropy) {
                    block_data[pos] = dis(gen); // Increase randomness
                } else {
                    block_data[pos] = block_data[pos % 16]; // Create patterns
                }
            }
            
            // Copy modified block back
            std::copy(block_data.begin(), block_data.end(), gradient_data.begin() + block_start);
        }
    }
    
    return gradient_data;
}

std::vector<uint8_t> EntropyShaper::apply_entropy_filter(const std::vector<uint8_t>& data,
                                                         const std::string& filter_type) {
    std::vector<uint8_t> filtered_data = data;
    
    if (filter_type == "lowpass") {
        // Low-pass filter reduces high-frequency entropy changes
        for (size_t i = 1; i < filtered_data.size() - 1; ++i) {
            uint16_t sum = filtered_data[i-1] + filtered_data[i] + filtered_data[i+1];
            filtered_data[i] = static_cast<uint8_t>(sum / 3);
        }
    } else if (filter_type == "highpass") {
        // High-pass filter emphasizes entropy differences
        std::vector<uint8_t> temp = filtered_data;
        for (size_t i = 1; i < filtered_data.size() - 1; ++i) {
            int16_t diff = 3 * temp[i] - temp[i-1] - temp[i+1];
            filtered_data[i] = static_cast<uint8_t>(std::max(0, std::min(255, static_cast<int>(temp[i]) + diff/4)));
        }
    } else if (filter_type == "median") {
        // Median filter reduces noise while preserving edges
        for (size_t i = 1; i < filtered_data.size() - 1; ++i) {
            std::vector<uint8_t> window = {filtered_data[i-1], filtered_data[i], filtered_data[i+1]};
            std::sort(window.begin(), window.end());
            filtered_data[i] = window[1]; // Median value
        }
    }
    
    return filtered_data;
}

std::vector<uint8_t> EntropyShaper::smooth_entropy_curve(const std::vector<uint8_t>& data, 
                                                         size_t window_size) {
    if (window_size == 0 || window_size > data.size()) {
        return data;
    }
    
    std::vector<uint8_t> smoothed_data = data;
    size_t half_window = window_size / 2;
    
    for (size_t i = half_window; i < data.size() - half_window; ++i) {
        uint32_t sum = 0;
        
        for (size_t j = i - half_window; j <= i + half_window; ++j) {
            sum += data[j];
        }
        
        smoothed_data[i] = static_cast<uint8_t>(sum / window_size);
    }
    
    return smoothed_data;
}

std::vector<uint8_t> EntropyShaper::interpolate_entropy(const std::vector<uint8_t>& data,
                                                        const EntropyProfile& start_profile,
                                                        const EntropyProfile& end_profile,
                                                        double factor) {
    std::vector<uint8_t> interpolated_data = data;
    
    // Interpolate target entropy
    double target_entropy = start_profile.average_entropy + 
                           factor * (end_profile.average_entropy - start_profile.average_entropy);
    
    // Interpolate byte frequencies
    std::map<uint8_t, double> target_frequencies;
    for (int i = 0; i < 256; ++i) {
        uint8_t byte = static_cast<uint8_t>(i);
        double start_freq = 0.0, end_freq = 0.0;
        
        auto start_it = start_profile.byte_frequencies.find(byte);
        if (start_it != start_profile.byte_frequencies.end()) {
            start_freq = start_it->second;
        }
        
        auto end_it = end_profile.byte_frequencies.find(byte);
        if (end_it != end_profile.byte_frequencies.end()) {
            end_freq = end_it->second;
        }
        
        target_frequencies[byte] = start_freq + factor * (end_freq - start_freq);
    }
    
    // Apply interpolated characteristics
    EntropyProfile target_profile = start_profile;
    target_profile.average_entropy = target_entropy;
    target_profile.byte_frequencies = target_frequencies;
    
    return adjust_statistical_properties(interpolated_data, target_profile);
}

// Steganographic features
std::vector<uint8_t> EntropyShaper::embed_entropy_watermark(const std::vector<uint8_t>& data,
                                                            const std::vector<uint8_t>& watermark) {
    std::vector<uint8_t> watermarked_data = data;
    
    if (watermark.empty() || data.size() < watermark.size() * 8) {
        return watermarked_data; // Not enough space for watermark
    }
    
    // Embed watermark in least significant bits
    size_t watermark_bit_index = 0;
    size_t data_interval = data.size() / (watermark.size() * 8);
    
    for (size_t byte_idx = 0; byte_idx < watermark.size(); ++byte_idx) {
        uint8_t watermark_byte = watermark[byte_idx];
        
        for (int bit = 0; bit < 8; ++bit) {
            size_t data_pos = watermark_bit_index * data_interval;
            
            if (data_pos < watermarked_data.size()) {
                // Clear LSB and set watermark bit
                watermarked_data[data_pos] &= 0xFE;
                if (watermark_byte & (1 << bit)) {
                    watermarked_data[data_pos] |= 0x01;
                }
            }
            
            watermark_bit_index++;
        }
    }
    
    return watermarked_data;
}

std::vector<std::vector<uint8_t>> EntropyShaper::create_entropy_channels(const std::vector<uint8_t>& data,
                                                                        size_t num_channels) {
    std::vector<std::vector<uint8_t>> channels(num_channels);
    
    if (num_channels == 0) return channels;
    
    // Distribute data across channels based on entropy characteristics
    for (size_t i = 0; i < data.size(); ++i) {
        size_t channel = i % num_channels;
        channels[channel].push_back(data[i]);
    }
    
    // Balance channel entropies
    std::vector<double> channel_entropies(num_channels);
    for (size_t i = 0; i < num_channels; ++i) {
        if (!channels[i].empty()) {
            channel_entropies[i] = calculate_shannon_entropy(channels[i]);
        }
    }
    
    // Find target entropy (average of all channels)
    double target_entropy = std::accumulate(channel_entropies.begin(), channel_entropies.end(), 0.0) / num_channels;
    
    // Adjust each channel to match target entropy
    for (size_t i = 0; i < num_channels; ++i) {
        if (std::abs(channel_entropies[i] - target_entropy) > 0.3) {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);
            
            size_t modifications = channels[i].size() / 20; // 5% modifications
            
            for (size_t j = 0; j < modifications && j < channels[i].size(); ++j) {
                size_t pos = gen() % channels[i].size();
                
                if (channel_entropies[i] < target_entropy) {
                    channels[i][pos] = dis(gen); // Increase entropy
                } else {
                    channels[i][pos] = channels[i][pos % 4]; // Create patterns
                }
            }
        }
    }
    
    return channels;
}

std::vector<uint8_t> EntropyShaper::distribute_entropy_across_channels(const std::vector<std::vector<uint8_t>>& channels) {
    std::vector<uint8_t> combined_data;
    
    if (channels.empty()) return combined_data;
    
    // Find maximum channel size
    size_t max_size = 0;
    for (const auto& channel : channels) {
        max_size = std::max(max_size, channel.size());
    }
    
    // Interleave data from all channels
    for (size_t pos = 0; pos < max_size; ++pos) {
        for (size_t ch = 0; ch < channels.size(); ++ch) {
            if (pos < channels[ch].size()) {
                combined_data.push_back(channels[ch][pos]);
            }
        }
    }
    
    return combined_data;
}

// Performance optimization functions
void EntropyShaper::optimize_entropy_calculation() {
    enable_caching_ = true;
    enable_fast_mode_ = true;
    
    // Pre-calculate common entropy values for faster lookup
    entropy_lookup_table_.clear();
    
    for (int freq = 1; freq <= 256; ++freq) {
        double probability = static_cast<double>(freq) / 256.0;
        double entropy_contribution = -probability * std::log2(probability);
        entropy_lookup_table_[freq] = entropy_contribution;
    }
}

void EntropyShaper::cache_entropy_calculations(const std::string& key, const EntropyProfile& profile) {
    if (enable_caching_ && entropy_cache_.size() < 1000) { // Limit cache size
        entropy_cache_[key] = profile;
    }
}

void EntropyShaper::use_parallel_processing(bool enable) {
    enable_parallel_ = enable;
}

// Error handling and recovery
bool EntropyShaper::recover_from_entropy_error(std::vector<uint8_t>& data) {
    try {
        // Check for common entropy calculation errors
        if (data.empty()) {
            // Complete silence enforcement - all error output removed
            return false;
        }
        
        if (data.size() > 100 * 1024 * 1024) { // 100MB limit
            // Complete silence enforcement - all error output removed
            data.resize(100 * 1024 * 1024);
        }
        
        // Check for invalid entropy values
        double entropy = calculate_shannon_entropy(data);
        if (std::isnan(entropy) || std::isinf(entropy) || entropy < 0) {
            // Complete silence enforcement - all error output removed
            
            // Apply basic entropy correction
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);
            
            // Replace potentially problematic bytes
            for (size_t i = 0; i < std::min(data.size(), size_t(100)); ++i) {
                data[i] = dis(gen);
            }
            
            return true;
        }
        
        return true; // No errors found
        
    } catch (const std::exception& e) {
        // Complete silence enforcement - all error output removed
        return false;
    }
}

bool EntropyShaper::validate_shaped_data_integrity(const std::vector<uint8_t>& original,
                                                   const std::vector<uint8_t>& shaped) {
    // Basic integrity checks
    if (shaped.empty()) {
        return false;
    }
    
    // Size should not change dramatically (within 20%)
    if (shaped.size() > original.size() * 1.2 || shaped.size() < original.size() * 0.8) {
        // Complete silence enforcement - all error output removed
        return false;
    }
    
    // Entropy should be within reasonable bounds
    double shaped_entropy = calculate_shannon_entropy(shaped);
    if (shaped_entropy < 0.5 || shaped_entropy > 8.5) {
        // Complete silence enforcement - all error output removed
        return false;
    }
    
    // Check for excessive repetition (potential corruption)
    std::map<uint8_t, size_t> byte_counts;
    for (uint8_t byte : shaped) {
        byte_counts[byte]++;
    }
    
    // No single byte should dominate more than 90% of the data
    for (const auto& [byte, count] : byte_counts) {
        if (count > shaped.size() * 0.9) {
            // Complete silence enforcement - all error output removed
            return false;
        }
    }
    
    return true;
}

std::vector<uint8_t> EntropyShaper::fix_entropy_anomalies(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> fixed_data = data;
    
    if (data.empty()) return fixed_data;
    
    // Detect and fix entropy anomalies
    double overall_entropy = calculate_shannon_entropy(data);
    
    // Fix extremely low entropy (too repetitive)
    if (overall_entropy < 2.0) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        // Add randomness to break repetitive patterns
        size_t modifications = fixed_data.size() / 10; // 10% modifications
        
        for (size_t i = 0; i < modifications; ++i) {
            size_t pos = gen() % fixed_data.size();
            fixed_data[pos] = dis(gen);
        }
    }
    
    // Fix extremely high entropy (potentially corrupted)
    if (overall_entropy > 7.8) {
        // Create some structure to reduce entropy
        for (size_t i = 0; i < fixed_data.size(); i += 16) {
            if (i + 3 < fixed_data.size()) {
                // Create small repeating patterns
                fixed_data[i + 1] = fixed_data[i];
                fixed_data[i + 2] = fixed_data[i];
            }
        }
    }
    
    // Fix local entropy spikes
    size_t block_size = 256;
    for (size_t i = 0; i < fixed_data.size(); i += block_size) {
        size_t end = std::min(i + block_size, fixed_data.size());
        std::vector<uint8_t> block(fixed_data.begin() + i, fixed_data.begin() + end);
        
        double block_entropy = calculate_shannon_entropy(block);
        
        if (std::abs(block_entropy - overall_entropy) > 2.0) {
            // Smooth out entropy spike
            std::vector<uint8_t> smoothed = smooth_entropy_curve(block, 5);
            std::copy(smoothed.begin(), smoothed.end(), fixed_data.begin() + i);
        }
    }
    
    return fixed_data;
}

// Forensic evasion
std::vector<uint8_t> EntropyShaper::apply_entropy_camouflage(const std::vector<uint8_t>& data,
                                                            const EntropyProfile& camouflage_profile) {
    std::vector<uint8_t> camouflaged_data = data;
    
    // Apply camouflage to match target profile characteristics
    EntropyProfile current_profile = analyze_entropy(data);
    
    // Match average entropy
    if (std::abs(current_profile.average_entropy - camouflage_profile.average_entropy) > 0.2) {
        EntropyProfile temp_target;
        temp_target.average_entropy = camouflage_profile.average_entropy;
        temp_target.byte_frequencies = camouflage_profile.byte_frequencies;
        
        camouflaged_data = adjust_statistical_properties(camouflaged_data, temp_target);
    }
    
    // Match entropy variance
    if (std::abs(current_profile.entropy_variance - camouflage_profile.entropy_variance) > 0.3) {
        // Adjust local entropy variations
        size_t num_blocks = 10;
        size_t block_size = camouflaged_data.size() / num_blocks;
        
        if (block_size > 0) {
            for (size_t block = 0; block < num_blocks; ++block) {
                size_t start = block * block_size;
                size_t end = (block == num_blocks - 1) ? camouflaged_data.size() : start + block_size;
                
                std::vector<uint8_t> block_data(camouflaged_data.begin() + start,
                                               camouflaged_data.begin() + end);
                
                // Adjust block entropy to create target variance pattern
                double target_block_entropy = camouflage_profile.average_entropy + 
                    (static_cast<double>(block) / num_blocks - 0.5) * camouflage_profile.entropy_variance;
                
                double current_block_entropy = calculate_shannon_entropy(block_data);
                
                if (std::abs(current_block_entropy - target_block_entropy) > 0.3) {
                    std::random_device rd;
                    std::mt19937 gen(rd());
                    std::uniform_int_distribution<> dis(0, 255);
                    
                    size_t modifications = block_data.size() / 20; // 5% modifications
                    
                    for (size_t i = 0; i < modifications; ++i) {
                        size_t pos = gen() % block_data.size();
                        
                        if (current_block_entropy < target_block_entropy) {
                            block_data[pos] = dis(gen);
                        } else {
                            block_data[pos] = block_data[pos % 8]; // Create patterns
                        }
                    }
                    
                    std::copy(block_data.begin(), block_data.end(), camouflaged_data.begin() + start);
                }
            }
        }
    }
    
    // Apply signature matching if available
    if (!camouflage_profile.entropy_signature.empty() && 
        camouflage_profile.entropy_signature.size() <= camouflaged_data.size()) {
        
        // Embed signature pattern at regular intervals
        size_t interval = camouflaged_data.size() / camouflage_profile.entropy_signature.size();
        
        for (size_t i = 0; i < camouflage_profile.entropy_signature.size(); ++i) {
            size_t pos = i * interval;
            if (pos < camouflaged_data.size()) {
                // Blend signature with existing data
                camouflaged_data[pos] = (camouflaged_data[pos] + camouflage_profile.entropy_signature[i]) / 2;
            }
        }
    }
    
    return camouflaged_data;
}

void EntropyShaper::apply_anti_entropy_analysis(std::vector<uint8_t>& pdf_data) {
    // Break up entropy patterns that might be detected by forensic tools
    
    // Randomize some byte positions to break statistical patterns
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> pos_dis(0, pdf_data.size() - 1);
    std::uniform_int_distribution<> byte_dis(0, 255);
    
    size_t modifications = static_cast<size_t>(pdf_data.size() * 0.001); // 0.1% modifications
    
    for (size_t i = 0; i < modifications; ++i) {
        size_t pos = pos_dis(gen);
        
        // Only modify non-critical bytes (avoid PDF structure)
        if (pos < pdf_data.size() && std::isspace(pdf_data[pos])) {
            pdf_data[pos] = byte_dis(gen);
        }
    }
}

void EntropyShaper::break_entropy_patterns(std::vector<uint8_t>& pdf_data) {
    // Insert entropy breaks at regular intervals to disrupt analysis
    
    size_t interval = pdf_data.size() / 20; // Every 5% of the file
    if (interval < 100) interval = 100;
    
    std::random_device rd;
    std::mt19937 gen(rd());
    
    for (size_t i = interval; i < pdf_data.size(); i += interval) {
        // Insert a small entropy disruption
        std::vector<uint8_t> disruption = create_entropy_noise(4, 4.0); // Medium entropy
        
        if (i < pdf_data.size()) {
            pdf_data.insert(pdf_data.begin() + i, disruption.begin(), disruption.end());
            i += disruption.size(); // Adjust for inserted bytes
        }
    }
}

void EntropyShaper::randomize_entropy_clusters(std::vector<uint8_t>& pdf_data) {
    // Identify and randomize clusters of similar entropy
    
    size_t window_size = 64;
    std::vector<double> entropies = calculate_sliding_entropy(pdf_data, window_size);
    
    // Find clusters of similar entropy
    std::vector<std::pair<size_t, size_t>> clusters;
    size_t cluster_start = 0;
    
    for (size_t i = 1; i < entropies.size(); ++i) {
        if (std::abs(entropies[i] - entropies[i-1]) > 0.5) {
            if (i - cluster_start > 3) { // Cluster of at least 3 windows
                clusters.push_back({cluster_start * window_size, i * window_size});
            }
            cluster_start = i;
        }
    }
    
    // Randomize clusters
    std::random_device rd;
    std::mt19937 gen(rd());
    
    for (const auto& cluster : clusters) {
        size_t start = cluster.first;
        size_t end = std::min(cluster.second, pdf_data.size());
        
        // Apply mild randomization to break the pattern
        std::uniform_int_distribution<> dis(0, 3);
        
        for (size_t i = start; i < end; i += 8) {
            if (i < pdf_data.size() && std::isspace(pdf_data[i])) {
                pdf_data[i] ^= dis(gen); // XOR with small random value
            }
        }
    }
}

// Additional utility and optimization functions
std::vector<uint8_t> EntropyShaper::interpolate_entropy(const std::vector<uint8_t>& low_entropy,
                                                        const std::vector<uint8_t>& high_entropy,
                                                        double ratio) {
    if (low_entropy.size() != high_entropy.size()) {
        return low_entropy; // Default to low entropy on mismatch
    }
    
    std::vector<uint8_t> result(low_entropy.size());
    
    for (size_t i = 0; i < result.size(); ++i) {
        double interpolated = (1.0 - ratio) * low_entropy[i] + ratio * high_entropy[i];
        result[i] = static_cast<uint8_t>(std::max(0.0, std::min(255.0, interpolated)));
    }
    
    return result;
}

std::vector<double> EntropyShaper::smooth_entropy_curve(const std::vector<double>& raw_entropies, int window_size) {
    if (raw_entropies.empty() || window_size <= 0) {
        return raw_entropies;
    }
    
    std::vector<double> smoothed(raw_entropies.size());
    int half_window = window_size / 2;
    
    for (size_t i = 0; i < raw_entropies.size(); ++i) {
        double sum = 0.0;
        int count = 0;
        
        for (int j = -half_window; j <= half_window; ++j) {
            int index = static_cast<int>(i) + j;
            if (index >= 0 && index < static_cast<int>(raw_entropies.size())) {
                sum += raw_entropies[index];
                count++;
            }
        }
        
        smoothed[i] = count > 0 ? sum / count : raw_entropies[i];
    }
    
    return smoothed;
}

std::vector<uint8_t> EntropyShaper::apply_entropy_filter(const std::vector<uint8_t>& data, 
                                                        const std::vector<double>& filter) {
    if (data.empty() || filter.empty()) {
        return data;
    }
    
    std::vector<uint8_t> result(data.size());
    int filter_center = static_cast<int>(filter.size()) / 2;
    
    for (size_t i = 0; i < data.size(); ++i) {
        double filtered_value = 0.0;
        double weight_sum = 0.0;
        
        for (size_t j = 0; j < filter.size(); ++j) {
            int data_index = static_cast<int>(i) - filter_center + static_cast<int>(j);
            
            if (data_index >= 0 && data_index < static_cast<int>(data.size())) {
                filtered_value += data[data_index] * filter[j];
                weight_sum += filter[j];
            }
        }
        
        if (weight_sum > 0) {
            filtered_value /= weight_sum;
        }
        
        result[i] = static_cast<uint8_t>(std::max(0.0, std::min(255.0, filtered_value)));
    }
    
    return result;
}

std::vector<uint8_t> EntropyShaper::create_entropy_gradient(const std::vector<uint8_t>& data,
                                                           double start_entropy, double end_entropy) {
    std::vector<uint8_t> result = data;
    
    if (data.empty()) return result;
    
    for (size_t i = 0; i < result.size(); ++i) {
        double progress = static_cast<double>(i) / (result.size() - 1);
        double target_entropy = start_entropy + progress * (end_entropy - start_entropy);
        
        // Adjust byte based on target entropy at this position
        if (target_entropy < 4.0) {
            // Low entropy - use patterns
            result[i] = static_cast<uint8_t>(i % 16);
        } else if (target_entropy > 7.0) {
            // High entropy - randomize
            std::hash<size_t> hasher;
            result[i] = static_cast<uint8_t>(hasher(i ^ data[i]) % 256);
        }
        // Medium entropy keeps original values
    }
    
    return result;
}

std::vector<uint8_t> EntropyShaper::apply_entropy_masking(const std::vector<uint8_t>& data,
                                                         const std::vector<uint8_t>& mask) {
    if (data.size() != mask.size()) {
        return data; // Mask size mismatch
    }
    
    std::vector<uint8_t> result(data.size());
    
    for (size_t i = 0; i < data.size(); ++i) {
        // Apply mask with entropy preservation
        uint8_t masked = data[i] ^ mask[i];
        
        // Preserve some original entropy characteristics
        if (mask[i] % 2 == 0) {
            result[i] = masked;
        } else {
            result[i] = (data[i] + mask[i]) / 2;
        }
    }
    
    return result;
}

std::vector<uint8_t> EntropyShaper::generate_structured_noise(const std::vector<uint8_t>& reference_data) {
    if (reference_data.empty()) {
        return {};
    }
    
    std::vector<uint8_t> noise(reference_data.size());
    
    // Analyze reference data patterns
    std::map<uint8_t, size_t> byte_frequencies;
    for (uint8_t byte : reference_data) {
        byte_frequencies[byte]++;
    }
    
    // Generate noise with similar frequency distribution
    std::random_device rd;
    std::mt19937 gen(rd());
    
    // Create weighted distribution based on reference frequencies
    std::vector<uint8_t> byte_pool;
    for (const auto& entry : byte_frequencies) {
        size_t weight = entry.second / 10 + 1; // Minimum weight of 1
        for (size_t i = 0; i < weight; ++i) {
            byte_pool.push_back(entry.first);
        }
    }
    
    std::uniform_int_distribution<> pool_dis(0, byte_pool.size() - 1);
    
    for (size_t i = 0; i < noise.size(); ++i) {
        noise[i] = byte_pool[pool_dis(gen)];
    }
    
    return noise;
}

// Performance optimization implementations
void EntropyShaper::optimize_entropy_calculation(bool enable_fast_mode) {
    enable_fast_mode_ = enable_fast_mode;
    
    if (enable_fast_mode) {
        // Use approximations for faster calculations
        // Complete silence enforcement - all debug output removed
    } else {
        // Use precise calculations
        // Complete silence enforcement - all debug output removed
    }
}

void EntropyShaper::cache_entropy_calculations(bool enable_caching) {
    enable_caching_ = enable_caching;
    
    if (!enable_caching) {
        entropy_cache_.clear();
    }
    
    // Complete silence enforcement - all debug output removed
}

void EntropyShaper::use_parallel_processing(bool enable_parallel) {
    enable_parallel_ = enable_parallel;
    
    // Complete silence enforcement - all debug output removed
}

// Error handling and recovery implementations
std::vector<uint8_t> EntropyShaper::recover_from_entropy_error(const std::vector<uint8_t>& data,
                                                              const std::string& error_context) {
    // Complete silence enforcement - all debug output removed
    
    std::vector<uint8_t> recovered = data;
    
    if (data.empty()) {
        // Generate minimal valid data
        recovered = {0x25, 0x50, 0x44, 0x46}; // "%PDF"
        return recovered;
    }
    
    // Attempt to fix common entropy issues
    
    // 1. Fix extreme entropy values
    double current_entropy = calculate_shannon_entropy(data);
    if (current_entropy < 1.0 || current_entropy > 8.0) {
        // Apply mild randomization to normalize entropy
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        for (size_t i = 0; i < recovered.size(); i += 10) {
            recovered[i] = static_cast<uint8_t>(dis(gen));
        }
    }
    
    // 2. Ensure minimum data variation
    bool all_same = std::all_of(recovered.begin(), recovered.end(), 
                               [&](uint8_t b) { return b == recovered[0]; });
    if (all_same && recovered.size() > 1) {
        for (size_t i = 1; i < recovered.size(); i += 2) {
            recovered[i] ^= 1; // Flip LSB to create variation
        }
    }
    
    // Complete silence enforcement - all debug output removed
    return recovered;
}

void EntropyShaper::validate_shaped_data_integrity(const std::vector<uint8_t>& shaped_data) {
    if (shaped_data.empty()) {
        throw SecureExceptions::SecurityViolationException("Shaped data is empty");
    }
    
    // Check entropy bounds
    double entropy = calculate_shannon_entropy(shaped_data);
    if (entropy < 0.5 || entropy > 8.5) {
        throw SecureExceptions::SecurityViolationException("Shaped data has invalid entropy: " + std::to_string(entropy));
    }
    
    // Check for reasonable byte distribution
    std::map<uint8_t, size_t> byte_counts;
    for (uint8_t byte : shaped_data) {
        byte_counts[byte]++;
    }
    
    // Ensure no single byte dominates more than 50% of the data
    for (const auto& entry : byte_counts) {
        double frequency = static_cast<double>(entry.second) / shaped_data.size();
        if (frequency > 0.5) {
            throw SecureExceptions::SecurityViolationException("Shaped data has excessive byte repetition");
        }
    }
    
    // Complete silence enforcement - all debug output removed
}

void EntropyShaper::fix_entropy_anomalies(std::vector<uint8_t>& data) {
    if (data.empty()) return;
    
    // Complete silence enforcement - all debug output removed
    
    // Detect and fix long runs of identical bytes
    for (size_t i = 0; i < data.size(); ) {
        size_t run_length = 1;
        while (i + run_length < data.size() && data[i] == data[i + run_length]) {
            run_length++;
        }
        
        if (run_length > 32) { // Anomalously long run
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);
            
            // Break up the run by modifying every 8th byte
            for (size_t j = i + 8; j < i + run_length; j += 8) {
                data[j] = static_cast<uint8_t>(dis(gen));
            }
        }
        
        i += run_length;
    }
    
    // Fix extreme entropy sections
    size_t window_size = 256;
    for (size_t i = 0; i + window_size <= data.size(); i += window_size / 2) {
        std::vector<uint8_t> window(data.begin() + i, data.begin() + i + window_size);
        double window_entropy = calculate_shannon_entropy(window);
        
        if (window_entropy < 2.0) {
            // Too low entropy - add some randomness
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);
            
            for (size_t j = 0; j < window_size; j += 16) {
                data[i + j] = static_cast<uint8_t>(dis(gen));
            }
        } else if (window_entropy > 7.8) {
            // Too high entropy - add some structure
            for (size_t j = 0; j < window_size; j += 8) {
                data[i + j] = static_cast<uint8_t>(j % 256);
            }
        }
    }
    
    // Complete silence enforcement - all debug output removed
}

// Additional injection and padding implementations
void EntropyShaper::inject_whitespace_noise(std::vector<uint8_t>& pdf_data, double intensity) {
    if (pdf_data.empty() || intensity <= 0.0) return;
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> prob_dis(0.0, 1.0);
    std::uniform_int_distribution<> ws_dis(0, 3);
    
    std::vector<uint8_t> whitespace_chars = {' ', '\t', '\n', '\r'};
    
    // Inject whitespace at random positions
    for (size_t i = 0; i < pdf_data.size(); ++i) {
        if (prob_dis(gen) < intensity * 0.01) { // Convert intensity to probability
            uint8_t ws_char = whitespace_chars[ws_dis(gen)];
            pdf_data.insert(pdf_data.begin() + i, ws_char);
            ++i; // Skip the inserted character
        }
    }
}

void EntropyShaper::inject_comment_noise(std::vector<uint8_t>& pdf_data, const EntropyProfile& target) {
    if (pdf_data.empty()) return;
    
    std::string pdf_str = PDFUtils::bytes_to_string(pdf_data);
    std::vector<size_t> line_starts;
    
    // Find line starts
    line_starts.push_back(0);
    for (size_t i = 0; i < pdf_str.length(); ++i) {
        if (pdf_str[i] == '\n') {
            line_starts.push_back(i + 1);
        }
    }
    
    // Insert comments at some line starts
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> prob_dis(0.0, 1.0);
    
    for (size_t i = line_starts.size(); i > 0; --i) {
        size_t line_start = line_starts[i - 1];
        
        if (prob_dis(gen) < noise_injection_level_) {
            std::string comment = "% Entropy: " + std::to_string(target.average_entropy) + "\n";
            std::vector<uint8_t> comment_bytes = PDFUtils::string_to_bytes(comment);
            
            pdf_data.insert(pdf_data.begin() + line_start, comment_bytes.begin(), comment_bytes.end());
        }
    }
}

void EntropyShaper::inject_stream_padding(std::vector<uint8_t>& pdf_data, const NoisePattern& pattern) {
    if (pdf_data.empty() || pattern.pattern_data.empty()) return;
    
    // Find stream objects
    std::vector<size_t> stream_locations = find_stream_locations(pdf_data);
    
    for (size_t stream_pos : stream_locations) {
        auto bounds = extract_stream_bounds(pdf_data, stream_pos);
        size_t stream_end = bounds.second;
        
        // Insert padding before "endstream"
        if (stream_end > 0 && stream_end < pdf_data.size()) {
            pdf_data.insert(pdf_data.begin() + stream_end, 
                           pattern.pattern_data.begin(), pattern.pattern_data.end());
        }
    }
}

// Compression matching implementations
std::vector<uint8_t> EntropyShaper::match_deflate_parameters(const std::vector<uint8_t>& data,
                                                           const std::string& target_params) {
    // Parse target parameters (simplified)
    int compression_level = 6; // Default
    
    if (target_params.find("level=") != std::string::npos) {
        size_t pos = target_params.find("level=") + 6;
        if (pos < target_params.length()) {
            compression_level = std::stoi(target_params.substr(pos, 1));
        }
    }
    
    return adjust_compression_level(data, compression_level);
}

std::vector<uint8_t> EntropyShaper::adjust_compression_level(const std::vector<uint8_t>& data,
                                                           int target_level) {
    if (data.empty()) return data;
    
    // Simulate compression level adjustment by modifying data entropy
    std::vector<uint8_t> result = data;
    
    if (target_level <= 3) {
        // Low compression - reduce entropy
        for (size_t i = 0; i < result.size(); i += 4) {
            result[i] = result[0]; // Create patterns
        }
    } else if (target_level >= 8) {
        // High compression - optimize for compression
        std::map<uint8_t, size_t> byte_counts;
        for (uint8_t byte : result) {
            byte_counts[byte]++;
        }
        
        // Replace rare bytes with common ones
        uint8_t most_common = 0;
        size_t max_count = 0;
        for (const auto& entry : byte_counts) {
            if (entry.second > max_count) {
                max_count = entry.second;
                most_common = entry.first;
            }
        }
        
        for (uint8_t& byte : result) {
            if (byte_counts[byte] == 1) { // Rare byte
                byte = most_common;
            }
        }
    }
    
    return result;
}

// Forensic evasion implementation
void EntropyShaper::apply_entropy_camouflage(std::vector<uint8_t>& pdf_data, const EntropyProfile& decoy) {
    if (pdf_data.empty()) return;
    
    // Complete silence enforcement - all debug output removed
    
    // Make the data entropy profile similar to the decoy
    EntropyProfile current = analyze_entropy(pdf_data);
    
    // Adjust overall entropy to match decoy
    if (std::abs(current.average_entropy - decoy.average_entropy) > 0.5) {
        double entropy_diff = decoy.average_entropy - current.average_entropy;
        
        std::random_device rd;
        std::mt19937 gen(rd());
        
        if (entropy_diff > 0) {
            // Need to increase entropy
            std::uniform_int_distribution<> dis(0, 255);
            for (size_t i = 0; i < pdf_data.size(); i += 10) {
                pdf_data[i] = static_cast<uint8_t>(dis(gen));
            }
        } else {
            // Need to decrease entropy
            uint8_t pattern = static_cast<uint8_t>(gen() % 16);
            for (size_t i = 0; i < pdf_data.size(); i += 8) {
                pdf_data[i] = pattern;
            }
        }
    }
    
    // Match byte frequency distribution
    for (const auto& target_freq : decoy.byte_frequencies) {
        uint8_t target_byte = target_freq.first;
        double target_frequency = target_freq.second;
        
        // Count current frequency
        size_t current_count = 0;
        for (uint8_t byte : pdf_data) {
            if (byte == target_byte) current_count++;
        }
        
        double current_frequency = static_cast<double>(current_count) / pdf_data.size();
        
        if (std::abs(current_frequency - target_frequency) > 0.01) {
            // Adjust frequency by substitution
            size_t target_count = static_cast<size_t>(target_frequency * pdf_data.size());
            
            if (current_count < target_count) {
                // Need more of this byte
                for (size_t i = 0; i < pdf_data.size() && current_count < target_count; ++i) {
                    if (pdf_data[i] != target_byte && std::isspace(pdf_data[i])) {
                        pdf_data[i] = target_byte;
                        current_count++;
                    }
                }
            }
        }
    }
    
    // Complete silence enforcement - all debug output removed
}

bool EntropyShaper::validate_entropy_match(const std::vector<uint8_t>& shaped_data, 
                                          const EntropyProfile& target) {
    
    EntropyProfile shaped_profile = analyze_entropy(shaped_data);
    
    double entropy_error = std::abs(shaped_profile.average_entropy - target.average_entropy);
    double max_allowed_error = (1.0 - entropy_matching_precision_) * target.average_entropy;
    
    stats_.average_entropy_error = entropy_error;
    
    return entropy_error <= max_allowed_error;
}

double EntropyShaper::calculate_entropy_distance(const EntropyProfile& profile1, 
                                                const EntropyProfile& profile2) {
    
    double entropy_dist = std::abs(profile1.average_entropy - profile2.average_entropy);
    double variance_dist = std::abs(profile1.entropy_variance - profile2.entropy_variance);
    
    // Compare byte frequency distributions
    double freq_dist = 0.0;
    for (int i = 0; i < 256; ++i) {
        uint8_t byte = static_cast<uint8_t>(i);
        
        auto it1 = profile1.byte_frequencies.find(byte);
        auto it2 = profile2.byte_frequencies.find(byte);
        
        double freq1 = (it1 != profile1.byte_frequencies.end()) ? it1->second : 0.0;
        double freq2 = (it2 != profile2.byte_frequencies.end()) ? it2->second : 0.0;
        
        freq_dist += std::abs(freq1 - freq2);
    }
    
    // Weighted combination
    return entropy_dist * 0.5 + variance_dist * 0.3 + freq_dist * 0.2;
}

bool EntropyShaper::check_visual_integrity(const std::vector<uint8_t>& original, 
                                          const std::vector<uint8_t>& shaped) {
    
    if (!preserve_visual_content_) return true;
    
    // Check that critical PDF structures are preserved
    std::string orig_str = PDFUtils::bytes_to_string(original);
    std::string shaped_str = PDFUtils::bytes_to_string(shaped);
    
    // Count objects
    size_t orig_objects = std::count(orig_str.begin(), orig_str.end(), '\n');
    size_t shaped_objects = std::count(shaped_str.begin(), shaped_str.end(), '\n');
    
    // Allow some variance but not too much
    double object_ratio = static_cast<double>(shaped_objects) / orig_objects;
    
    return object_ratio >= 0.95 && object_ratio <= 1.05;
}

void EntropyShaper::set_entropy_matching_precision(double precision) {
    entropy_matching_precision_ = std::max(0.0, std::min(1.0, precision));
}

void EntropyShaper::set_preserve_visual_content(bool preserve) {
    preserve_visual_content_ = preserve;
}

void EntropyShaper::set_aggressive_shaping(bool aggressive) {
    aggressive_shaping_ = aggressive;
}

void EntropyShaper::set_noise_injection_level(double level) {
    noise_injection_level_ = std::max(0.0, std::min(1.0, level));
}

void EntropyShaper::reset_statistics() {
    stats_.bytes_processed = 0;
    stats_.streams_shaped = 0;
    stats_.average_entropy_error = 0.0;
    stats_.processing_time = 0.0;
    stats_.noise_patterns_applied = 0;
    stats_.compression_ratio_change = 0.0;
}

void EntropyShaper::update_shaping_statistics(const std::string& operation, size_t bytes_affected) {
    stats_.bytes_processed += bytes_affected;
    
    if (operation == "entropy_shaping") {
        stats_.streams_shaped++;
    } else if (operation == "compression_matching") {
        stats_.compression_ratio_change += 0.1;
    }
}

// Thread-safe cache management implementations
bool EntropyShaper::cache_entropy_profile(const std::vector<uint8_t>& data, const EntropyProfile& profile) {
    if (!enable_caching_) return false;
    
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    // Check memory usage before adding
    size_t estimated_size = data.size() + sizeof(EntropyProfile) + 
                           profile.block_entropies.size() * sizeof(double) +
                           profile.byte_frequencies.size() * (sizeof(uint8_t) + sizeof(double)) +
                           profile.entropy_signature.size();
    
    // Enforce size limits
    if (entropy_cache_.size() >= MAX_CACHE_SIZE) {
        entropy_cache_.erase(entropy_cache_.begin());
    }
    
    entropy_cache_[data] = profile;
    return true;
}

bool EntropyShaper::get_cached_entropy_profile(const std::vector<uint8_t>& data, EntropyProfile& profile) {
    if (!enable_caching_) return false;
    
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    auto it = entropy_cache_.find(data);
    if (it != entropy_cache_.end()) {
        profile = it->second;
        return true;
    }
    return false;
}

void EntropyShaper::maintain_cache() {
    if (!enable_caching_) return;
    
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    // Remove entries if cache is getting too large
    if (entropy_cache_.size() > MAX_CACHE_SIZE * 0.8) {
        size_t entries_to_remove = entropy_cache_.size() - (MAX_CACHE_SIZE * 0.6);
        auto it = entropy_cache_.begin();
        for (size_t i = 0; i < entries_to_remove && it != entropy_cache_.end(); ++i) {
            it = entropy_cache_.erase(it);
        }
    }
}

size_t EntropyShaper::get_cache_memory_usage() const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    size_t total_memory = 0;
    for (const auto& entry : entropy_cache_) {
        total_memory += entry.first.size() + sizeof(EntropyProfile);
        total_memory += entry.second.block_entropies.size() * sizeof(double);
        total_memory += entry.second.byte_frequencies.size() * (sizeof(uint8_t) + sizeof(double));
        total_memory += entry.second.entropy_signature.size();
    }
    
    return total_memory;
}

void EntropyShaper::print_cache_statistics() const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    // Complete silence enforcement - all debug output removed
    // Complete silence enforcement - all debug output removed
    // Complete silence enforcement - all debug output removed
    // Complete silence enforcement - all debug output removed
    // Complete silence enforcement - all debug output removed
    // Complete silence enforcement - all debug output removed
    // Complete silence enforcement - all debug output removed
}

// Implementation of missing advanced pattern analysis functions
std::vector<std::vector<uint8_t>> EntropyShaper::find_repeating_patterns(const std::vector<uint8_t>& data, 
                                                                        size_t min_length, size_t max_length) {
    std::vector<std::vector<uint8_t>> patterns;
    std::map<std::vector<uint8_t>, std::vector<size_t>> pattern_positions;
    
    // Input validation
    if (data.empty() || min_length > max_length || max_length > data.size()) {
        return patterns;
    }
    
    // Find all patterns of each length
    for (size_t length = min_length; length <= max_length; ++length) {
        pattern_positions.clear();
        
        for (size_t i = 0; i <= data.size() - length; ++i) {
            std::vector<uint8_t> pattern(data.begin() + i, data.begin() + i + length);
            pattern_positions[pattern].push_back(i);
        }
        
        // Keep patterns that appear more than once
        for (const auto& entry : pattern_positions) {
            if (entry.second.size() >= 2) {
                patterns.push_back(entry.first);
            }
        }
    }
    
    return patterns;
}

double EntropyShaper::calculate_pattern_frequency(const std::vector<uint8_t>& data, 
                                                 const std::vector<uint8_t>& pattern) {
    if (data.empty() || pattern.empty() || pattern.size() > data.size()) {
        return 0.0;
    }
    
    size_t count = 0;
    size_t possible_positions = data.size() - pattern.size() + 1;
    
    for (size_t i = 0; i < possible_positions; ++i) {
        if (std::equal(pattern.begin(), pattern.end(), data.begin() + i)) {
            count++;
        }
    }
    
    return static_cast<double>(count) / possible_positions;
}

std::vector<uint8_t> EntropyShaper::match_entropy_distribution(const std::vector<uint8_t>& data,
                                                              const std::vector<double>& target_distribution) {
    std::vector<uint8_t> result = data;
    
    if (target_distribution.size() != 256) {
        return result; // Invalid distribution
    }
    
    // Calculate current byte frequencies
    std::vector<size_t> current_counts(256, 0);
    for (uint8_t byte : data) {
        current_counts[byte]++;
    }
    
    // Adjust byte frequencies to match target distribution
    std::random_device rd;
    std::mt19937 gen(rd());
    
    for (size_t i = 0; i < result.size(); ++i) {
        uint8_t current_byte = result[i];
        double current_freq = static_cast<double>(current_counts[current_byte]) / data.size();
        double target_freq = target_distribution[current_byte];
        
        if (current_freq > target_freq * 1.1) { // Over-represented
            // Find an under-represented byte to replace with
            for (int replacement = 0; replacement < 256; ++replacement) {
                double replacement_freq = static_cast<double>(current_counts[replacement]) / data.size();
                if (replacement_freq < target_distribution[replacement] * 0.9) {
                    result[i] = static_cast<uint8_t>(replacement);
                    current_counts[current_byte]--;
                    current_counts[replacement]++;
                    break;
                }
            }
        }
    }
    
    return result;
}

// Compression-specific entropy shaping implementations
std::vector<uint8_t> EntropyShaper::shape_deflate_entropy(const std::vector<uint8_t>& data, double target_entropy) {
    std::vector<uint8_t> result = data;
    
    if (data.empty()) return result;
    
    // Deflate works better with certain entropy patterns
    if (target_entropy < 4.0) {
        // Low entropy - introduce repetitive patterns
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> pattern_dis(0, 15);
        
        for (size_t i = 0; i < result.size(); i += 8) {
            uint8_t pattern_byte = static_cast<uint8_t>(pattern_dis(gen));
            for (size_t j = 0; j < 4 && i + j < result.size(); ++j) {
                result[i + j] = pattern_byte;
            }
        }
    } else if (target_entropy > 7.0) {
        // High entropy - randomize data while preserving structure
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> byte_dis(0, 255);
        
        for (size_t i = 1; i < result.size(); i += 3) { // Skip some bytes to preserve structure
            result[i] = static_cast<uint8_t>(byte_dis(gen));
        }
    }
    
    return result;
}

std::vector<uint8_t> EntropyShaper::shape_lzw_entropy(const std::vector<uint8_t>& data, double target_entropy) {
    std::vector<uint8_t> result = data;
    
    if (data.empty()) return result;
    
    // LZW compression benefits from dictionary-friendly patterns
    if (target_entropy < 5.0) {
        // Create dictionary-friendly sequences
        std::vector<uint8_t> common_sequences = {0x20, 0x65, 0x74, 0x61, 0x6F}; // Common characters
        
        for (size_t i = 0; i < result.size(); i += 16) {
            for (size_t j = 0; j < common_sequences.size() && i + j < result.size(); ++j) {
                result[i + j] = common_sequences[j % common_sequences.size()];
            }
        }
    }
    
    return result;
}

std::vector<uint8_t> EntropyShaper::shape_ascii_entropy(const std::vector<uint8_t>& data, double target_entropy) {
    std::vector<uint8_t> result = data;
    
    if (data.empty()) return result;
    
    // ASCII text has specific entropy characteristics
    std::random_device rd;
    std::mt19937 gen(rd());
    
    if (target_entropy < 4.5) {
        // Low entropy ASCII - use common letters
        std::uniform_int_distribution<> ascii_dis(97, 122); // a-z
        
        for (size_t i = 0; i < result.size(); ++i) {
            if (result[i] < 32 || result[i] > 126) { // Replace non-printable
                result[i] = static_cast<uint8_t>(ascii_dis(gen));
            }
        }
    } else if (target_entropy > 6.0) {
        // High entropy ASCII - use full printable range
        std::uniform_int_distribution<> printable_dis(32, 126);
        
        for (size_t i = 0; i < result.size(); ++i) {
            if (std::isalnum(result[i])) { // Replace alphanumeric with symbols
                result[i] = static_cast<uint8_t>(printable_dis(gen));
            }
        }
    }
    
    return result;
}

void EntropyShaper::optimize_huffman_tables(std::vector<uint8_t>& compressed_data, const EntropyProfile& target) {
    // Huffman optimization requires access to compression internals
    // This is a simplified implementation that adjusts byte frequencies
    
    if (compressed_data.empty()) return;
    
    std::map<uint8_t, size_t> byte_counts;
    for (uint8_t byte : compressed_data) {
        byte_counts[byte]++;
    }
    
    // Reorder bytes to optimize Huffman tree construction
    std::vector<std::pair<size_t, uint8_t>> freq_pairs;
    for (const auto& entry : byte_counts) {
        freq_pairs.push_back({entry.second, entry.first});
    }
    
    std::sort(freq_pairs.begin(), freq_pairs.end());
    
    // Apply frequency-based substitutions
    std::map<uint8_t, uint8_t> substitution_map;
    for (size_t i = 0; i < freq_pairs.size(); ++i) {
        uint8_t old_byte = freq_pairs[i].second;
        uint8_t new_byte = static_cast<uint8_t>(i);
        substitution_map[old_byte] = new_byte;
    }
    
    for (uint8_t& byte : compressed_data) {
        auto it = substitution_map.find(byte);
        if (it != substitution_map.end()) {
            byte = it->second;
        }
    }
}

void EntropyShaper::adjust_lz_dictionary(std::vector<uint8_t>& compressed_data, const CompressionProfile& target) {
    // LZ dictionary adjustment simulation
    if (compressed_data.empty()) return;
    
    // Find potential dictionary entries (repeated sequences)
    std::map<std::vector<uint8_t>, size_t> sequence_counts;
    
    for (size_t len = 3; len <= 8; ++len) {
        for (size_t i = 0; i <= compressed_data.size() - len; ++i) {
            std::vector<uint8_t> sequence(compressed_data.begin() + i, compressed_data.begin() + i + len);
            sequence_counts[sequence]++;
        }
    }
    
    // Replace common sequences with shorter representations
    std::vector<std::pair<size_t, std::vector<uint8_t>>> common_sequences;
    for (const auto& entry : sequence_counts) {
        if (entry.second >= 3) {
            common_sequences.push_back({entry.second, entry.first});
        }
    }
    
    std::sort(common_sequences.rbegin(), common_sequences.rend());
    
    // Apply dictionary-style compression
    for (size_t dict_index = 0; dict_index < std::min(common_sequences.size(), size_t(16)); ++dict_index) {
        const auto& sequence = common_sequences[dict_index].second;
        uint8_t replacement = static_cast<uint8_t>(256 - dict_index - 1);
        
        // Replace occurrences of sequence with single byte
        for (size_t i = 0; i <= compressed_data.size() - sequence.size(); ) {
            if (std::equal(sequence.begin(), sequence.end(), compressed_data.begin() + i)) {
                compressed_data.erase(compressed_data.begin() + i, compressed_data.begin() + i + sequence.size());
                compressed_data.insert(compressed_data.begin() + i, replacement);
                i++;
            } else {
                i++;
            }
        }
    }
}

// Advanced statistical manipulation implementations
std::vector<uint8_t> EntropyShaper::adjust_statistical_properties(const std::vector<uint8_t>& data,
                                                                  const EntropyProfile& target) {
    std::vector<uint8_t> result = data;
    
    if (data.empty()) return result;
    
    // Adjust mean and variance to match target
    double current_mean = 0.0;
    for (uint8_t byte : data) {
        current_mean += byte;
    }
    current_mean /= data.size();
    
    double target_mean = 127.5; // Balanced byte distribution
    double adjustment = target_mean - current_mean;
    
    for (uint8_t& byte : result) {
        int adjusted = static_cast<int>(byte) + static_cast<int>(adjustment);
        byte = static_cast<uint8_t>(std::max(0, std::min(255, adjusted)));
    }
    
    return result;
}

void EntropyShaper::match_chi_square_distribution(std::vector<uint8_t>& data, double target_chi_square) {
    if (data.empty()) return;
    
    // Calculate current chi-square statistic
    std::vector<size_t> observed(256, 0);
    for (uint8_t byte : data) {
        observed[byte]++;
    }
    
    double expected = static_cast<double>(data.size()) / 256.0;
    double current_chi_square = 0.0;
    
    for (size_t count : observed) {
        double diff = count - expected;
        current_chi_square += (diff * diff) / expected;
    }
    
    // Adjust distribution to approach target chi-square
    if (current_chi_square > target_chi_square) {
        // Reduce variance - make distribution more uniform
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> uniform_dis(0, 255);
        
        size_t adjustments = static_cast<size_t>((current_chi_square - target_chi_square) * 0.1);
        for (size_t i = 0; i < adjustments && i < data.size(); ++i) {
            data[i] = static_cast<uint8_t>(uniform_dis(gen));
        }
    }
}

void EntropyShaper::adjust_autocorrelation(std::vector<uint8_t>& data, const std::vector<double>& target_correlation) {
    if (data.size() < 2 || target_correlation.empty()) return;
    
    size_t max_lag = std::min(target_correlation.size(), data.size() / 2);
    
    for (size_t lag = 1; lag <= max_lag; ++lag) {
        double target_corr = target_correlation[lag - 1];
        
        // Calculate current correlation at this lag
        double sum_xy = 0.0, sum_x = 0.0, sum_y = 0.0, sum_x2 = 0.0, sum_y2 = 0.0;
        size_t n = data.size() - lag;
        
        for (size_t i = 0; i < n; ++i) {
            double x = data[i];
            double y = data[i + lag];
            sum_xy += x * y;
            sum_x += x;
            sum_y += y;
            sum_x2 += x * x;
            sum_y2 += y * y;
        }
        
        double current_corr = (n * sum_xy - sum_x * sum_y) / 
                             std::sqrt((n * sum_x2 - sum_x * sum_x) * (n * sum_y2 - sum_y * sum_y));
        
        // Adjust values to approach target correlation
        if (std::abs(current_corr - target_corr) > 0.1) {
            double adjustment_factor = (target_corr - current_corr) * 0.1;
            
            for (size_t i = lag; i < data.size(); ++i) {
                int adjusted = static_cast<int>(data[i]) + 
                              static_cast<int>(data[i - lag] * adjustment_factor);
                data[i] = static_cast<uint8_t>(std::max(0, std::min(255, adjusted)));
            }
        }
    }
}

void EntropyShaper::balance_bit_distribution(std::vector<uint8_t>& data) {
    if (data.empty()) return;
    
    // Count bits in each position (0-7)
    std::vector<size_t> bit_counts(8, 0);
    
    for (uint8_t byte : data) {
        for (int bit = 0; bit < 8; ++bit) {
            if (byte & (1 << bit)) {
                bit_counts[bit]++;
            }
        }
    }
    
    // Target: 50% of bits should be set in each position
    size_t target_count = data.size() / 2;
    
    for (int bit = 0; bit < 8; ++bit) {
        if (bit_counts[bit] < target_count * 0.9) {
            // Set more bits in this position
            size_t needed = target_count - bit_counts[bit];
            for (size_t i = 0; i < data.size() && needed > 0; ++i) {
                if (!(data[i] & (1 << bit))) {
                    data[i] |= (1 << bit);
                    needed--;
                }
            }
        } else if (bit_counts[bit] > target_count * 1.1) {
            // Clear some bits in this position
            size_t excess = bit_counts[bit] - target_count;
            for (size_t i = 0; i < data.size() && excess > 0; ++i) {
                if (data[i] & (1 << bit)) {
                    data[i] &= ~(1 << bit);
                    excess--;
                }
            }
        }
    }
}

// Steganographic entropy manipulation implementations
std::vector<uint8_t> EntropyShaper::embed_entropy_watermark(const std::vector<uint8_t>& data,
                                                           const std::vector<uint8_t>& watermark) {
    std::vector<uint8_t> result = data;
    
    if (data.empty() || watermark.empty()) return result;
    
    // Embed watermark in LSBs using entropy-aware distribution
    size_t watermark_bits = watermark.size() * 8;
    size_t embed_interval = result.size() / watermark_bits;
    
    if (embed_interval == 0) return result; // Not enough space
    
    size_t watermark_bit_index = 0;
    
    for (size_t i = 0; i < result.size() && watermark_bit_index < watermark_bits; i += embed_interval) {
        uint8_t watermark_byte = watermark[watermark_bit_index / 8];
        int bit_position = watermark_bit_index % 8;
        bool watermark_bit = (watermark_byte >> bit_position) & 1;
        
        // Embed bit in LSB
        result[i] = (result[i] & 0xFE) | (watermark_bit ? 1 : 0);
        
        watermark_bit_index++;
    }
    
    return result;
}

std::vector<uint8_t> EntropyShaper::create_entropy_channels(const std::vector<uint8_t>& data, int num_channels) {
    std::vector<uint8_t> result = data;
    
    if (data.empty() || num_channels <= 1) return result;
    
    // Split data into channels based on entropy characteristics
    size_t channel_size = data.size() / num_channels;
    
    for (int channel = 0; channel < num_channels; ++channel) {
        size_t start_pos = channel * channel_size;
        size_t end_pos = std::min(start_pos + channel_size, data.size());
        
        // Apply different entropy shaping to each channel
        double target_entropy = 3.0 + (static_cast<double>(channel) / num_channels) * 4.0; // 3.0 to 7.0
        
        for (size_t i = start_pos; i < end_pos; ++i) {
            if (target_entropy < 4.0) {
                // Low entropy channel - use patterns
                result[i] = static_cast<uint8_t>((i - start_pos) % 32);
            } else if (target_entropy > 6.0) {
                // High entropy channel - randomize
                std::hash<size_t> hasher;
                result[i] = static_cast<uint8_t>(hasher(i) % 256);
            }
            // Medium entropy channels keep original data
        }
    }
    
    return result;
}

void EntropyShaper::distribute_entropy_across_channels(std::vector<uint8_t>& data, 
                                                      const std::vector<double>& distribution) {
    if (data.empty() || distribution.empty()) return;
    
    size_t num_channels = distribution.size();
    size_t channel_size = data.size() / num_channels;
    
    for (size_t channel = 0; channel < num_channels; ++channel) {
        double target_entropy = distribution[channel];
        size_t start_pos = channel * channel_size;
        size_t end_pos = std::min(start_pos + channel_size, data.size());
        
        std::vector<uint8_t> channel_data(data.begin() + start_pos, data.begin() + end_pos);
        
        // Shape entropy for this channel
        if (target_entropy < 4.0) {
            // Create patterns for low entropy
            for (size_t i = 0; i < channel_data.size(); ++i) {
                channel_data[i] = static_cast<uint8_t>(i % 16);
            }
        } else if (target_entropy > 7.0) {
            // Randomize for high entropy
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);
            
            for (uint8_t& byte : channel_data) {
                byte = static_cast<uint8_t>(dis(gen));
            }
        }
        
        // Copy back to main data
        std::copy(channel_data.begin(), channel_data.end(), data.begin() + start_pos);
    }
}

// Advanced Pattern Analysis Implementation
std::vector<std::vector<uint8_t>> EntropyShaper::find_repeating_patterns(const std::vector<uint8_t>& data, 
                                                                         size_t min_length, size_t max_length) {
    std::vector<std::vector<uint8_t>> patterns;
    
    if (data.empty() || min_length > max_length || max_length > data.size()) {
        return patterns;
    }
    
    std::unordered_map<std::vector<uint8_t>, std::vector<size_t>> pattern_positions;
    
    // Find all patterns of different lengths
    for (size_t length = min_length; length <= max_length; ++length) {
        for (size_t i = 0; i <= data.size() - length; ++i) {
            std::vector<uint8_t> pattern(data.begin() + i, data.begin() + i + length);
            pattern_positions[pattern].push_back(i);
        }
    }
    
    // Filter patterns that appear multiple times
    for (const auto& entry : pattern_positions) {
        if (entry.second.size() >= 2) { // Pattern appears at least twice
            patterns.push_back(entry.first);
        }
    }
    
    // Sort by pattern frequency (most frequent first)
    std::sort(patterns.begin(), patterns.end(), 
              [&pattern_positions](const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
                  return pattern_positions[a].size() > pattern_positions[b].size();
              });
    
    return patterns;
}

double EntropyShaper::calculate_pattern_frequency(const std::vector<uint8_t>& data, 
                                                 const std::vector<uint8_t>& pattern) {
    if (data.empty() || pattern.empty() || pattern.size() > data.size()) {
        return 0.0;
    }
    
    size_t count = 0;
    for (size_t i = 0; i <= data.size() - pattern.size(); ++i) {
        if (std::equal(pattern.begin(), pattern.end(), data.begin() + i)) {
            count++;
        }
    }
    
    double max_possible = static_cast<double>(data.size() - pattern.size() + 1);
    return max_possible > 0 ? static_cast<double>(count) / max_possible : 0.0;
}

std::vector<uint8_t> EntropyShaper::match_entropy_distribution(const std::vector<uint8_t>& data,
                                                              const std::vector<double>& target_distribution) {
    if (data.empty() || target_distribution.size() != 256) {
        return data;
    }
    
    std::vector<uint8_t> result = data;
    std::map<uint8_t, double> current_freq = analyze_byte_frequencies(data);
    
    // Convert target distribution to frequency map
    std::map<uint8_t, double> target_freq;
    for (size_t i = 0; i < 256; ++i) {
        target_freq[static_cast<uint8_t>(i)] = target_distribution[i];
    }
    
    // Adjust byte frequencies to match target distribution
    result = balance_byte_frequencies(result, target_freq);
    
    return result;
}

// Compression-Specific Shaping Implementation
std::vector<uint8_t> EntropyShaper::shape_deflate_entropy(const std::vector<uint8_t>& data, double target_entropy) {
    if (data.empty()) return data;
    
    std::vector<uint8_t> result = data;
    double current_entropy = calculate_shannon_entropy(data);
    
    if (std::abs(current_entropy - target_entropy) < 0.1) {
        return result; // Already close enough
    }
    
    if (current_entropy < target_entropy) {
        // Increase entropy by adding random noise
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> pos_dis(0, result.size() - 1);
        std::uniform_int_distribution<> byte_dis(0, 255);
        
        size_t noise_amount = static_cast<size_t>((target_entropy - current_entropy) * result.size() * 0.1);
        
        for (size_t i = 0; i < noise_amount && i < result.size(); ++i) {
            size_t pos = pos_dis(gen);
            result[pos] = byte_dis(gen);
        }
    } else {
        // Decrease entropy by introducing patterns
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> pos_dis(0, result.size() - 1);
        std::uniform_int_distribution<> pattern_dis(0, 15); // Limited range
        
        size_t pattern_amount = static_cast<size_t>((current_entropy - target_entropy) * result.size() * 0.1);
        
        for (size_t i = 0; i < pattern_amount && i < result.size(); ++i) {
            size_t pos = pos_dis(gen);
            result[pos] = pattern_dis(gen);
        }
    }
    
    return result;
}

std::vector<uint8_t> EntropyShaper::shape_lzw_entropy(const std::vector<uint8_t>& data, double target_entropy) {
    if (data.empty()) return data;
    
    std::vector<uint8_t> result = data;
    double current_entropy = calculate_shannon_entropy(data);
    
    if (std::abs(current_entropy - target_entropy) < 0.1) {
        return result;
    }
    
    if (current_entropy < target_entropy) {
        // For LZW, increase entropy by breaking repetitive patterns
        std::random_device rd;
        std::mt19937 gen(rd());
        
        // Find and modify repetitive sequences
        for (size_t i = 0; i < result.size() - 1; ++i) {
            if (i + 4 < result.size()) {
                // Check for 4-byte repetitions
                if (result[i] == result[i+1] && result[i+1] == result[i+2] && result[i+2] == result[i+3]) {
                    std::uniform_int_distribution<> dis(0, 255);
                    result[i+2] = dis(gen); // Break the pattern
                }
            }
        }
    } else {
        // Decrease entropy by creating LZW-friendly patterns
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> pattern_dis(32, 126); // Printable ASCII
        
        // Insert repeating patterns that LZW can compress well
        for (size_t i = 0; i < result.size() - 8; i += 16) {
            uint8_t pattern_byte = pattern_dis(gen);
            for (size_t j = 0; j < 4 && i + j < result.size(); ++j) {
                result[i + j] = pattern_byte;
            }
        }
    }
    
    return result;
}

std::vector<uint8_t> EntropyShaper::shape_ascii_entropy(const std::vector<uint8_t>& data, double target_entropy) {
    if (data.empty()) return data;
    
    std::vector<uint8_t> result = data;
    double current_entropy = calculate_shannon_entropy(data);
    
    if (std::abs(current_entropy - target_entropy) < 0.1) {
        return result;
    }
    
    // Focus on ASCII range (32-126) for text-like entropy
    std::random_device rd;
    std::mt19937 gen(rd());
    
    if (current_entropy < target_entropy) {
        // Increase entropy with varied ASCII characters
        std::uniform_int_distribution<> ascii_dis(32, 126);
        
        for (size_t i = 0; i < result.size(); ++i) {
            if (result[i] >= 32 && result[i] <= 126) {
                if (gen() % 10 == 0) { // 10% chance to modify
                    result[i] = ascii_dis(gen);
                }
            }
        }
    } else {
        // Decrease entropy with common ASCII patterns
        std::vector<uint8_t> common_chars = {' ', 'e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r'};
        std::uniform_int_distribution<> common_dis(0, common_chars.size() - 1);
        
        for (size_t i = 0; i < result.size(); ++i) {
            if (result[i] >= 32 && result[i] <= 126) {
                if (gen() % 5 == 0) { // 20% chance to modify
                    result[i] = common_chars[common_dis(gen)];
                }
            }
        }
    }
    
    return result;
}

void EntropyShaper::optimize_huffman_tables(std::vector<uint8_t>& compressed_data, const EntropyProfile& target) {
    // Huffman table optimization for deflate streams
    if (compressed_data.empty()) return;
    
    // Analyze current byte frequencies
    std::map<uint8_t, double> current_freq = analyze_byte_frequencies(compressed_data);
    
    // Calculate optimal Huffman codes based on target entropy
    std::vector<std::pair<uint8_t, double>> freq_pairs;
    for (const auto& entry : current_freq) {
        freq_pairs.push_back({entry.first, entry.second});
    }
    
    // Sort by frequency (most frequent first)
    std::sort(freq_pairs.begin(), freq_pairs.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    // Adjust frequencies to match target entropy characteristics
    double entropy_factor = target.average_entropy / calculate_shannon_entropy(compressed_data);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    
    for (size_t i = 0; i < compressed_data.size(); ++i) {
        uint8_t current_byte = compressed_data[i];
        
        // Find this byte in frequency table
        auto it = std::find_if(freq_pairs.begin(), freq_pairs.end(),
                              [current_byte](const auto& pair) { return pair.first == current_byte; });
        
        if (it != freq_pairs.end()) {
            size_t rank = std::distance(freq_pairs.begin(), it);
            
            // Adjust byte based on its frequency rank and entropy target
            if (entropy_factor > 1.0 && rank < freq_pairs.size() / 4) {
                // High entropy target - randomize frequent bytes occasionally
                std::uniform_int_distribution<> dis(0, 255);
                if (gen() % 100 < 5) { // 5% chance
                    compressed_data[i] = dis(gen);
                }
            } else if (entropy_factor < 1.0 && rank > freq_pairs.size() / 2) {
                // Low entropy target - replace rare bytes with common ones
                if (gen() % 100 < 10) { // 10% chance
                    compressed_data[i] = freq_pairs[0].first; // Most frequent byte
                }
            }
        }
    }
}

void EntropyShaper::adjust_lz_dictionary(std::vector<uint8_t>& compressed_data, const CompressionProfile& target) {
    // LZ dictionary adjustment for better compression patterns
    if (compressed_data.empty()) return;
    
    // Find repeating sequences that could be dictionary entries
    auto patterns = find_repeating_patterns(compressed_data, 3, 16);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    
    for (const auto& pattern : patterns) {
        if (patterns.size() > 10) break; // Limit processing
        
        double frequency = calculate_pattern_frequency(compressed_data, pattern);
        
        // Adjust pattern frequency based on target compression profile
        if (target.average_compression_ratio < 0.5) {
            // Target wants high compression - enhance patterns
            if (frequency > 0.01) { // Pattern appears frequently enough
                // Strengthen the pattern by ensuring consistency
                for (size_t i = 0; i <= compressed_data.size() - pattern.size(); ++i) {
                    if (std::equal(pattern.begin(), pattern.end(), compressed_data.begin() + i)) {
                        // Ensure pattern is exactly as expected (no variations)
                        std::copy(pattern.begin(), pattern.end(), compressed_data.begin() + i);
                    }
                }
            }
        } else {
            // Target wants lower compression - break patterns
            if (frequency > 0.005) {
                for (size_t i = 0; i <= compressed_data.size() - pattern.size(); ++i) {
                    if (std::equal(pattern.begin(), pattern.end(), compressed_data.begin() + i)) {
                        // Introduce variation to break the pattern
                        std::uniform_int_distribution<> dis(0, 255);
                        if (gen() % 4 == 0) { // 25% chance
                            compressed_data[i + pattern.size() / 2] = dis(gen);
                        }
                    }
                }
            }
        }
    }
}

// Advanced Statistical Manipulation Implementation
std::vector<uint8_t> EntropyShaper::adjust_statistical_properties(const std::vector<uint8_t>& data,
                                                                  const EntropyProfile& target) {
    if (data.empty()) return data;
    
    std::vector<uint8_t> result = data;
    
    // Adjust to match target entropy variance
    double current_variance = calculate_entropy_variance(calculate_sliding_entropy(data, 256));
    double target_variance = target.entropy_variance;
    
    if (std::abs(current_variance - target_variance) > 0.1) {
        std::random_device rd;
        std::mt19937 gen(rd());
        
        if (current_variance < target_variance) {
            // Increase variance by creating entropy hotspots
            std::uniform_int_distribution<> pos_dis(0, result.size() - 256);
            std::uniform_int_distribution<> byte_dis(0, 255);
            
            for (int hotspot = 0; hotspot < 5; ++hotspot) {
                size_t pos = pos_dis(gen);
                for (size_t i = 0; i < 64 && pos + i < result.size(); ++i) {
                    result[pos + i] = byte_dis(gen);
                }
            }
        } else {
            // Decrease variance by smoothing entropy distribution
            for (size_t i = 0; i < result.size() - 8; i += 8) {
                uint8_t avg = 0;
                for (size_t j = 0; j < 8 && i + j < result.size(); ++j) {
                    avg += result[i + j];
                }
                avg /= 8;
                
                for (size_t j = 0; j < 4 && i + j < result.size(); ++j) {
                    result[i + j] = avg;
                }
            }
        }
    }
    
    return result;
}

void EntropyShaper::match_chi_square_distribution(std::vector<uint8_t>& data, double target_chi_square) {
    if (data.empty()) return;
    
    // Calculate current chi-square statistic
    std::vector<size_t> observed(256, 0);
    for (uint8_t byte : data) {
        observed[byte]++;
    }
    
    double expected = static_cast<double>(data.size()) / 256.0;
    double current_chi_square = 0.0;
    
    for (size_t count : observed) {
        double diff = static_cast<double>(count) - expected;
        current_chi_square += (diff * diff) / expected;
    }
    
    if (std::abs(current_chi_square - target_chi_square) < 1.0) {
        return; // Close enough
    }
    
    std::random_device rd;
    std::mt19937 gen(rd());
    
    if (current_chi_square < target_chi_square) {
        // Increase chi-square by making distribution more uneven
        std::uniform_int_distribution<> byte_dis(0, 255);
        std::uniform_int_distribution<> pos_dis(0, data.size() - 1);
        
        // Concentrate some values
        uint8_t concentrate_value = byte_dis(gen);
        size_t modifications = static_cast<size_t>((target_chi_square - current_chi_square) * 0.1);
        
        for (size_t i = 0; i < modifications && i < data.size(); ++i) {
            data[pos_dis(gen)] = concentrate_value;
        }
    } else {
        // Decrease chi-square by making distribution more even
        std::uniform_int_distribution<> byte_dis(0, 255);
        
        // Randomize to make more uniform
        size_t modifications = static_cast<size_t>((current_chi_square - target_chi_square) * 0.1);
        
        for (size_t i = 0; i < modifications && i < data.size(); ++i) {
            data[i] = byte_dis(gen);
        }
    }
}

void EntropyShaper::adjust_autocorrelation(std::vector<uint8_t>& data, const std::vector<double>& target_correlation) {
    if (data.empty() || target_correlation.empty()) return;
    
    size_t max_lag = std::min(target_correlation.size(), data.size() / 2);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> byte_dis(0, 255);
    
    // Adjust autocorrelation by modifying byte relationships
    for (size_t lag = 1; lag < max_lag; ++lag) {
        double target_corr = target_correlation[lag];
        
        if (target_corr > 0.5) {
            // High correlation - make bytes similar to previous ones
            for (size_t i = lag; i < data.size(); ++i) {
                if (gen() % 10 < 3) { // 30% chance
                    data[i] = data[i - lag]; // Copy from lag positions back
                }
            }
        } else if (target_corr < -0.5) {
            // Negative correlation - make bytes opposite
            for (size_t i = lag; i < data.size(); ++i) {
                if (gen() % 10 < 3) { // 30% chance
                    data[i] = 255 - data[i - lag]; // Inverse of lag positions back
                }
            }
        } else {
            // Low correlation - randomize
            for (size_t i = lag; i < data.size(); ++i) {
                if (gen() % 20 == 0) { // 5% chance
                    data[i] = byte_dis(gen);
                }
            }
        }
    }
}

void EntropyShaper::balance_bit_distribution(std::vector<uint8_t>& data) {
    if (data.empty()) return;
    
    // Count bits in each position
    std::vector<size_t> bit_counts(8, 0);
    
    for (uint8_t byte : data) {
        for (int bit = 0; bit < 8; ++bit) {
            if (byte & (1 << bit)) {
                bit_counts[bit]++;
            }
        }
    }
    
    size_t target_count = data.size() / 2; // 50% distribution
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> pos_dis(0, data.size() - 1);
    
    // Adjust each bit position
    for (int bit = 0; bit < 8; ++bit) {
        if (bit_counts[bit] < target_count * 0.9) {
            // Too few 1s in this position - set some bits
            size_t to_set = target_count - bit_counts[bit];
            for (size_t i = 0; i < to_set && i < data.size(); ++i) {
                size_t pos = pos_dis(gen);
                data[pos] |= (1 << bit);
            }
        } else if (bit_counts[bit] > target_count * 1.1) {
            // Too many 1s in this position - clear some bits
            size_t to_clear = bit_counts[bit] - target_count;
            for (size_t i = 0; i < to_clear && i < data.size(); ++i) {
                size_t pos = pos_dis(gen);
                data[pos] &= ~(1 << bit);
            }
        }
    }
}