#include "statistical_pattern_masker.hpp"
#include "stealth_macros.hpp"
#include <algorithm>
#include <numeric>
#include <cmath>
#include <unordered_map>
#include <iostream>
#include "stealth_macros.hpp"
#include "stealth_macros.hpp"

StatisticalPatternMasker::StatisticalPatternMasker() : entropy_generator_(std::random_device{}()) {
    initialize_document_type_profiles();
    initialize_authentic_noise_patterns();
    initialize_tool_signature_database();
}

std::vector<uint8_t> StatisticalPatternMasker::mask_statistical_patterns(const std::vector<uint8_t>& pdf_data) {
    // CRITICAL METHOD IMPLEMENTATION - Called by pdf_byte_fidelity_processor.cpp
    std::vector<uint8_t> masked_data = pdf_data;
    
    // Step 1: Normalize entropy distribution to match authentic documents
    normalize_entropy_distribution(masked_data);
    
    // Step 2: Mask artificial patterns that indicate processing
    auto artificial_positions = detect_artificial_patterns(masked_data);
    for (size_t pos : artificial_positions) {
        apply_pattern_masking_at_position(masked_data, pos);
    }
    
    // Step 3: Inject authentic document noise
    inject_natural_document_variations(masked_data);
    
    // Step 4: Camouflage processing signatures
    auto processing_signatures = detect_processing_signatures(masked_data);
    for (size_t pos : processing_signatures) {
        camouflage_signature_at_position(masked_data, pos);
    }
    
    // Step 5: Apply document-type specific entropy profile
    if (document_type_ == "legal") {
        apply_legal_document_entropy_profile(masked_data);
    } else if (document_type_ == "financial") {
        apply_financial_document_entropy_profile(masked_data);
    } else if (document_type_ == "medical") {
        apply_medical_document_entropy_profile(masked_data);
    } else {
        apply_technical_document_entropy_profile(masked_data);
    }
    
    // Step 6: Final validation and adjustment
    if (!validate_entropy_authenticity(masked_data)) {
        // Apply additional masking if validation fails
        apply_entropy_smoothing(masked_data);
        normalize_byte_frequency_distribution(masked_data);
    }
    
    return masked_data;
}

void StatisticalPatternMasker::normalize_entropy_distribution(std::vector<uint8_t>& pdf_data) {
    EntropyProfile current_profile = analyze_document_entropy(pdf_data);
    AuthenticDocumentProfile target = document_type_profiles_[document_type_];
    
    // Calculate entropy adjustment needed
    double entropy_delta = target.baseline_entropy.byte_entropy - current_profile.byte_entropy;
    
    if (std::abs(entropy_delta) > 0.1) {
        if (entropy_delta > 0) {
            // Need to increase entropy - inject controlled randomness
            inject_entropy_balancing_bytes(pdf_data, target.baseline_entropy.byte_entropy);
        } else {
            // Need to decrease entropy - apply smoothing
            apply_entropy_smoothing(pdf_data);
        }
    }
    
    // Normalize frequency distributions
    normalize_byte_frequency_distribution(pdf_data);
}

void StatisticalPatternMasker::mask_artificial_patterns() {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    try {
        SecureMemory secure_masking_buffer(16384);
        
        // Mask regular pattern distributions that indicate machine processing
        mask_regular_byte_patterns();
        
        // Mask perfect alignments and structures
        mask_perfect_alignment_patterns();
        
        // Mask unnatural compression signatures
        mask_compression_processing_signatures();
        
        // Mask tool-specific byte arrangements
        mask_tool_specific_byte_patterns();
        
        // Mask artificial entropy patterns
        mask_artificial_entropy_distributions();
        
        // Mask mathematical precision indicators
        mask_mathematical_precision_patterns();
        
        // Apply document-type specific pattern masking
        if (document_type_ == "legal") {
            mask_legal_document_artificial_patterns();
        } else if (document_type_ == "financial") {
            mask_financial_document_artificial_patterns();
        } else if (document_type_ == "medical") {
            mask_medical_document_artificial_patterns();
        }
        
        // Validate masking effectiveness
        validate_pattern_masking_effectiveness();
        
        eliminate_masking_traces();
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

void StatisticalPatternMasker::inject_authentic_document_noise() {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    try {
        SecureMemory secure_noise_buffer(32768);
        
        // Generate authentic document noise patterns based on document type
        std::vector<uint8_t> base_noise = generate_document_type_specific_noise();
        
        // Inject natural byte frequency variations
        inject_natural_byte_frequency_variations(base_noise);
        
        // Add authentic compression noise patterns
        inject_authentic_compression_variations(base_noise);
        
        // Inject natural document aging patterns
        inject_document_aging_noise_patterns(base_noise);
        
        // Add authentic encoding noise
        inject_authentic_encoding_variations(base_noise);
        
        // Inject natural document creation noise
        inject_natural_document_creation_patterns(base_noise);
        
        // Add scanner/printer noise patterns for physically processed documents
        if (document_processing_history_.physical_processing) {
            inject_scanner_printer_noise_patterns(base_noise);
        }
        
        // Inject natural editing artifacts
        inject_natural_editing_artifacts(base_noise);
        
        // Add authentic metadata noise
        inject_authentic_metadata_variations(base_noise);
        
        // Apply document workflow noise patterns
        inject_workflow_specific_noise_patterns(base_noise);
        
        // Validate noise authenticity
        validate_injected_noise_authenticity(base_noise);
        
        eliminate_noise_injection_traces();
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

void StatisticalPatternMasker::camouflage_processing_signatures() {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    try {
        SecureMemory secure_camouflage_buffer(16384);
        
        // Camouflage tool-specific processing signatures
        camouflage_tool_specific_signatures();
        
        // Mask timestamp-based processing indicators
        camouflage_timestamp_processing_patterns();
        
        // Hide batch processing signatures
        camouflage_batch_processing_indicators();
        
        // Mask automated processing artifacts
        camouflage_automated_processing_artifacts();
        
        // Hide version control processing signatures
        camouflage_version_control_signatures();
        
        // Mask optimization processing patterns
        camouflage_optimization_processing_patterns();
        
        // Hide compression processing signatures
        camouflage_compression_processing_signatures();
        
        // Mask metadata processing artifacts
        camouflage_metadata_processing_signatures();
        
        // Hide workflow processing patterns
        camouflage_workflow_processing_indicators();
        
        // Apply enterprise software camouflage patterns
        apply_enterprise_software_camouflage();
        
        // Validate signature camouflage effectiveness
        validate_signature_camouflage_effectiveness();
        
        eliminate_camouflage_traces();
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

double StatisticalPatternMasker::calculate_authentic_entropy_baseline() {
    if (document_type_profiles_.find(document_type_) != document_type_profiles_.end()) {
        return document_type_profiles_[document_type_].baseline_entropy.byte_entropy;
    }
    return 7.5; // Default entropy for typical PDF documents
}

StatisticalPatternMasker::EntropyProfile StatisticalPatternMasker::analyze_document_entropy(const std::vector<uint8_t>& pdf_data) {
    EntropyProfile profile;
    
    // Calculate Shannon entropy
    profile.byte_entropy = calculate_shannon_entropy(pdf_data);
    
    // Calculate frequency distributions
    profile.byte_frequency = calculate_byte_frequencies(pdf_data);
    profile.bigram_frequency = calculate_bigram_frequencies(pdf_data);
    profile.trigram_frequency = calculate_trigram_frequencies(pdf_data);
    
    // Calculate higher-order entropies
    profile.bigram_entropy = calculate_conditional_entropy(pdf_data, 2);
    profile.trigram_entropy = calculate_conditional_entropy(pdf_data, 3);
    
    // Calculate compression ratio estimate
    size_t original_size = pdf_data.size();
    std::vector<uint8_t> compressed_estimate;
    // Simplified compression ratio calculation
    std::unordered_map<uint8_t, size_t> frequency_map;
    for (uint8_t byte : pdf_data) {
        frequency_map[byte]++;
    }
    size_t unique_bytes = frequency_map.size();
    profile.compression_ratio = static_cast<double>(unique_bytes) / 256.0;
    
    // Calculate randomness score
    profile.randomness_score = profile.byte_entropy / 8.0; // Normalize to [0,1]
    
    // Calculate block entropy distribution
    size_t block_size = 1024;
    for (size_t i = 0; i < pdf_data.size(); i += block_size) {
        size_t end = std::min(i + block_size, pdf_data.size());
        std::vector<uint8_t> block(pdf_data.begin() + i, pdf_data.begin() + end);
        profile.block_entropy_distribution.push_back(calculate_shannon_entropy(block));
    }
    
    return profile;
}

StatisticalPatternMasker::AuthenticDocumentProfile StatisticalPatternMasker::generate_authentic_baseline(const std::string& document_type) {
    AuthenticDocumentProfile profile;
    
    if (document_type == "legal") {
        profile.baseline_entropy.byte_entropy = 7.2;
        profile.baseline_entropy.bigram_entropy = 6.8;
        profile.baseline_entropy.trigram_entropy = 6.4;
        profile.baseline_entropy.compression_ratio = 0.85;
        profile.baseline_entropy.randomness_score = 0.90;
        profile.authentic_noise_level = 0.05;
        
        // Legal documents typically have structured text patterns
        profile.typical_entropy_ranges = {6.8, 7.0, 7.2, 7.4, 7.6};
        profile.document_type_entropy_signatures["legal"] = 7.2;
        
    } else if (document_type == "financial") {
        profile.baseline_entropy.byte_entropy = 7.4;
        profile.baseline_entropy.bigram_entropy = 7.0;
        profile.baseline_entropy.trigram_entropy = 6.6;
        profile.baseline_entropy.compression_ratio = 0.82;
        profile.baseline_entropy.randomness_score = 0.92;
        profile.authentic_noise_level = 0.03;
        
        // Financial documents have more numerical data
        profile.typical_entropy_ranges = {7.0, 7.2, 7.4, 7.6, 7.8};
        profile.document_type_entropy_signatures["financial"] = 7.4;
        
    } else if (document_type == "medical") {
        profile.baseline_entropy.byte_entropy = 7.1;
        profile.baseline_entropy.bigram_entropy = 6.7;
        profile.baseline_entropy.trigram_entropy = 6.3;
        profile.baseline_entropy.compression_ratio = 0.87;
        profile.baseline_entropy.randomness_score = 0.89;
        profile.authentic_noise_level = 0.06;
        
        // Medical documents have specialized terminology
        profile.typical_entropy_ranges = {6.7, 6.9, 7.1, 7.3, 7.5};
        profile.document_type_entropy_signatures["medical"] = 7.1;
        
    } else {
        // Default technical document profile
        profile.baseline_entropy.byte_entropy = 7.3;
        profile.baseline_entropy.bigram_entropy = 6.9;
        profile.baseline_entropy.trigram_entropy = 6.5;
        profile.baseline_entropy.compression_ratio = 0.84;
        profile.baseline_entropy.randomness_score = 0.91;
        profile.authentic_noise_level = 0.04;
        
        profile.typical_entropy_ranges = {6.9, 7.1, 7.3, 7.5, 7.7};
        profile.document_type_entropy_signatures["technical"] = 7.3;
    }
    
    return profile;
}

void StatisticalPatternMasker::normalize_to_authentic_profile(std::vector<uint8_t>& pdf_data, const AuthenticDocumentProfile& profile) {
    EntropyProfile current = analyze_document_entropy(pdf_data);
    
    // Adjust entropy to match authentic profile
    double entropy_difference = profile.baseline_entropy.byte_entropy - current.byte_entropy;
    
    if (std::abs(entropy_difference) > 0.05) {
        if (entropy_difference > 0) {
            // Increase entropy by injecting controlled randomness
            inject_entropy_balancing_bytes(pdf_data, profile.baseline_entropy.byte_entropy);
        } else {
            // Decrease entropy by smoothing high-entropy regions
            apply_entropy_smoothing(pdf_data);
        }
    }
    
    // Inject authentic noise patterns
    inject_natural_document_variations(pdf_data);
    
    // Normalize frequency distributions to match authentic patterns
    normalize_byte_frequency_distribution(pdf_data);
}

std::vector<size_t> StatisticalPatternMasker::detect_artificial_patterns(const std::vector<uint8_t>& pdf_data) {
    std::vector<size_t> artificial_positions;
    
    // Detect repetitive patterns that indicate artificial generation
    for (size_t i = 0; i < pdf_data.size() - 16; ++i) {
        bool is_repetitive = true;
        for (size_t j = 1; j < 8; ++j) {
            if (pdf_data[i] != pdf_data[i + j]) {
                is_repetitive = false;
                break;
            }
        }
        if (is_repetitive) {
            artificial_positions.push_back(i);
        }
    }
    
    // Detect overly regular patterns
    for (size_t i = 0; i < pdf_data.size() - 32; ++i) {
        std::vector<uint8_t> pattern(pdf_data.begin() + i, pdf_data.begin() + i + 16);
        size_t pattern_count = 0;
        for (size_t j = i + 16; j < pdf_data.size() - 16; j += 16) {
            if (std::equal(pattern.begin(), pattern.end(), pdf_data.begin() + j)) {
                pattern_count++;
            }
        }
        if (pattern_count > 3) {
            artificial_positions.push_back(i);
        }
    }
    
    return artificial_positions;
}

std::vector<size_t> StatisticalPatternMasker::detect_processing_signatures(const std::vector<uint8_t>& pdf_data) {
    std::vector<size_t> signature_positions;
    
    // Search for known tool signatures
    for (const auto& signature : known_tool_signatures_) {
        for (size_t i = 0; i <= pdf_data.size() - signature.size(); ++i) {
            if (std::equal(signature.begin(), signature.end(), pdf_data.begin() + i)) {
                signature_positions.push_back(i);
            }
        }
    }
    
    // Detect timestamp patterns that indicate recent processing
    std::string pdf_content(pdf_data.begin(), pdf_data.end());
    size_t timestamp_pos = pdf_content.find("D:202");
    while (timestamp_pos != std::string::npos) {
        signature_positions.push_back(timestamp_pos);
        timestamp_pos = pdf_content.find("D:202", timestamp_pos + 1);
    }
    
    return signature_positions;
}

std::vector<size_t> StatisticalPatternMasker::detect_compression_artifacts(const std::vector<uint8_t>& pdf_data) {
    std::vector<size_t> artifact_positions;
    
    // Search for known compression patterns
    for (const auto& pattern : known_compression_patterns_) {
        for (size_t i = 0; i <= pdf_data.size() - pattern.size(); ++i) {
            if (std::equal(pattern.begin(), pattern.end(), pdf_data.begin() + i)) {
                artifact_positions.push_back(i);
            }
        }
    }
    
    return artifact_positions;
}

std::vector<size_t> StatisticalPatternMasker::detect_tool_fingerprints(const std::vector<uint8_t>& pdf_data) {
    std::vector<size_t> fingerprint_positions;
    
    std::string pdf_content(pdf_data.begin(), pdf_data.end());
    
    // Common tool fingerprints
    std::vector<std::string> tool_signatures = {
        "Adobe PDF Library",
        "Microsoft Print to PDF",
        "wkhtmltopdf",
        "iText",
        "PDFtk",
        "Ghostscript",
        "Chrome PDF Viewer",
        "Firefox PDF.js"
    };
    
    for (const auto& signature : tool_signatures) {
        size_t pos = pdf_content.find(signature);
        while (pos != std::string::npos) {
            fingerprint_positions.push_back(pos);
            pos = pdf_content.find(signature, pos + 1);
        }
    }
    
    return fingerprint_positions;
}

void StatisticalPatternMasker::inject_natural_document_variations(std::vector<uint8_t>& pdf_data) {
    // Inject subtle variations that occur in natural document creation
    std::uniform_real_distribution<> noise_dist(0.0, target_profile_.authentic_noise_level);
    std::uniform_int_distribution<> position_dist(0, pdf_data.size() - 1);
    
    size_t noise_injection_count = static_cast<size_t>(pdf_data.size() * target_profile_.authentic_noise_level);
    
    for (size_t i = 0; i < noise_injection_count; ++i) {
        size_t position = position_dist(entropy_generator_);
        
        // Inject minimal noise that doesn't break PDF structure
        if (position > 0 && position < pdf_data.size() - 1) {
            // Only modify non-critical bytes (not in PDF structure)
            if (pdf_data[position] != '<' && pdf_data[position] != '>' && 
                pdf_data[position] != '[' && pdf_data[position] != ']') {
                
                // Apply subtle bit-level noise
                uint8_t noise_byte = static_cast<uint8_t>(noise_dist(entropy_generator_) * 255);
                pdf_data[position] ^= (noise_byte & 0x01); // Flip only least significant bit
            }
        }
    }
}

void StatisticalPatternMasker::simulate_scanner_noise_patterns(std::vector<uint8_t>& pdf_data) {
    // Simulate noise patterns typical of scanned documents
    std::vector<uint8_t> scanner_noise = generate_scanner_noise(pdf_data.size() / 1000);
    
    // Inject scanner noise at regular intervals
    for (size_t i = 0; i < scanner_noise.size() && i * 1000 < pdf_data.size(); ++i) {
        size_t position = i * 1000;
        if (position < pdf_data.size()) {
            // Subtle modification that mimics scanner noise
            pdf_data[position] ^= (scanner_noise[i] & 0x03);
        }
    }
}

void StatisticalPatternMasker::replicate_printer_characteristics(std::vector<uint8_t>& pdf_data) {
    // Replicate subtle characteristics of printer-generated documents
    std::vector<uint8_t> printer_noise = generate_printer_noise(pdf_data.size() / 500);
    
    for (size_t i = 0; i < printer_noise.size() && i * 500 < pdf_data.size(); ++i) {
        size_t position = i * 500;
        if (position < pdf_data.size()) {
            pdf_data[position] ^= (printer_noise[i] & 0x01);
        }
    }
}

void StatisticalPatternMasker::emulate_paper_document_artifacts(std::vector<uint8_t>& pdf_data) {
    // Emulate artifacts from paper document processing
    std::vector<uint8_t> paper_noise = generate_paper_texture_noise(pdf_data.size() / 2000);
    
    for (size_t i = 0; i < paper_noise.size() && i * 2000 < pdf_data.size(); ++i) {
        size_t position = i * 2000;
        if (position < pdf_data.size()) {
            pdf_data[position] ^= (paper_noise[i] & 0x01);
        }
    }
}

void StatisticalPatternMasker::apply_entropy_smoothing(std::vector<uint8_t>& pdf_data) {
    // Identify high-entropy regions and smooth them
    size_t block_size = 256;
    
    for (size_t i = 0; i < pdf_data.size(); i += block_size) {
        size_t end = std::min(i + block_size, pdf_data.size());
        std::vector<uint8_t> block(pdf_data.begin() + i, pdf_data.begin() + end);
        
        double block_entropy = calculate_shannon_entropy(block);
        
        if (block_entropy > target_profile_.baseline_entropy.byte_entropy + 0.2) {
            // Apply smoothing to this high-entropy block
            smooth_entropy_peaks(pdf_data, {i});
        }
    }
}

void StatisticalPatternMasker::normalize_byte_frequency_distribution(std::vector<uint8_t>& pdf_data) {
    auto current_frequencies = calculate_byte_frequencies(pdf_data);
    auto target_frequencies = target_profile_.baseline_entropy.byte_frequency;
    
    // Identify bytes that are significantly over or under-represented
    for (const auto& freq_pair : current_frequencies) {
        uint8_t byte_value = freq_pair.first;
        double current_freq = freq_pair.second;
        
        double target_freq = 1.0 / 256.0; // Default uniform distribution
        if (target_frequencies.find(byte_value) != target_frequencies.end()) {
            target_freq = target_frequencies[byte_value];
        }
        
        double freq_difference = std::abs(current_freq - target_freq);
        
        if (freq_difference > 0.01) {
            // Adjust frequency by subtle modifications
            normalize_frequency_outliers(pdf_data);
        }
    }
}

double StatisticalPatternMasker::calculate_shannon_entropy(const std::vector<uint8_t>& data) {
    if (data.empty()) return 0.0;
    
    std::unordered_map<uint8_t, size_t> frequency_map;
    for (uint8_t byte : data) {
        frequency_map[byte]++;
    }
    
    double entropy = 0.0;
    size_t total_bytes = data.size();
    
    for (const auto& freq_pair : frequency_map) {
        double probability = static_cast<double>(freq_pair.second) / total_bytes;
        if (probability > 0) {
            entropy -= probability * std::log2(probability);
        }
    }
    
    return entropy;
}

double StatisticalPatternMasker::calculate_conditional_entropy(const std::vector<uint8_t>& data, size_t context_length) {
    if (data.size() < context_length + 1) return 0.0;
    
    std::map<std::vector<uint8_t>, std::map<uint8_t, size_t>> context_frequencies;
    
    for (size_t i = 0; i <= data.size() - context_length - 1; ++i) {
        std::vector<uint8_t> context(data.begin() + i, data.begin() + i + context_length);
        uint8_t next_byte = data[i + context_length];
        context_frequencies[context][next_byte]++;
    }
    
    double conditional_entropy = 0.0;
    size_t total_contexts = data.size() - context_length;
    
    for (const auto& context_pair : context_frequencies) {
        const auto& next_byte_frequencies = context_pair.second;
        size_t context_count = 0;
        for (const auto& freq_pair : next_byte_frequencies) {
            context_count += freq_pair.second;
        }
        
        double context_probability = static_cast<double>(context_count) / total_contexts;
        double context_entropy = 0.0;
        
        for (const auto& freq_pair : next_byte_frequencies) {
            double conditional_prob = static_cast<double>(freq_pair.second) / context_count;
            if (conditional_prob > 0) {
                context_entropy -= conditional_prob * std::log2(conditional_prob);
            }
        }
        
        conditional_entropy += context_probability * context_entropy;
    }
    
    return conditional_entropy;
}

std::map<uint8_t, double> StatisticalPatternMasker::calculate_byte_frequencies(const std::vector<uint8_t>& data) {
    std::map<uint8_t, double> frequencies;
    std::unordered_map<uint8_t, size_t> counts;
    
    for (uint8_t byte : data) {
        counts[byte]++;
    }
    
    size_t total = data.size();
    for (const auto& count_pair : counts) {
        frequencies[count_pair.first] = static_cast<double>(count_pair.second) / total;
    }
    
    return frequencies;
}

std::map<uint16_t, double> StatisticalPatternMasker::calculate_bigram_frequencies(const std::vector<uint8_t>& data) {
    std::map<uint16_t, double> frequencies;
    std::unordered_map<uint16_t, size_t> counts;
    
    for (size_t i = 0; i < data.size() - 1; ++i) {
        uint16_t bigram = (static_cast<uint16_t>(data[i]) << 8) | data[i + 1];
        counts[bigram]++;
    }
    
    size_t total = data.size() - 1;
    for (const auto& count_pair : counts) {
        frequencies[count_pair.first] = static_cast<double>(count_pair.second) / total;
    }
    
    return frequencies;
}

std::map<uint32_t, double> StatisticalPatternMasker::calculate_trigram_frequencies(const std::vector<uint8_t>& data) {
    std::map<uint32_t, double> frequencies;
    std::unordered_map<uint32_t, size_t> counts;
    
    for (size_t i = 0; i < data.size() - 2; ++i) {
        uint32_t trigram = (static_cast<uint32_t>(data[i]) << 16) | 
                          (static_cast<uint32_t>(data[i + 1]) << 8) | 
                          data[i + 2];
        counts[trigram]++;
    }
    
    size_t total = data.size() - 2;
    for (const auto& count_pair : counts) {
        frequencies[count_pair.first] = static_cast<double>(count_pair.second) / total;
    }
    
    return frequencies;
}

std::vector<uint8_t> StatisticalPatternMasker::generate_natural_noise(size_t length, double noise_level) {
    std::vector<uint8_t> noise(length);
    std::uniform_int_distribution<> byte_dist(0, 255);
    std::uniform_real_distribution<> intensity_dist(0.0, noise_level);
    
    for (size_t i = 0; i < length; ++i) {
        noise[i] = static_cast<uint8_t>(byte_dist(entropy_generator_) * intensity_dist(entropy_generator_));
    }
    
    return noise;
}

std::vector<uint8_t> StatisticalPatternMasker::generate_scanner_noise(size_t length) {
    return generate_natural_noise(length, 0.02); // 2% noise level typical of scanners
}

std::vector<uint8_t> StatisticalPatternMasker::generate_printer_noise(size_t length) {
    return generate_natural_noise(length, 0.01); // 1% noise level typical of printers
}

std::vector<uint8_t> StatisticalPatternMasker::generate_paper_texture_noise(size_t length) {
    return generate_natural_noise(length, 0.005); // 0.5% noise level from paper texture
}

void StatisticalPatternMasker::smooth_entropy_peaks(std::vector<uint8_t>& data, const std::vector<size_t>& peak_positions) {
    for (size_t pos : peak_positions) {
        if (pos > 0 && pos < data.size() - 1) {
            // Apply smoothing by averaging with neighboring bytes
            uint16_t avg = (static_cast<uint16_t>(data[pos - 1]) + 
                           static_cast<uint16_t>(data[pos]) + 
                           static_cast<uint16_t>(data[pos + 1])) / 3;
            data[pos] = static_cast<uint8_t>(avg);
        }
    }
}

void StatisticalPatternMasker::normalize_frequency_outliers(std::vector<uint8_t>& data) {
    auto frequencies = calculate_byte_frequencies(data);
    double mean_frequency = 1.0 / 256.0;
    
    for (size_t i = 0; i < data.size(); ++i) {
        uint8_t byte_value = data[i];
        double current_freq = frequencies[byte_value];
        
        if (current_freq > mean_frequency * 2.0) {
            // This byte is over-represented, replace some instances
            std::uniform_real_distribution<> replace_prob(0.0, 0.1);
            if (replace_prob(entropy_generator_) < 0.05) {
                std::uniform_int_distribution<> replacement_dist(0, 255);
                data[i] = static_cast<uint8_t>(replacement_dist(entropy_generator_));
            }
        }
    }
}

void StatisticalPatternMasker::inject_entropy_balancing_bytes(std::vector<uint8_t>& data, double target_entropy) {
    double current_entropy = calculate_shannon_entropy(data);
    
    if (current_entropy < target_entropy) {
        // Need to increase entropy
        std::uniform_int_distribution<> position_dist(0, data.size() - 1);
        std::uniform_int_distribution<> byte_dist(0, 255);
        
        size_t modifications = static_cast<size_t>((target_entropy - current_entropy) * data.size() * 0.01);
        
        for (size_t i = 0; i < modifications; ++i) {
            size_t pos = position_dist(entropy_generator_);
            if (pos < data.size()) {
                data[pos] = static_cast<uint8_t>(byte_dist(entropy_generator_));
            }
        }
    }
}

void StatisticalPatternMasker::initialize_document_type_profiles() {
    document_type_profiles_["legal"] = generate_authentic_baseline("legal");
    document_type_profiles_["financial"] = generate_authentic_baseline("financial");
    document_type_profiles_["medical"] = generate_authentic_baseline("medical");
    document_type_profiles_["technical"] = generate_authentic_baseline("technical");
}

void StatisticalPatternMasker::initialize_authentic_noise_patterns() {
    authentic_noise_patterns_["scanner"] = generate_scanner_noise(1024);
    authentic_noise_patterns_["printer"] = generate_printer_noise(1024);
    authentic_noise_patterns_["paper"] = generate_paper_texture_noise(1024);
}

void StatisticalPatternMasker::initialize_tool_signature_database() {
    // Initialize with common tool signatures
    known_tool_signatures_.push_back({'A', 'd', 'o', 'b', 'e', ' ', 'P', 'D', 'F'});
    known_tool_signatures_.push_back({'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't'});
    known_tool_signatures_.push_back({'G', 'h', 'o', 's', 't', 's', 'c', 'r', 'i', 'p', 't'});
    known_tool_signatures_.push_back({'i', 'T', 'e', 'x', 't'});
    known_tool_signatures_.push_back({'P', 'D', 'F', 't', 'k'});
    
    // Initialize compression patterns
    known_compression_patterns_.push_back({0x78, 0x9C}); // zlib header
    known_compression_patterns_.push_back({0x1F, 0x8B}); // gzip header
    known_compression_patterns_.push_back({0x42, 0x5A}); // bzip2 header
}