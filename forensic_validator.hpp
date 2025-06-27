// Adding missing function declarations to ForensicValidator class in forensic_validator.hpp

#pragma once
#include <vector>
#include <string>
#include <map>
#include <cstdint>
#include <regex>
#include <chrono>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <mutex>

struct ValidationResult {
    bool passed = false;
    double confidence_score = 0.0;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
    std::map<std::string, double> metrics;
    std::string detailed_report;
    
    // Core validation metrics
    double structural_similarity = 0.0;
    double entropy_similarity = 0.0;
    double metadata_similarity = 0.0;
    double compression_similarity = 0.0;
    double timing_similarity = 0.0;
    
    // Forensic analysis results
    bool passes_pdfid_analysis = false;
    bool passes_parser_analysis = false;
    bool passes_preflight_analysis = false;
    bool passes_peepdf_analysis = false;
    bool passes_virustotal_analysis = false;
    bool passes_hybrid_analysis = false;
    
    // Security validation
    bool has_suspicious_patterns = false;
    bool has_malformed_structures = false;
    bool has_encryption_bypass = false;
    bool has_javascript_exploits = false;
    bool has_steganographic_content = false;
    
    // Performance metrics
    std::chrono::milliseconds processing_time = std::chrono::milliseconds(0);
    size_t memory_usage_bytes = 0;
    size_t operations_performed = 0;
    
    // Statistical analysis
    double chi_square_statistic = 0.0;
    double kolmogorov_complexity = 0.0;
    std::vector<double> autocorrelation_coefficients;
    std::map<std::string, double> frequency_analysis;
    
    ValidationResult() = default;
    
    // Helper methods
    void add_warning(const std::string& warning) {
        warnings.push_back(warning);
    }
    
    void add_error(const std::string& error) {
        errors.push_back(error);
        passed = false;
    }
    
    void set_metric(const std::string& name, double value) {
        metrics[name] = value;
    }
    
    double get_overall_score() const {
        if (!passed) return 0.0;
        
        double score = confidence_score * 0.4 +
                      structural_similarity * 0.2 +
                      entropy_similarity * 0.15 +
                      metadata_similarity * 0.15 +
                      compression_similarity * 0.1;
        
        return std::min(1.0, std::max(0.0, score));
    }
};

struct ForensicFingerprint {
    // Core document identification
    std::string document_id;
    std::string creation_signature;
    std::string producer_signature;
    std::string creator_application;
    std::string version;
    
    // Structural fingerprinting
    std::vector<uint8_t> structure_hash;
    std::string structural_hash;
    std::vector<uint8_t> object_layout_hash;
    std::vector<size_t> object_positions;
    std::map<int, size_t> object_size_map;
    int object_count = 0;
    
    // Entropy and statistical analysis
    std::vector<uint8_t> entropy_profile;
    double entropy_score = 0.0;
    std::vector<double> block_entropies;
    double conditional_entropy = 0.0;
    std::vector<double> mutual_information;
    
    // Compression analysis
    std::string compression_signature;
    std::map<std::string, int> compression_types;
    std::vector<double> compression_ratios;
    std::string compression_pattern_hash;
    
    // Timing analysis
    double timing_signature = 0.0;
    std::chrono::system_clock::time_point creation_time;
    std::chrono::system_clock::time_point modification_time;
    std::vector<double> object_creation_intervals;
    bool has_batch_processing_artifacts = false;
    
    // Metadata fingerprinting
    std::map<std::string, std::string> metadata_hash;
    std::map<std::string, std::string> extended_metadata;
    std::vector<uint8_t> metadata_structure_hash;
    
    // Statistical markers
    std::map<std::string, double> statistical_markers;
    double chi_square_statistic = 0.0;
    double kolmogorov_complexity_estimate = 0.0;
    std::vector<double> autocorrelation_coefficients;
    std::map<uint8_t, double> byte_frequency_distribution;
    
    // Security and forensic markers
    std::vector<std::string> suspicious_patterns;
    std::map<std::string, bool> forensic_tool_signatures;
    std::vector<std::string> steganographic_indicators;
    bool has_encryption_artifacts = false;
    bool has_javascript_content = false;
    
    // Advanced fingerprinting
    std::vector<uint8_t> font_fingerprint;
    std::vector<uint8_t> image_fingerprint;
    std::vector<uint8_t> graphics_state_fingerprint;
    std::string rendering_intent_signature;
    
    // Quality metrics
    double fingerprint_confidence = 0.0;
    std::chrono::milliseconds extraction_time = std::chrono::milliseconds(0);
    size_t fingerprint_size_bytes = 0;
    
    ForensicFingerprint() = default;
    
    // Helper methods
    bool is_valid() const {
        return !document_id.empty() && 
               !structure_hash.empty() && 
               entropy_score > 0.0 &&
               object_count > 0;
    }
    
    double calculate_similarity(const ForensicFingerprint& other) const {
        if (!is_valid() || !other.is_valid()) return 0.0;
        
        double structural_sim = (structural_hash == other.structural_hash) ? 1.0 : 0.0;
        double entropy_sim = 1.0 - std::abs(entropy_score - other.entropy_score);
        double timing_sim = 1.0 - std::abs(timing_signature - other.timing_signature) / 
                           std::max(timing_signature, other.timing_signature);
        double compression_sim = (compression_signature == other.compression_signature) ? 1.0 : 0.0;
        
        return (structural_sim * 0.3 + entropy_sim * 0.25 + 
                timing_sim * 0.25 + compression_sim * 0.2);
    }
    
    std::string to_string() const {
        std::stringstream ss;
        ss << "ForensicFingerprint{" 
           << "id=" << document_id 
           << ", version=" << version
           << ", objects=" << object_count
           << ", entropy=" << entropy_score
           << ", confidence=" << fingerprint_confidence
           << "}";
        return ss.str();
    }
};

class ForensicValidator {
public:
    ForensicValidator();
    ~ForensicValidator();

    // Core validation functions
    bool validate(const std::vector<uint8_t>& source_pdf, const std::vector<uint8_t>& cloned_pdf);
    ValidationResult detailed_validate(const std::vector<uint8_t>& source_pdf, 
                                     const std::vector<uint8_t>& cloned_pdf);
    
    // Comprehensive PDF analysis
    ValidationResult analyze_pdf_security(const std::vector<uint8_t>& pdf_data);
    ValidationResult validate_pdf_integrity(const std::vector<uint8_t>& pdf_data);
    ValidationResult detect_manipulation_attempts(const std::vector<uint8_t>& pdf_data);

    // Evasion technique validation - added for test compatibility
    ValidationResult validate_evasion_techniques(const std::vector<uint8_t>& pdf_data);

    // Individual validation tests
    bool validate_document_id_match(const std::vector<uint8_t>& source, const std::vector<uint8_t>& cloned);
    bool validate_metadata_consistency(const std::vector<uint8_t>& source, const std::vector<uint8_t>& cloned);
    bool validate_entropy_profile_match(const std::vector<uint8_t>& source, const std::vector<uint8_t>& cloned);
    bool validate_compression_patterns(const std::vector<uint8_t>& source, const std::vector<uint8_t>& cloned);
    bool validate_object_structure(const std::vector<uint8_t>& source, const std::vector<uint8_t>& cloned);
    bool validate_timing_signatures(const std::vector<uint8_t>& source, const std::vector<uint8_t>& cloned);
    bool validate_statistical_properties(const std::vector<uint8_t>& source, const std::vector<uint8_t>& cloned);

    // Advanced forensic evasion tests - comprehensive testing functions
    bool test_pdfid_evasion(const std::vector<uint8_t>& pdf_data);
    bool test_pdf_parser_evasion(const std::vector<uint8_t>& pdf_data);
    bool test_adobe_preflight_evasion(const std::vector<uint8_t>& pdf_data);
    bool test_foxit_forensics_evasion(const std::vector<uint8_t>& pdf_data);
    bool test_peepdf_evasion(const std::vector<uint8_t>& pdf_data);
    bool test_qpdf_analysis_evasion(const std::vector<uint8_t>& pdf_data);
    bool test_malformed_structure_detection(const std::vector<uint8_t>& pdf_data);
    bool test_encryption_bypass_detection(const std::vector<uint8_t>& pdf_data);
    bool test_javascript_execution_bypass(const std::vector<uint8_t>& pdf_data);
    bool test_metadata_extraction_evasion(const std::vector<uint8_t>& pdf_data);
    bool check_pdf_validity(const std::vector<uint8_t>& pdf_data);

    // Advanced evasion testing
    bool test_advanced_steganography_evasion(const std::vector<uint8_t>& pdf_data);
    bool test_compression_anomaly_detection(const std::vector<uint8_t>& pdf_data);
    bool test_temporal_analysis_evasion(const std::vector<uint8_t>& pdf_data);
    bool test_encryption_detection_bypass(const std::vector<uint8_t>& pdf_data);
    bool test_timing_attack_resistance(const std::vector<uint8_t>& pdf_data);
    bool test_side_channel_resilience(const std::vector<uint8_t>& pdf_data);
    bool test_pattern_camouflage_effectiveness(const std::vector<uint8_t>& pdf_data);

    // Fingerprint analysis
    ForensicFingerprint extract_fingerprint(const std::vector<uint8_t>& pdf_data);
    double compare_fingerprints(const ForensicFingerprint& fp1, const ForensicFingerprint& fp2);
    bool fingerprints_match(const ForensicFingerprint& fp1, const ForensicFingerprint& fp2, double threshold);

    // Configuration
    void set_validation_strictness(double strictness);
    void set_enable_deep_analysis(bool enable);
    void set_forensic_tool_testing(bool enable);
    void set_statistical_threshold(double threshold);

private:
    // Core analysis functions
    std::string extract_document_id(const std::vector<uint8_t>& pdf_data);
    std::map<std::string, std::string> extract_metadata(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> calculate_entropy_profile(const std::vector<uint8_t>& pdf_data);
    std::string analyze_compression_patterns(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> hash_object_structure(const std::vector<uint8_t>& pdf_data);

    // Statistical analysis
    std::map<std::string, double> calculate_statistical_markers(const std::vector<uint8_t>& pdf_data);
    double calculate_chi_square_statistic(const std::vector<uint8_t>& data);
    std::vector<double> calculate_autocorrelation(const std::vector<uint8_t>& data, int max_lag);
    double calculate_kolmogorov_complexity_estimate(const std::vector<uint8_t>& data);

    // Entropy analysis
    double calculate_shannon_entropy(const std::vector<uint8_t>& data);
    std::vector<double> calculate_block_entropies(const std::vector<uint8_t>& data, size_t block_size);
    double calculate_conditional_entropy(const std::vector<uint8_t>& data);
    std::vector<double> calculate_mutual_information(const std::vector<uint8_t>& data1, 
                                                   const std::vector<uint8_t>& data2);

    // Pattern detection
    std::vector<std::vector<uint8_t>> detect_repeating_patterns(const std::vector<uint8_t>& data);
    std::map<std::string, int> count_pdf_keywords(const std::vector<uint8_t>& pdf_data);
    std::vector<size_t> find_suspicious_sequences(const std::vector<uint8_t>& pdf_data);

    // Structure validation
    bool validate_pdf_syntax(const std::vector<uint8_t>& pdf_data);
    bool validate_xref_table_integrity(const std::vector<uint8_t>& pdf_data);
    bool validate_object_references(const std::vector<uint8_t>& pdf_data);
    bool validate_stream_consistency(const std::vector<uint8_t>& pdf_data);
    
    // Content validation functions
    bool validate_visual_integrity(const std::vector<uint8_t>& pdf_data);
    bool check_font_consistency(const std::vector<uint8_t>& pdf_data);
    bool check_image_integrity(const std::vector<uint8_t>& pdf_data);
    bool check_layout_consistency(const std::vector<uint8_t>& pdf_data);
    bool validate_form_fields(const std::vector<uint8_t>& pdf_data);
    bool validate_javascript_functionality(const std::vector<uint8_t>& pdf_data);
    bool validate_annotations(const std::vector<uint8_t>& pdf_data);
    bool validate_hyperlinks(const std::vector<uint8_t>& pdf_data);
    bool validate_bookmarks(const std::vector<uint8_t>& pdf_data);
    bool validate_embedded_files(const std::vector<uint8_t>& pdf_data);

    // Timing analysis
    double extract_timing_signature(const std::vector<uint8_t>& pdf_data);
    std::vector<double> analyze_object_creation_timing(const std::vector<uint8_t>& pdf_data);
    bool detect_batch_processing_artifacts(const std::vector<uint8_t>& pdf_data);

    // Forensic tool simulation
    ValidationResult simulate_pdfid_analysis(const std::vector<uint8_t>& pdf_data);
    ValidationResult simulate_pdf_parser_analysis(const std::vector<uint8_t>& pdf_data);
    ValidationResult simulate_preflight_analysis(const std::vector<uint8_t>& pdf_data);
    ValidationResult simulate_peepdf_analysis(const std::vector<uint8_t>& pdf_data);
    ValidationResult simulate_virustotal_analysis(const std::vector<uint8_t>& pdf_data);
    ValidationResult simulate_hybrid_analysis(const std::vector<uint8_t>& pdf_data);
    bool test_sandbox_evasion(const std::vector<uint8_t>& pdf_data);

    // Hash and signature functions
    std::vector<uint8_t> calculate_md5_hash(const std::vector<uint8_t>& data);
    std::vector<uint8_t> calculate_sha256_hash(const std::vector<uint8_t>& data);
    std::string calculate_fuzzy_hash(const std::vector<uint8_t>& data);
    std::vector<uint8_t> calculate_structural_hash(const std::vector<uint8_t>& pdf_data);

    // Comparison functions
    double compare_entropy_profiles(const std::vector<uint8_t>& profile1, const std::vector<uint8_t>& profile2);
    double compare_statistical_markers(const std::map<std::string, double>& markers1,
                                     const std::map<std::string, double>& markers2);
    double compare_compression_signatures(const std::string& sig1, const std::string& sig2);
    double compare_object_structures(const std::vector<uint8_t>& hash1, const std::vector<uint8_t>& hash2);

    // Deep analysis functions
    std::vector<std::string> perform_deep_structure_analysis(const std::vector<uint8_t>& pdf_data);
    std::vector<std::string> analyze_invisible_elements(const std::vector<uint8_t>& pdf_data);
    std::vector<std::string> check_steganographic_indicators(const std::vector<uint8_t>& pdf_data);
    std::vector<std::string> detect_manipulation_artifacts(const std::vector<uint8_t>& pdf_data);

public:
    // Quality assurance functions - PUBLIC for testing access
    bool verify_visual_integrity(const std::vector<uint8_t>& original, const std::vector<uint8_t>& cloned);
    bool check_functionality_preservation(const std::vector<uint8_t>& original, const std::vector<uint8_t>& cloned);

    // Reporting functions - PUBLIC for testing access
    std::string generate_validation_report(const ValidationResult& result);
    std::string format_forensic_summary(const std::vector<ValidationResult>& results);
    void log_validation_details(const std::string& test_name, bool passed, const std::string& details);

    // Utility functions - PUBLIC for testing access
    std::vector<size_t> find_pdf_objects(const std::vector<uint8_t>& pdf_data);
    std::vector<size_t> find_stream_objects(const std::vector<uint8_t>& pdf_data);
    std::string extract_pdf_version(const std::vector<uint8_t>& pdf_data);
    size_t count_pdf_objects(const std::vector<uint8_t>& pdf_data);

    std::vector<uint8_t> normalize_pdf_data(const std::vector<uint8_t>& pdf_data);
    std::string bytes_to_hex_string(const std::vector<uint8_t>& data);
    std::vector<uint8_t> hex_string_to_bytes(const std::string& hex);
    
    // Secure entropy generation - PUBLIC for testing access
    std::vector<uint8_t> generate_secure_random_bytes(size_t length);
    bool initialize_secure_random();
    void secure_zero_memory(std::vector<uint8_t>& data);
    void secure_zero_memory(std::string& str);
    
    // Additional utility functions - PUBLIC for testing access
    // Duplicate declaration removed

private:

    // Helper functions for visual integrity
    std::vector<std::string> extract_page_content(const std::string& pdf_str);
    std::string resolve_content_streams(const std::string& pdf_str, const std::string& refs);
    std::string normalize_content_stream(const std::string& content);
    bool compare_page_visual_content(const std::string& page1, const std::string& page2);
    size_t calculate_edit_distance(const std::string& s1, const std::string& s2);

    std::vector<std::map<std::string, std::string>> extract_font_objects(const std::string& pdf_str);
    std::vector<std::map<std::string, std::string>> extract_image_objects(const std::string& pdf_str);
    std::vector<std::map<std::string, std::string>> extract_graphics_states(const std::string& pdf_str);

    bool compare_font_collections(const std::vector<std::map<std::string, std::string>>& fonts1,
                                  const std::vector<std::map<std::string, std::string>>& fonts2);
    bool compare_image_collections(const std::vector<std::map<std::string, std::string>>& images1,
                                   const std::vector<std::map<std::string, std::string>>& images2);
    bool compare_graphics_states(const std::vector<std::map<std::string, std::string>>& gstates1,
                                 const std::vector<std::map<std::string, std::string>>& gstates2);

    // Helper functions for functionality preservation
    bool compare_document_structure(const std::string& pdf1, const std::string& pdf2);
    bool compare_interactive_elements(const std::string& pdf1, const std::string& pdf2);
    bool compare_annotations(const std::string& pdf1, const std::string& pdf2);
    bool compare_form_fields(const std::string& pdf1, const std::string& pdf2);
    bool compare_bookmarks(const std::string& pdf1, const std::string& pdf2);
    bool compare_metadata_functionality(const std::string& pdf1, const std::string& pdf2);

    // Error handling
    void handle_validation_error(const std::string& error_message, ValidationResult& result);
    void add_validation_warning(const std::string& warning_message, ValidationResult& result);
    bool is_recoverable_error(const std::string& error_type);

    // Configuration
    double validation_strictness_;
    bool enable_deep_analysis_;
    bool enable_forensic_tool_testing_;
    double statistical_threshold_;
    bool enable_timing_analysis_;
    bool enable_steganographic_detection_;

    // Cache for performance
    std::map<std::vector<uint8_t>, ForensicFingerprint> fingerprint_cache_;
    std::map<std::vector<uint8_t>, ValidationResult> validation_cache_;
    bool enable_caching_;
    
    // Secure entropy state
    bool secure_random_initialized_;
    std::vector<uint8_t> entropy_pool_;
    std::mutex entropy_mutex_;

    // Statistics
    struct ValidationStats {
        size_t total_validations;
        size_t passed_validations;
        size_t failed_validations;
        double average_confidence_score;
        size_t forensic_tests_run;
        double average_processing_time;
    } stats_;

    void reset_statistics();
    void update_validation_statistics(const ValidationResult& result);

    // Additional statistical helper functions
    double calculate_byte_frequency_variance(const std::vector<uint8_t>& data);
    double calculate_pattern_regularity(const std::vector<uint8_t>& data);
    double calculate_structural_complexity(const std::vector<uint8_t>& data);

    // Enhanced safety functions
    std::string safe_regex_replace_with_timeout(const std::string& input, 
                                               const std::regex& pattern, 
                                               const std::string& replacement,
                                               std::chrono::milliseconds timeout = std::chrono::milliseconds(100));
    bool check_memory_usage_safe(size_t additional_bytes_needed);
};
