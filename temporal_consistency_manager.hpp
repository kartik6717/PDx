#ifndef TEMPORAL_CONSISTENCY_MANAGER_HPP
#define TEMPORAL_CONSISTENCY_MANAGER_HPP
#include "stealth_macros.hpp"

#include <vector>
#include <string>
#include <map>
#include <chrono>

class TemporalConsistencyManager {
public:
    struct TemporalMetadata {
        std::string creation_date;
        std::string modification_date;
        std::string producer_timestamp;
        std::string creator_timestamp;
        std::map<std::string, std::string> all_timestamps;
    };

    struct ConsistencyConfig {
        bool preserve_original_timestamps = true;
        bool maintain_document_age_indicators = true;
        bool eliminate_fresh_processing_markers = true;
        bool synchronize_all_temporal_metadata = true;
        bool remove_system_generated_timestamps = true;
    };

    TemporalConsistencyManager();
    ~TemporalConsistencyManager() = default;

    // Core temporal consistency functions
    std::vector<uint8_t> maintain_temporal_consistency(const std::vector<uint8_t>& pdf_data);
    
    bool capture_original_temporal_metadata(const std::vector<uint8_t>& source_pdf);
    std::vector<uint8_t> preserve_original_timestamps(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> maintain_document_age_indicators(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> eliminate_fresh_processing_markers(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> synchronize_all_temporal_metadata(const std::vector<uint8_t>& pdf_data);
    
    // CRITICAL MISSING METHODS - Called by pdf_byte_fidelity_processor.cpp
    void preserve_original_timestamps();
    void eliminate_fresh_processing_markers();
    void synchronize_all_temporal_metadata();
    
    // Validation functions
    bool validate_temporal_consistency(const std::vector<uint8_t>& source, const std::vector<uint8_t>& target);
    std::vector<std::string> detect_temporal_inconsistencies(const std::vector<uint8_t>& pdf_data);
    
    // Configuration
    void configure(const ConsistencyConfig& config);
    ConsistencyConfig get_config() const { return config_; }
    
    // Metadata access
    TemporalMetadata get_captured_metadata() const { return captured_metadata_; }

private:
    ConsistencyConfig config_;
    TemporalMetadata captured_metadata_;
    std::map<std::string, std::string> preserved_timestamps_;
    bool processing_markers_eliminated_ = false;
    bool metadata_synchronized_ = false;
    
    // Internal processing functions
    std::vector<std::string> extract_all_timestamps(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> replace_timestamp_at_position(const std::vector<uint8_t>& pdf_data, 
                                                      size_t position, 
                                                      const std::string& old_timestamp, 
                                                      const std::string& new_timestamp);
                                                      
    // Helper methods for critical implementations
    std::vector<uint8_t> apply_preserved_timestamps(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> apply_processing_marker_elimination(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> apply_temporal_synchronization(const std::vector<uint8_t>& pdf_data);
    
    // Timestamp detection and parsing
    std::vector<size_t> find_timestamp_positions(const std::vector<uint8_t>& pdf_data);
    bool is_valid_pdf_timestamp(const std::string& timestamp);
    std::string normalize_timestamp_format(const std::string& timestamp);
    
    // Processing marker detection
    std::vector<size_t> find_processing_markers(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> remove_processing_markers(const std::vector<uint8_t>& pdf_data);
    
    // Age indicator management
    std::vector<uint8_t> preserve_age_related_metadata(const std::vector<uint8_t>& pdf_data);
    bool indicates_recent_processing(const std::string& timestamp);
    
    // Synchronization helpers
    void synchronize_creation_modification_dates();
    void ensure_temporal_logic_consistency();
    void validate_timestamp_relationships();
};

#endif // TEMPORAL_CONSISTENCY_MANAGER_HPP
