#pragma once
// Security Components Integration - Missing Critical Dependencies
#include "stealth_scrubber.hpp"
#include "trace_cleaner.hpp"
#include "metadata_cleaner.hpp"
#include "memory_sanitizer.hpp"
#include "pdf_integrity_checker.hpp"
#include <vector>
#include <string>
#include <map>
#include <set>
#include <unordered_map>
#include <cstdint>
#include <regex>
#include <mutex>

// Advanced Anti-Fingerprinting Engine
// Removes ALL traces of processing tools, libraries, and default values
class AntiFingerprintEngine {
public:
    struct LibrarySignature {
        std::string library_name;
        std::vector<std::string> signature_patterns;
        std::vector<std::string> metadata_keys;
        std::vector<std::string> default_values;
        std::vector<std::string> timestamp_patterns;
        std::vector<std::string> version_patterns;
    };

    struct ProcessingTrace {
        std::string trace_type;
        std::string location;
        std::vector<uint8_t> original_bytes;
        std::vector<uint8_t> replacement_bytes;
        bool is_critical;
    };

private:
    // Known library fingerprints database
    std::vector<LibrarySignature> known_signatures_;
    std::map<std::string, std::string> library_replacements_;
    std::set<std::string> forbidden_metadata_keys_;
    std::vector<std::regex> watermark_patterns_;
    std::vector<std::regex> timestamp_patterns_;
    std::vector<std::regex> version_patterns_;
    std::vector<std::regex> tool_signature_patterns_;
    
    // Source PDF fingerprints for authentic replacement
    std::map<std::string, std::string> source_metadata_;
    std::map<std::string, std::vector<uint8_t>> source_signatures_;
    std::string source_creation_date_;
    std::string source_modification_date_;
    std::string source_producer_;
    std::string source_creator_;
    
    mutable std::mutex fingerprint_mutex_;

    // Critical fingerprint removal methods
    void initialize_known_signatures();
    void load_source_fingerprints(const std::vector<uint8_t>& source_pdf);
    std::vector<uint8_t> remove_library_watermarks(const std::vector<uint8_t>& data);
    std::vector<uint8_t> replace_default_values(const std::vector<uint8_t>& data);
    std::vector<uint8_t> neutralize_timestamps(const std::vector<uint8_t>& data);
    std::vector<uint8_t> remove_tool_signatures(const std::vector<uint8_t>& data);
    std::vector<uint8_t> clean_metadata_traces(const std::vector<uint8_t>& data);
    std::vector<uint8_t> remove_compression_artifacts(const std::vector<uint8_t>& data);
    std::vector<uint8_t> sanitize_object_references(const std::vector<uint8_t>& data);

public:
    AntiFingerprintEngine();
    ~AntiFingerprintEngine();

    // Main anti-fingerprinting methods
    void set_source_pdf(const std::vector<uint8_t>& source_pdf);
    std::vector<uint8_t> clean_all_traces(const std::vector<uint8_t>& processed_pdf);
    std::vector<ProcessingTrace> detect_processing_traces(const std::vector<uint8_t>& pdf_data);
    bool verify_trace_free(const std::vector<uint8_t>& pdf_data);
    
    // Library-specific cleaning
    std::vector<uint8_t> remove_poppler_traces(const std::vector<uint8_t>& data);
    std::vector<uint8_t> remove_pdfium_traces(const std::vector<uint8_t>& data);
    std::vector<uint8_t> remove_itext_traces(const std::vector<uint8_t>& data);
    std::vector<uint8_t> remove_pdftk_traces(const std::vector<uint8_t>& data);
    std::vector<uint8_t> remove_ghostscript_traces(const std::vector<uint8_t>& data);
    std::vector<uint8_t> remove_mupdf_traces(const std::vector<uint8_t>& data);
    std::vector<uint8_t> remove_cairo_traces(const std::vector<uint8_t>& data);
    std::vector<uint8_t> remove_qpdf_traces(const std::vector<uint8_t>& data);
    
    // Metadata cleaning
    std::vector<uint8_t> replace_creation_metadata(const std::vector<uint8_t>& data);
    std::vector<uint8_t> clone_authentic_timestamps(const std::vector<uint8_t>& data);
    std::vector<uint8_t> replace_producer_info(const std::vector<uint8_t>& data);
    
    // Deep structure cleaning
    std::vector<uint8_t> clean_stream_dictionaries(const std::vector<uint8_t>& data);
    std::vector<uint8_t> remove_processing_comments(const std::vector<uint8_t>& data);
    std::vector<uint8_t> sanitize_xref_table(const std::vector<uint8_t>& data);
    std::vector<uint8_t> clean_trailer_dictionary(const std::vector<uint8_t>& data);
    
    // Verification and reporting
    std::vector<std::string> get_detected_libraries(const std::vector<uint8_t>& data);
    std::map<std::string, std::vector<std::string>> get_trace_report(const std::vector<uint8_t>& data);
    bool has_processing_artifacts(const std::vector<uint8_t>& data);
    
    // Configuration
    void add_custom_signature(const LibrarySignature& signature);
    
    // STRICT SOURCE-ONLY POLICY functions
    void set_source_metadata(const std::string& key, const std::string& value);
    void clear_source_metadata();
    std::vector<uint8_t> process(const std::vector<uint8_t>& data);
    void enforce_blank_fields_policy(std::vector<uint8_t>& data);
    
    // CRITICAL: Anti-processing timestamp functions
    std::vector<uint8_t> remove_all_processing_timestamps(const std::vector<uint8_t>& data);
    std::vector<uint8_t> final_processing_timestamp_removal(const std::vector<uint8_t>& data);
    
    // CRITICAL: XMP-DocInfo synchronization to prevent tampering detection
    std::vector<uint8_t> synchronize_xmp_docinfo(const std::vector<uint8_t>& data);
    std::string convert_pdf_date_to_xmp(const std::string& pdf_date);
    void set_aggressive_cleaning(bool enabled);
    void enable_deep_structure_cleaning(bool enabled);
};

// Utility functions for anti-fingerprinting
namespace AntiFingerprintUtils {
    // Pattern matching and replacement
    std::vector<uint8_t> replace_pattern(const std::vector<uint8_t>& data, 
                                        const std::string& pattern, 
                                        const std::string& replacement);
    
    std::vector<uint8_t> remove_pattern(const std::vector<uint8_t>& data, 
                                       const std::string& pattern);
    
    // Timestamp manipulation
    std::string convert_to_source_timestamp_format(const std::string& timestamp, 
                                                   const std::string& source_format);
    
    // Metadata extraction and cloning
    std::map<std::string, std::string> extract_authentic_metadata(const std::vector<uint8_t>& source_pdf);
    
    // Binary signature detection
    std::vector<size_t> find_binary_signatures(const std::vector<uint8_t>& data, 
                                              const std::vector<uint8_t>& signature);
    
    // Safe replacement without corruption
    std::vector<uint8_t> safe_replace_bytes(const std::vector<uint8_t>& data, 
                                           size_t offset, 
                                           const std::vector<uint8_t>& new_bytes);
}
