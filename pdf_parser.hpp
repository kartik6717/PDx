#pragma once
#include <vector>
#include <string>
#include <map>
#include <cstdint>
#include <memory>
#include <chrono>
#include <mutex>
#include <stdexcept>
#include <set>

// Enhanced error handling
class PDFParseException : public std::runtime_error {
public:
    PDFParseException(const std::string& message, const std::string& context = "", size_t position = 0)
        : std::runtime_error(message), context_(context), position_(position) {}
    
    const std::string& context() const { return context_; }
    size_t position() const { return position_; }
    
private:
    std::string context_;
    size_t position_;
};

// Security and validation settings
struct PDFParserConfig {
    size_t max_file_size = 100 * 1024 * 1024;      // 100MB limit
    size_t max_objects = 100000;                    // Max objects limit
    size_t max_recursion_depth = 50;               // Max dictionary nesting
    size_t max_string_length = 1024 * 1024;        // 1MB string limit
    size_t max_stream_size = 50 * 1024 * 1024;     // 50MB stream limit
    std::chrono::seconds max_parse_time{30};       // 30 second timeout
    bool strict_validation = true;                 // Strict PDF compliance
    bool enable_recovery = true;                   // Error recovery mode
};

struct PDFObject {
    int number = 0;
    int generation = 0;
    size_t offset = 0;
    size_t length = 0;
    std::string content;
    std::string dictionary_data;
    std::map<std::string, std::string> dictionary;
    std::vector<uint8_t> data;
    std::vector<uint8_t> stream_data;
    bool has_stream = false;
    bool is_compressed = false;
    bool is_encrypted = false;
    std::vector<std::string> filters;
    
    // Enhanced metadata
    std::string object_type;
    size_t original_size = 0;
    std::string checksum;
    bool is_valid = true;
};

struct PDFXRefEntry {
    size_t offset = 0;
    int generation = 0;
    bool in_use = false;
    bool is_compressed = false;  // For PDF 1.5+ object streams
    int containing_stream = -1;  // Object stream number
    int index_in_stream = -1;    // Index within object stream
};

struct PDFTrailer {
    std::map<std::string, std::string> dictionary;
    size_t prev_xref_offset = 0;
    bool has_prev = false;
    std::string document_id;
    std::string encryption_dict_ref;
    std::string info_dict_ref;
    std::string root_dict_ref;
    int size = 0;
};

// Enhanced forensic data structure
struct PDFForensicData {
    // Document metadata
    std::string document_id;
    std::string creation_date;
    std::string modification_date;
    std::string creator;
    std::string producer;
    std::string title;
    std::string author;
    std::string subject;
    std::string keywords;
    
    // Technical metadata
    std::string pdf_version;
    std::vector<std::string> incremental_updates;
    std::vector<std::string> javascript_actions;
    std::map<std::string, std::string> form_fields;
    std::vector<std::string> embedded_files;
    std::map<std::string, std::string> xmp_properties;
    std::map<std::string, std::string> viewer_preferences;
    
    // Hidden content detection
    std::vector<std::string> hidden_text;
    std::vector<std::string> invisible_annotations;
    std::vector<std::string> overlay_content;
    std::vector<std::string> micro_text;
    
    // Creation tool fingerprints
    std::string creation_tool_signature;
    std::vector<std::string> object_ordering_patterns;
    std::map<std::string, std::string> compression_signatures;
    std::vector<std::string> timestamp_patterns;
    
    // Security analysis
    bool has_encryption = false;
    std::string encryption_method;
    std::vector<std::string> security_vulnerabilities;
    bool has_javascript = false;
    bool has_forms = false;
    bool has_external_references = false;
};

struct PDFStructure {
    std::string version;
    std::vector<PDFObject> objects;
    std::map<int, PDFXRefEntry> xref_table;
    PDFTrailer trailer;
    size_t startxref_offset = 0;
    std::vector<uint8_t> header_garbage;
    std::vector<uint8_t> tail_garbage;
    int next_object_number = 1;
    
    // Enhanced structure data
    PDFForensicData forensic_data;
    std::vector<std::string> parse_warnings;
    std::vector<std::string> parse_errors;
    bool is_linearized = false;
    bool is_encrypted = false;
    bool is_signed = false;
    size_t total_size = 0;
    
    // Additional metadata
    std::string document_id;
    std::string info_object_ref;
    std::string root_object_ref;
    std::string metadata_object_ref;
    std::map<std::string, std::string> producer_info;
    std::vector<std::string> javascript_actions;
    std::map<std::string, std::string> form_fields;
    std::vector<uint8_t> embedded_files;
    std::map<std::string, std::string> linearization_params;
    
    // Performance metrics
    std::chrono::milliseconds parse_time{0};
    size_t objects_parsed = 0;
    size_t streams_decompressed = 0;
    size_t memory_used = 0;
};

class PDFParser {
public:
    PDFParser();
    explicit PDFParser(const PDFParserConfig& config);
    ~PDFParser();

    // Main parsing interface
    PDFStructure parse(const std::vector<uint8_t>& pdf_data);
    PDFStructure parse_with_recovery(const std::vector<uint8_t>& pdf_data);
    
    // Configuration
    void set_config(const PDFParserConfig& config);
    PDFParserConfig get_config() const;
    
    // Validation and diagnostics
    bool validate_pdf(const std::vector<uint8_t>& pdf_data);
    std::vector<std::string> get_parse_warnings() const;
    std::vector<std::string> get_parse_errors() const;

private:
    std::string extract_version(const std::vector<uint8_t>& data);
    std::vector<PDFObject> extract_objects(const std::vector<uint8_t>& data);
    std::map<int, PDFXRefEntry> extract_xref_table(const std::vector<uint8_t>& data, size_t xref_offset);
    PDFTrailer extract_trailer(const std::vector<uint8_t>& data, size_t trailer_offset);

    // Enhanced object parsing with validation
    PDFObject parse_object(const std::string& obj_data, size_t offset, size_t recursion_depth = 0);
    std::map<std::string, std::string> parse_dictionary(const std::string& dict_data, size_t recursion_depth = 0);
    std::vector<uint8_t> extract_stream_data(const std::string& obj_data);

    // Advanced PDF features (PDF 1.5+)
    std::vector<PDFObject> parse_object_streams(const PDFStructure& structure);
    std::map<int, PDFXRefEntry> parse_xref_streams(const std::vector<uint8_t>& data, size_t offset);
    bool parse_linearized_pdf(const std::vector<uint8_t>& data, PDFStructure& structure);
    
    // Comprehensive forensic analysis
    void extract_forensic_data(PDFStructure& structure, const std::vector<uint8_t>& data);
    void extract_document_metadata(PDFForensicData& forensic, const PDFStructure& structure);
    void extract_technical_metadata(PDFForensicData& forensic, const PDFStructure& structure);
    void extract_hidden_content(PDFForensicData& forensic, const std::vector<uint8_t>& data);
    void extract_creation_signatures(PDFForensicData& forensic, const PDFStructure& structure);
    void analyze_security_features(PDFForensicData& forensic, const PDFStructure& structure);
    
    // Enhanced metadata extraction
    void extract_xmp_properties(PDFForensicData& forensic, const std::string& xmp_content);
    void extract_viewer_preferences(PDFForensicData& forensic, const PDFObject& vp_obj);
    void extract_font_metadata(PDFForensicData& forensic, const PDFObject& font_obj);
    void extract_image_metadata(PDFForensicData& forensic, const PDFObject& image_obj);
    void extract_javascript_content(PDFForensicData& forensic, const PDFStructure& structure);
    void extract_form_fields(PDFForensicData& forensic, const PDFStructure& structure);
    void extract_embedded_files(PDFForensicData& forensic, const PDFStructure& structure);
    
    // Hidden content detection
    void detect_invisible_text(PDFForensicData& forensic, const std::vector<uint8_t>& data);
    void detect_overlay_content(PDFForensicData& forensic, const PDFStructure& structure);
    void detect_micro_text(PDFForensicData& forensic, const std::vector<uint8_t>& data);
    void detect_white_on_white_text(PDFForensicData& forensic, const PDFStructure& structure);
    
    // Creation tool fingerprinting
    void analyze_object_ordering(PDFForensicData& forensic, const PDFStructure& structure);
    void analyze_compression_patterns(PDFForensicData& forensic, const PDFStructure& structure);
    void analyze_timestamp_patterns(PDFForensicData& forensic, const PDFStructure& structure);
    void identify_creation_tool(PDFForensicData& forensic, const PDFStructure& structure);
    
    // Security and vulnerability analysis
    void check_javascript_vulnerabilities(PDFForensicData& forensic, const std::vector<std::string>& js_content);
    void check_form_vulnerabilities(PDFForensicData& forensic, const std::map<std::string, std::string>& forms);
    void check_external_references(PDFForensicData& forensic, const PDFStructure& structure);
    void analyze_encryption_security(PDFForensicData& forensic, const PDFStructure& structure);

    // Robust stream decompression with all filters
    std::vector<uint8_t> decompress_stream(const std::vector<uint8_t>& compressed_data, 
                                          const std::vector<std::string>& filters);

    // Complete PDF filter implementations
    std::vector<uint8_t> decode_ascii_hex(const std::vector<uint8_t>& data);
    std::vector<uint8_t> decode_ascii85(const std::vector<uint8_t>& data);
    std::vector<uint8_t> decode_lzw(const std::vector<uint8_t>& data);
    std::vector<uint8_t> decode_run_length(const std::vector<uint8_t>& data);
    std::vector<uint8_t> decode_flate(const std::vector<uint8_t>& data);
    std::vector<uint8_t> decode_ccitt_fax(const std::vector<uint8_t>& data);
    std::vector<uint8_t> decode_jbig2(const std::vector<uint8_t>& data);
    std::vector<uint8_t> decode_jpx(const std::vector<uint8_t>& data);
    std::vector<uint8_t> decode_crypt(const std::vector<uint8_t>& data);
    
    // JPEG2000 helper function
    std::vector<uint8_t> decode_j2k_codestream(const std::vector<uint8_t>& data, size_t offset, size_t length);

    // Reference resolution with circular detection
    std::string resolve_reference(const std::string& reference, const PDFStructure& structure, 
                                 std::set<std::string>& visited_refs);
    PDFObject* find_object_by_reference(const std::string& reference, PDFStructure& structure);
    
    // Input validation and security
    void validate_input_size(const std::vector<uint8_t>& data);
    void validate_object_count(size_t count);
    void validate_string_length(const std::string& str);
    void validate_recursion_depth(size_t depth);
    void validate_numeric_range(const std::string& value, const std::string& context);
    
    // Error handling and recovery
    bool attempt_error_recovery(PDFStructure& structure, const std::string& error_context);
    void handle_malformed_dictionary(std::map<std::string, std::string>& dict, const std::string& data);
    void handle_invalid_stream(PDFObject& obj);
    void handle_corrupted_xref(std::map<int, PDFXRefEntry>& xref_table, const std::vector<uint8_t>& data);
    
    // Utility methods with bounds checking
    size_t find_object_end(const std::string& data, size_t start_pos);
    size_t find_next_occurrence(const std::string& data, const std::string& pattern, size_t start_pos);
    bool is_valid_pdf_object(const PDFObject& obj);
    bool is_encrypted_pdf(const PDFStructure& structure);
    std::string sanitize_string(const std::string& input);
    
    // Helper methods for parsing
    size_t find_matching_delimiter(const std::string& data, size_t start, const std::string& open, const std::string& close);
    std::map<std::string, std::string> parse_dictionary_content(const std::string& content);
    std::string trim(const std::string& str);
    std::vector<uint8_t> decompress_stream_data(const std::vector<uint8_t>& compressed_data, const std::vector<std::string>& filters);
    
    // Extraction methods
    void extract_document_id(PDFStructure& structure, const std::vector<uint8_t>& data);
    void extract_info_metadata(PDFStructure& structure);
    void extract_javascript_actions(PDFStructure& structure);
    void extract_form_fields(PDFStructure& structure);
    void extract_embedded_files(PDFStructure& structure);
    void extract_producer_info(PDFStructure& structure);
    
    // Additional utility methods
    std::string resolve_reference(const std::string& reference, const PDFStructure& structure);
    void resolve_and_extract_js_content(PDFStructure& structure, const std::string& reference);
    void extract_named_javascript_actions(PDFStructure& structure, const PDFObject& obj);
    bool contains_javascript_patterns(const std::string& content);
    void extract_hidden_javascript_patterns(PDFStructure& structure, const std::string& pdf_str);
    void extract_xmp_properties(PDFStructure& structure, const std::string& xmp_content);
    void extract_viewer_preferences(PDFStructure& structure, const std::string& vp_ref);
    void extract_font_metadata(PDFStructure& structure, const PDFObject& obj);
    void extract_image_metadata(PDFStructure& structure, const PDFObject& obj);
    void extract_hidden_metadata(PDFStructure& structure, const std::string& pdf_str);
    void extract_creation_tool_signatures(PDFStructure& structure);
    void extract_incremental_update_metadata(PDFStructure& structure, const std::string& pdf_str);
    void validate_pdf_structure(const PDFStructure& structure);
    
    // Performance and memory management
    void monitor_memory_usage();
    void check_parsing_timeout();
    void optimize_object_storage(std::vector<PDFObject>& objects);
    
    // Thread safety
    mutable std::mutex parser_mutex_;
    
    // Configuration and state
    PDFParserConfig config_;
    std::vector<std::string> warnings_;
    std::vector<std::string> errors_;
    std::chrono::steady_clock::time_point parse_start_time_;
    size_t current_memory_usage_;
    
    // Cache for performance
    std::map<std::string, std::vector<uint8_t>> decompression_cache_;
    std::map<int, PDFObject*> object_cache_;
    
    // Security tracking
    std::set<std::string> visited_references_;
    size_t current_recursion_depth_;
    
    // Current PDF data for reference
    std::vector<uint8_t> current_pdf_data_;
    
    // Performance statistics
    struct {
        size_t streams_extracted = 0;
        size_t total_stream_bytes = 0;
    } stats_;
};
