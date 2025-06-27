#ifndef SOURCE_FORMAT_PRESERVATION_HPP
#define SOURCE_FORMAT_PRESERVATION_HPP

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <memory>
#include <regex>

struct CriticalSection {
    std::string section_name;
    size_t start_position;
    size_t length;
    std::vector<uint8_t> original_bytes;
    bool is_preserved;
};

class SourceFormatPreservation {
public:
    struct FormatCapture {
        std::map<std::string, std::string> exact_field_formats;
        std::map<std::string, std::string> delimiter_patterns;
        std::map<std::string, std::string> spacing_patterns;
        std::map<std::string, std::string> date_formats;
        std::map<std::string, std::string> number_formats;
        std::map<std::string, std::string> text_formats;
        std::vector<std::string> format_violations;
        std::vector<uint8_t> original_byte_sequence;
        std::map<size_t, std::string> position_format_map;
        std::vector<CriticalSection> critical_sections;
        std::string document_format_signature;
        std::map<std::string, std::vector<size_t>> format_pattern_positions;
        bool capture_complete;
    };

    // Core format preservation functions
    bool capture_source_format(const std::vector<uint8_t>& source_pdf);
    std::vector<uint8_t> preserve_all_formats(const std::vector<uint8_t>& pdf_data);
    std::vector<std::string> detect_format_violations(const std::vector<uint8_t>& target);
    void enforce_zero_tolerance_policy();
    FormatCapture get_captured_format();

    // Format detection and analysis
    FormatCapture analyze_document_formats(const std::vector<uint8_t>& pdf_data);
    bool validate_format_integrity(const FormatCapture& source_format, const std::vector<uint8_t>& target);

    // Format preservation utilities
    std::string extract_exact_format_pattern(const std::string& field_data);
    bool preserve_character_spacing(std::string& target, const std::string& source_pattern);
    bool preserve_delimiter_structure(std::string& target, const std::string& source_delimiters);

    // Validation and enforcement
    bool perform_format_fidelity_check(const std::vector<uint8_t>& source, const std::vector<uint8_t>& target);
    void generate_format_violation_report(const std::vector<std::string>& violations);

    // Strict validation and injection control
    void validate_injection_data_authenticity(const std::vector<uint8_t>& pdf_data, size_t injection_start);
    void enforce_injection_only_operations(const std::vector<uint8_t>& source, const std::vector<uint8_t>& target);
    void validate_no_foreign_data_injection(const std::vector<uint8_t>& pdf_data, size_t injection_start, const std::vector<uint8_t>& authorized_injection_data);
    bool is_injection_zone_safe(const std::vector<uint8_t>& pdf_data, size_t position);
    std::vector<size_t> identify_safe_injection_zones(const std::vector<uint8_t>& pdf_data);

    // Comprehensive format fidelity checking
    bool perform_comprehensive_format_fidelity_check(const std::vector<uint8_t>& source, const std::vector<uint8_t>& target);
    void validate_complete_byte_sequence_preservation(const std::vector<uint8_t>& source, const std::vector<uint8_t>& target);
    void validate_pdf_structure_integrity(const std::vector<uint8_t>& pdf_data);
    void validate_metadata_preservation(const std::vector<uint8_t>& source, const std::vector<uint8_t>& target);
    void validate_timestamp_preservation(const std::vector<uint8_t>& source, const std::vector<uint8_t>& target);

    // Getters
    const FormatCapture& get_captured_format() const { return captured_format_; }
    bool is_format_preserved() const { return format_preserved_; }

private:
    FormatCapture captured_format_;
    bool format_preserved_ = false;

    // Internal format analysis functions
    void detect_date_formats(const std::vector<uint8_t>& data);
    void detect_number_formats(const std::vector<uint8_t>& data);
    void detect_text_formats(const std::vector<uint8_t>& data);
    void detect_delimiter_patterns(const std::vector<uint8_t>& data);
    void detect_spacing_patterns(const std::vector<uint8_t>& data);

    // Format validation helpers
    bool validate_exact_byte_sequence(size_t position, const std::vector<uint8_t>& source, const std::vector<uint8_t>& target);
    bool check_format_consistency(const std::string& field_type, const std::string& source_format, const std::string& target_format);

    // Error handling
    void handle_format_violation(const std::string& violation_type, const std::string& details);
};

#endif // SOURCE_FORMAT_PRESERVATION_HPP