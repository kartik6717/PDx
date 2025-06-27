#ifndef FORMAT_VALIDATION_ENGINE_HPP
#define FORMAT_VALIDATION_ENGINE_HPP
#include "stealth_macros.hpp"

#include "source_format_preservation.hpp"
#include <vector>
#include <string>
#include <map>

class FormatValidationEngine {
public:
    struct ValidationResult {
        bool is_valid;
        std::vector<std::string> format_violations;
        std::vector<std::string> critical_errors;
        double fidelity_score;
        std::map<std::string, std::string> field_comparisons;
    };

    // Core validation functions
    bool check_absolute_fidelity(const std::vector<uint8_t>& source, const std::vector<uint8_t>& processed);
    bool validate_exact_format_match(const std::string& source, const std::string& target);
    std::vector<std::string> detect_format_changes(
        const SourceFormatPreservation::FormatCapture& source_format, 
        const std::vector<uint8_t>& target_pdf
    );
    void reject_format_modifications();
    
    // Comprehensive validation
    ValidationResult perform_comprehensive_validation(
        const std::vector<uint8_t>& source_pdf,
        const std::vector<uint8_t>& processed_pdf,
        const SourceFormatPreservation::FormatCapture& source_format
    );
    
    // Field-specific validation
    bool validate_date_format_preservation(const std::string& source_date, const std::string& target_date);
    bool validate_number_format_preservation(const std::string& source_number, const std::string& target_number);
    bool validate_text_format_preservation(const std::string& source_text, const std::string& target_text);
    bool validate_delimiter_preservation(const std::string& source_delim, const std::string& target_delim);
    bool validate_spacing_preservation(const std::string& source_spacing, const std::string& target_spacing);
    
    // Byte-level validation
    bool validate_byte_sequence_integrity(
        const std::vector<uint8_t>& source,
        const std::vector<uint8_t>& target,
        size_t start_position,
        size_t length
    );
    
    // Zero-tolerance enforcement
    void enforce_zero_modification_policy(const ValidationResult& result);
    bool check_absolute_fidelity(const std::vector<uint8_t>& source, const std::vector<uint8_t>& target);
    
    // Reporting and analysis
    void generate_validation_report(const ValidationResult& result);
    double calculate_format_fidelity_score(
        const SourceFormatPreservation::FormatCapture& source_format,
        const std::vector<uint8_t>& target_pdf
    );
    
    // Configuration
    void set_zero_tolerance_mode(bool enabled) { zero_tolerance_mode_ = enabled; }
    void set_validation_strictness(ValidationStrictness level) { validation_strictness_ = level; }

    enum class ValidationStrictness {
        STRICT,      // Zero tolerance for any changes
        MODERATE,    // Allow minor non-format changes
        LENIENT      // Focus only on critical format preservation
    };

private:
    bool zero_tolerance_mode_ = true;
    ValidationStrictness validation_strictness_ = ValidationStrictness::STRICT;
    
    // Internal validation helpers
    bool compare_format_patterns(const std::string& pattern1, const std::string& pattern2);
    bool validate_character_by_character(const std::string& source, const std::string& target);
    std::string extract_format_signature(const std::string& data);
    
    // Error handling and reporting
    void log_format_violation(const std::string& violation_type, const std::string& details);
    void throw_zero_tolerance_exception(const std::vector<std::string>& violations);
    
    // Helper methods for format extraction and validation
    std::string extract_field_format(const std::string& content, const std::string& field_name);
    std::string extract_delimiter_pattern(const std::string& content, const std::string& delimiter_type);
    std::string extract_spacing_pattern(const std::string& content, const std::string& spacing_type);
    std::vector<std::string> validate_pdf_structure_preservation(const std::vector<uint8_t>& source_pdf, const std::vector<uint8_t>& target_pdf);
    std::vector<std::string> validate_metadata_format_preservation(const std::vector<uint8_t>& source_pdf, const std::vector<uint8_t>& target_pdf);
    std::vector<std::string> validate_stream_format_preservation(const std::vector<uint8_t>& source_pdf, const std::vector<uint8_t>& target_pdf);
    std::map<std::string, std::string> perform_field_by_field_comparison(const SourceFormatPreservation::FormatCapture& source_format, const std::vector<uint8_t>& target_pdf);
};

#endif // FORMAT_VALIDATION_ENGINE_HPP
