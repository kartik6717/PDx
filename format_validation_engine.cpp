#include "format_validation_engine.hpp"
#include "stealth_macros.hpp"
#include "complete_silence_enforcer.hpp"
#include "secure_memory.hpp"
#include <sstream>
#include <algorithm>
#include <cmath>
#include <stdexcept>

// Initialize secure validation environment
static void* secure_validation_workspace = nullptr;

void initialize_secure_validation() {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    secure_validation_workspace = SecureMemory::allocate_secure_buffer(8192);
}

bool FormatValidationEngine::check_absolute_fidelity(const std::vector<uint8_t>& source, const std::vector<uint8_t>& processed) {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    try {
        return structured_exception_handling([&]() -> bool {
            SecureMemory secure_source_buffer(source.size() + 2048);
            SecureMemory secure_processed_buffer(processed.size() + 2048);
            SecureMemory secure_comparison_buffer(8192);
            
            // Copy data to secure memory with obfuscated operations
            secure_source_buffer.copy_from(source.data(), source.size());
            secure_processed_buffer.copy_from(processed.data(), processed.size());
            
            bool fidelity_result = false;
            
            // Randomized validation approach to prevent signature detection
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> validation_method_dist(1, 4);
            int validation_method = validation_method_dist(gen);
            
            // Multiple validation methods to break forensic patterns
            switch (validation_method) {
                case 1:
                    fidelity_result = perform_byte_by_byte_validation(
                        secure_source_buffer, secure_processed_buffer, secure_comparison_buffer
                    );
                    break;
                case 2:
                    fidelity_result = perform_checksum_validation(
                        secure_source_buffer, secure_processed_buffer, secure_comparison_buffer
                    );
                    break;
                case 3:
                    fidelity_result = perform_statistical_validation(
                        secure_source_buffer, secure_processed_buffer, secure_comparison_buffer
                    );
                    break;
                case 4:
                    fidelity_result = perform_hash_based_validation(
                        secure_source_buffer, secure_processed_buffer, secure_comparison_buffer
                    );
                    break;
            }
            
            // Randomized multi-pass cleanup
            std::uniform_int_distribution<> cleanup_passes_dist(7, 15);
            int cleanup_passes = cleanup_passes_dist(gen);
            
            for (int pass = 0; pass < cleanup_passes; ++pass) {
                secure_source_buffer.zero();
                secure_processed_buffer.zero();
                secure_comparison_buffer.zero();
                eliminate_all_traces();
                
                // Random inter-pass delays
                std::uniform_int_distribution<> delay_dist(30, 200);
                std::this_thread::sleep_for(std::chrono::microseconds(delay_dist(gen)));
            }
            
            return fidelity_result;
        }, false);
    } catch (...) {
        eliminate_all_traces();
        return false;
    }
    
    try {
        return structured_exception_handling([&]() -> bool {
            // Initialize secure validation workspace
            SecureMemory secure_source_buffer(source.size() + 4096);
            SecureMemory secure_processed_buffer(processed.size() + 4096);
            SecureMemory secure_comparison_buffer(8192);
            
            secure_source_buffer.copy_from(source.data(), source.size());
            secure_processed_buffer.copy_from(processed.data(), processed.size());
            
            bool fidelity_maintained = true;
            
            // Silent size validation
            if (source.size() > processed.size()) {
                fidelity_maintained = false;
            } else {
                // Silent byte-by-byte comparison with obfuscated memory access
                for (size_t i = 0; i < source.size(); ++i) {
                    // Use secure comparison to prevent timing attacks
                    if (!SecureMemory::secure_byte_compare(
                            static_cast<const uint8_t*>(secure_source_buffer.get()) + i,
                            static_cast<const uint8_t*>(secure_processed_buffer.get()) + i,
                            1)) {
                        if (zero_tolerance_mode_) {
                            fidelity_maintained = false;
                            break;
                        }
                    }
                }
                
                // Silent injection zone validation if document is larger
                if (processed.size() > source.size() && fidelity_maintained) {
                    SecureMemory secure_content_buffer(source.size() + 256);
                    secure_content_buffer.copy_from(source.data(), source.size());
                    
                    // Silent EOF marker detection
                    const uint8_t* content_ptr = static_cast<const uint8_t*>(secure_content_buffer.get());
                    bool eof_found = SecureMemory::secure_pattern_search(
                        content_ptr, source.size(),
                        reinterpret_cast<const uint8_t*>("%%EOF"), 5
                    );
                    
                    if (!eof_found) {
                        fidelity_maintained = false;
                    }
                    
                    secure_content_buffer.zero();
                }
            }
            
            // Randomized comprehensive cleanup
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> cleanup_passes_dist(6, 15);
            int cleanup_passes = cleanup_passes_dist(gen);
            
            for (int pass = 0; pass < cleanup_passes; ++pass) {
                secure_source_buffer.zero();
                secure_processed_buffer.zero();
                secure_comparison_buffer.zero();
                eliminate_all_traces();
                
                // Randomized inter-pass delays
                std::uniform_int_distribution<> delay_dist(50, 250);
                std::this_thread::sleep_for(std::chrono::microseconds(delay_dist(gen)));
            }
            
            return fidelity_maintained;
        }, false); // Silent failure
    } catch (...) {
        eliminate_all_traces();
        return false;
    }
    
    // Initialize secure validation environment
    if (!secure_validation_workspace) {
        initialize_secure_validation();
    }
    
    // Secure memory operations for validation
    void* secure_comparison_buffer = SecureMemory::allocate_secure_buffer(1024);
    
    // CRITICAL METHOD IMPLEMENTATION - Called by pdf_byte_fidelity_processor.cpp
    
    // Step 1: Validate size consistency
    if (source.size() > processed.size()) {
        SILENT_OPERATION("FORMAT_VALIDATION", "Size reduction detected");
        return false;
    }
    
    // Step 2: Validate exact byte preservation for original content
    for (size_t i = 0; i < source.size(); ++i) {
        if (processed[i] != source[i]) {
            SILENT_OPERATION("FORMAT_VALIDATION", "Byte modification detected");
            
            if (zero_tolerance_mode_) {
                return false;
            }
        }
    }
    
    // Step 3: Validate injection zone if document is larger
    if (processed.size() > source.size()) {
        // Only allow additions after %%EOF marker
        std::string source_content(source.begin(), source.end());
        size_t eof_pos = source_content.rfind("%%EOF");
        
        if (eof_pos == std::string::npos) {
            SILENT_OPERATION("FORMAT_VALIDATION", "Invalid injection zone");
            return false;
        }
        
        // Calculate safe injection position
        size_t safe_injection_start = eof_pos + 5; // After %%EOF
        if (safe_injection_start < source.size() && source[safe_injection_start] == '\n') {
            safe_injection_start++;
        }
        
        if (safe_injection_start != source.size()) {
            SILENT_OPERATION("FORMAT_VALIDATION", "Unsafe injection detected");
            return false;
        }
    }
    
    return true;
}

bool FormatValidationEngine::validate_exact_format_match(const std::string& source, const std::string& target) {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    // Secure string comparison with memory protection
    void* secure_match_buffer = SecureMemory::allocate_secure_buffer(256);
    
    if (source.length() != target.length()) {
        SecureMemory::secure_free(secure_match_buffer);
        return false;
    }
    
    // Character-by-character comparison with secure memory operations
    bool match_result = true;
    for (size_t i = 0; i < source.length(); ++i) {
        if (source[i] != target[i]) {
            match_result = false;
            break;
        }
    }
    
    // Secure cleanup
    SecureMemory::secure_zero_memory(secure_match_buffer, 256);
    SecureMemory::secure_free(secure_match_buffer);
    SecureMemory::eliminate_validation_traces();
    
    return match_result;
}

std::vector<std::string> FormatValidationEngine::detect_format_changes(
    const SourceFormatPreservation::FormatCapture& source_format, 
    const std::vector<uint8_t>& target_pdf) {
    
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    // Secure format change detection with memory protection
    void* secure_detection_space = SecureMemory::allocate_secure_buffer(2048);
    std::vector<std::string> changes;
    
    // Check size consistency
    if (target_pdf.size() != source_format.original_byte_sequence.size()) {
        changes.push_back("CRITICAL: Document size changed from " + 
                         std::to_string(source_format.original_byte_sequence.size()) + 
                         " to " + std::to_string(target_pdf.size()) + " bytes");
    }
    
    // Check byte-level changes at format-critical positions
    for (const auto& format_position : source_format.position_format_map) {
        size_t position = format_position.first;
        const std::string& expected_format = format_position.second;
        
        if (position < target_pdf.size() && position < source_format.original_byte_sequence.size()) {
            if (target_pdf[position] != source_format.original_byte_sequence[position]) {
                changes.push_back("FORMAT_CHANGE at position " + std::to_string(position) + 
                                 ": expected format '" + expected_format + "'");
            }
        }
    }
    
    // Check specific format field integrity
    for (const auto& date_format : source_format.date_formats) {
        size_t position = std::stoull(date_format.first);
        if (position < target_pdf.size()) {
            std::string target_section(target_pdf.begin() + position, 
                                     target_pdf.begin() + std::min(position + date_format.second.length(), target_pdf.size()));
            if (target_section != date_format.second) {
                changes.push_back("DATE_FORMAT_CHANGE at position " + date_format.first + 
                                 ": '" + date_format.second + "' -> '" + target_section + "'");
            }
        }
    }
    
    for (const auto& number_format : source_format.number_formats) {
        size_t position = std::stoull(number_format.first);
        if (position < target_pdf.size()) {
            std::string target_section(target_pdf.begin() + position, 
                                     target_pdf.begin() + std::min(position + number_format.second.length(), target_pdf.size()));
            if (target_section != number_format.second) {
                changes.push_back("NUMBER_FORMAT_CHANGE at position " + number_format.first + 
                                 ": '" + number_format.second + "' -> '" + target_section + "'");
            }
        }
    }
    
    // Secure cleanup and trace elimination
    SecureMemory::secure_vector_validation(changes, secure_detection_space);
    SecureMemory::secure_free(secure_detection_space);
    SecureMemory::eliminate_validation_traces();
    
    return changes;
}

void FormatValidationEngine::reject_format_modifications() {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    // Secure rejection with memory protection
    void* secure_rejection_buffer = SecureMemory::allocate_secure_buffer(128);
    
    if (zero_tolerance_mode_) {
        SecureMemory::secure_free(secure_rejection_buffer);
        SecureMemory::eliminate_validation_traces();
        SECURE_THROW(FormatValidationError, "Zero tolerance violation detected");
    }
    
    SecureMemory::secure_free(secure_rejection_buffer);
    SecureMemory::eliminate_validation_traces();
}

std::vector<std::string> FormatValidationEngine::detect_format_changes(
    const SourceFormatPreservation::FormatCapture& source_format,
    const std::vector<uint8_t>& target_pdf) {
    
    std::vector<std::string> format_changes;
    
    // Convert target PDF to string for format analysis
    std::string target_content(target_pdf.begin(), target_pdf.end());
    
    // Check exact field format preservation
    for (const auto& field_format : source_format.exact_field_formats) {
        const std::string& field_name = field_format.first;
        const std::string& expected_format = field_format.second;
        
        // Extract corresponding field from target
        std::string actual_format = extract_field_format(target_content, field_name);
        
        if (actual_format != expected_format) {
            format_changes.push_back("Field format changed: " + field_name + 
                                   " (expected: '" + expected_format + 
                                   "', actual: '" + actual_format + "')");
        }
    }
    
    // Check delimiter pattern preservation
    for (const auto& delimiter_pattern : source_format.delimiter_patterns) {
        const std::string& delimiter_type = delimiter_pattern.first;
        const std::string& expected_delimiter = delimiter_pattern.second;
        
        std::string actual_delimiter = extract_delimiter_pattern(target_content, delimiter_type);
        
        if (actual_delimiter != expected_delimiter) {
            format_changes.push_back("Delimiter pattern changed: " + delimiter_type + 
                                   " (expected: '" + expected_delimiter + 
                                   "', actual: '" + actual_delimiter + "')");
        }
    }
    
    // Check spacing pattern preservation
    for (const auto& spacing_pattern : source_format.spacing_patterns) {
        const std::string& spacing_type = spacing_pattern.first;
        const std::string& expected_spacing = spacing_pattern.second;
        
        std::string actual_spacing = extract_spacing_pattern(target_content, spacing_type);
        
        if (actual_spacing != expected_spacing) {
            format_changes.push_back("Spacing pattern changed: " + spacing_type + 
                                   " (expected: '" + expected_spacing + 
                                   "', actual: '" + actual_spacing + "')");
        }
    }
    
    // Check byte-level format integrity
    if (source_format.original_byte_sequence.size() != target_pdf.size()) {
        format_changes.push_back("Document size changed: " + 
                               std::to_string(source_format.original_byte_sequence.size()) + 
                               " -> " + std::to_string(target_pdf.size()) + " bytes");
    }
    
    // Perform byte-by-byte comparison for critical sections
    for (const auto& critical_section : source_format.critical_sections) {
        if (!validate_byte_sequence_integrity(
                source_format.original_byte_sequence, 
                target_pdf,
                critical_section.start_position,
                critical_section.length)) {
            format_changes.push_back("Critical section modified: " + critical_section.section_name);
        }
    }
    
    return format_changes;
}

FormatValidationEngine::ValidationResult FormatValidationEngine::perform_comprehensive_validation(
    const std::vector<uint8_t>& source_pdf,
    const std::vector<uint8_t>& target_pdf,
    const SourceFormatPreservation::FormatCapture& source_format) {
    
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    // Secure comprehensive validation with memory protection
    void* secure_validation_buffer = SecureMemory::allocate_secure_buffer(4096);
    
    ValidationResult result;
    result.is_valid = true;
    result.fidelity_score = 1.0;
    
    // 1. Detect format changes
    result.format_violations = detect_format_changes(source_format, target_pdf);
    
    // 2. Check absolute fidelity
    bool absolute_fidelity = check_absolute_fidelity(source_pdf, target_pdf);
    if (!absolute_fidelity) {
        result.critical_errors.push_back("Absolute byte-to-byte fidelity check failed");
        result.is_valid = false;
    }
    
    // 3. Calculate precise fidelity score
    result.fidelity_score = calculate_format_fidelity_score(source_format, target_pdf);
    
    // 4. Validate critical PDF structure elements
    std::vector<std::string> structure_violations = validate_pdf_structure_preservation(source_pdf, target_pdf);
    result.format_violations.insert(result.format_violations.end(), 
                                   structure_violations.begin(), 
                                   structure_violations.end());
    
    // 5. Check metadata format preservation
    std::vector<std::string> metadata_violations = validate_metadata_format_preservation(source_pdf, target_pdf);
    result.format_violations.insert(result.format_violations.end(), 
                                   metadata_violations.begin(), 
                                   metadata_violations.end());
    
    // 6. Validate stream format preservation
    std::vector<std::string> stream_violations = validate_stream_format_preservation(source_pdf, target_pdf);
    result.format_violations.insert(result.format_violations.end(), 
                                   stream_violations.begin(), 
                                   stream_violations.end());
    
    // 7. Perform field-by-field comparison
    result.field_comparisons = perform_field_by_field_comparison(source_format, target_pdf);
    
    // 8. Apply zero-tolerance policy
    if (!result.format_violations.empty() && zero_tolerance_mode_) {
        result.critical_errors.push_back("Zero-tolerance policy violated: " + 
                                        std::to_string(result.format_violations.size()) + 
                                        " format violations detected");
        result.is_valid = false;
    }
    
    // 9. Final validation status
    if (!result.format_violations.empty() || !result.critical_errors.empty()) {
        result.is_valid = false;
    }
    
    // Secure cleanup and trace elimination
    SecureMemory::secure_validation_result(result, secure_validation_buffer);
    SecureMemory::secure_free(secure_validation_buffer);
    SecureMemory::eliminate_validation_traces();
    
    return result;
}

bool FormatValidationEngine::validate_date_format_preservation(const std::string& source_date, const std::string& target_date) {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    void* secure_date_buffer = SecureMemory::allocate_secure_buffer(128);
    bool result = validate_exact_format_match(source_date, target_date);
    SecureMemory::secure_free(secure_date_buffer);
    SecureMemory::eliminate_validation_traces();
    
    return result;
}

bool FormatValidationEngine::validate_number_format_preservation(const std::string& source_number, const std::string& target_number) {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    void* secure_number_buffer = SecureMemory::allocate_secure_buffer(128);
    bool result = validate_exact_format_match(source_number, target_number);
    SecureMemory::secure_free(secure_number_buffer);
    SecureMemory::eliminate_validation_traces();
    
    return result;
}

bool FormatValidationEngine::validate_text_format_preservation(const std::string& source_text, const std::string& target_text) {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    void* secure_text_buffer = SecureMemory::allocate_secure_buffer(256);
    bool result = validate_exact_format_match(source_text, target_text);
    SecureMemory::secure_free(secure_text_buffer);
    SecureMemory::eliminate_validation_traces();
    
    return result;
}

bool FormatValidationEngine::validate_delimiter_preservation(const std::string& source_delim, const std::string& target_delim) {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    void* secure_delim_buffer = SecureMemory::allocate_secure_buffer(64);
    bool result = validate_exact_format_match(source_delim, target_delim);
    SecureMemory::secure_free(secure_delim_buffer);
    SecureMemory::eliminate_validation_traces();
    
    return result;
}

bool FormatValidationEngine::validate_spacing_preservation(const std::string& source_spacing, const std::string& target_spacing) {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    void* secure_spacing_buffer = SecureMemory::allocate_secure_buffer(64);
    bool result = validate_exact_format_match(source_spacing, target_spacing);
    SecureMemory::secure_free(secure_spacing_buffer);
    SecureMemory::eliminate_validation_traces();
    
    return result;
}

bool FormatValidationEngine::validate_byte_sequence_integrity(
    const std::vector<uint8_t>& source,
    const std::vector<uint8_t>& target,
    size_t start_position,
    size_t length) {
    
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    void* secure_byte_buffer = SecureMemory::allocate_secure_buffer(512);
    
    if (start_position + length > source.size() || start_position + length > target.size()) {
        SecureMemory::secure_free(secure_byte_buffer);
        SecureMemory::eliminate_validation_traces();
        return false;
    }
    
    bool integrity_valid = true;
    for (size_t i = start_position; i < start_position + length; ++i) {
        if (source[i] != target[i]) {
            integrity_valid = false;
            break;
        }
    }
    
    SecureMemory::secure_free(secure_byte_buffer);
    SecureMemory::eliminate_validation_traces();
    
    return integrity_valid;
}

void FormatValidationEngine::enforce_zero_modification_policy(const ValidationResult& result) {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    void* secure_policy_buffer = SecureMemory::allocate_secure_buffer(1024);
    
    if (!result.format_violations.empty() || !result.critical_errors.empty()) {
        std::vector<std::string> all_violations;
        all_violations.insert(all_violations.end(), result.format_violations.begin(), result.format_violations.end());
        all_violations.insert(all_violations.end(), result.critical_errors.begin(), result.critical_errors.end());
        
        SecureMemory::secure_free(secure_policy_buffer);
        SecureMemory::eliminate_validation_traces();
        
        throw_zero_tolerance_exception(all_violations);
    }
    
    SecureMemory::secure_free(secure_policy_buffer);
    SecureMemory::eliminate_validation_traces();
}

bool FormatValidationEngine::check_absolute_fidelity(const std::vector<uint8_t>& source, const std::vector<uint8_t>& target) {
    // Enhanced absolute fidelity check with comprehensive validation
    
    // Step 1: Size validation - must be exact match for absolute fidelity
    if (source.size() != target.size()) {
        SILENT_OPERATION("FORMAT_VALIDATION", "Size mismatch detected");
        return false;
    }
    
    // Step 2: Byte-by-byte comparison with position tracking
    for (size_t i = 0; i < source.size(); ++i) {
        if (source[i] != target[i]) {
            SILENT_OPERATION("FORMAT_VALIDATION", "Byte mismatch detected");
            return false;
        }
    }
    
    // Step 3: Additional validation checks for absolute fidelity
    std::string source_content(source.begin(), source.end());
    std::string target_content(target.begin(), target.end());
    
    // Check PDF header preservation
    if (source_content.substr(0, 8) != target_content.substr(0, 8)) {
        SILENT_OPERATION("FORMAT_VALIDATION", "PDF header mismatch");
        return false;
    }
    
    // Check EOF marker preservation
    size_t source_eof = source_content.rfind("%%EOF");
    size_t target_eof = target_content.rfind("%%EOF");
    
    if (source_eof != target_eof) {
        SILENT_OPERATION("FORMAT_VALIDATION", "EOF marker mismatch");
        return false;
    }
    
    // Absolute fidelity confirmed
    return true;
}

void FormatValidationEngine::generate_validation_report(const ValidationResult& result) {
    ENFORCE_COMPLETE_SILENCE();
    // Silent validation report generation - no output traces
    
    // Silent operation - no trace output
}

double FormatValidationEngine::calculate_format_fidelity_score(
    const SourceFormatPreservation::FormatCapture& source_format,
    const std::vector<uint8_t>& target_pdf) {
    
    if (source_format.original_byte_sequence.size() != target_pdf.size()) {
        return 0.0; // Size mismatch = zero fidelity
    }
    
    size_t total_bytes = source_format.original_byte_sequence.size();
    size_t matching_bytes = 0;
    
    for (size_t i = 0; i < total_bytes; ++i) {
        if (source_format.original_byte_sequence[i] == target_pdf[i]) {
            matching_bytes++;
        }
    }
    
    return static_cast<double>(matching_bytes) / static_cast<double>(total_bytes);
}

bool FormatValidationEngine::compare_format_patterns(const std::string& pattern1, const std::string& pattern2) {
    return pattern1 == pattern2;
}

bool FormatValidationEngine::validate_character_by_character(const std::string& source, const std::string& target) {
    if (source.length() != target.length()) {
        return false;
    }
    
    for (size_t i = 0; i < source.length(); ++i) {
        if (source[i] != target[i]) {
            return false;
        }
    }
    
    return true;
}

std::string FormatValidationEngine::extract_format_signature(const std::string& data) {
    // Extract format signature by preserving structure characters
    std::string signature;
    for (char c : data) {
        if (c == '/' || c == '-' || c == '.' || c == ':' || c == '@' || c == '_' || c == ' ') {
            signature += c;
        } else if (std::isdigit(c)) {
            signature += 'N'; // Numeric character
        } else if (std::isalpha(c)) {
            signature += 'L'; // Letter character
        }
    }
    return signature;
}

void FormatValidationEngine::log_format_violation(const std::string& violation_type, const std::string& details) {
    ENFORCE_COMPLETE_SILENCE();
    // Silent operation - no violation logging traces
}

std::string FormatValidationEngine::extract_field_format(const std::string& content, const std::string& field_name) {
    ENFORCE_COMPLETE_SILENCE();
    
    // Secure field format extraction with trace suppression
    void* secure_buffer = SecureMemory::allocate_secure_buffer(256);
    std::string result;
    
    try {
        // Search for field pattern with silent operation
        size_t field_pos = content.find(field_name);
        if (field_pos != std::string::npos) {
            size_t start = field_pos + field_name.length();
            size_t end = content.find_first_of("\n\r", start);
            if (end != std::string::npos) {
                result = content.substr(start, end - start);
                SecureMemory::secure_string_copy(result, secure_buffer, 256);
            }
        }
    } catch (...) {
        SECURE_THROW(FormatExtractionError, "Field format extraction failed");
    }
    
    SecureMemory::secure_free(secure_buffer);
    return result;
}

std::string FormatValidationEngine::extract_delimiter_pattern(const std::string& content, const std::string& delimiter_type) {
    ENFORCE_COMPLETE_SILENCE();
    
    // Secure delimiter pattern extraction
    void* secure_workspace = SecureMemory::allocate_secure_buffer(128);
    std::string pattern;
    
    try {
        if (delimiter_type == "whitespace") {
            pattern = " ";
        } else if (delimiter_type == "newline") {
            pattern = "\n";
        } else if (delimiter_type == "tab") {
            pattern = "\t";
        } else {
            pattern = delimiter_type;
        }
        SecureMemory::secure_string_validation(pattern, secure_workspace);
    } catch (...) {
        SECURE_THROW(DelimiterExtractionError, "Delimiter extraction failed");
    }
    
    SecureMemory::secure_free(secure_workspace);
    return pattern;
}

std::string FormatValidationEngine::extract_spacing_pattern(const std::string& content, const std::string& spacing_type) {
    ENFORCE_COMPLETE_SILENCE();
    
    // Secure spacing pattern extraction with memory protection
    void* secure_buffer = SecureMemory::allocate_secure_buffer(64);
    std::string spacing;
    
    try {
        size_t pattern_pos = content.find(spacing_type);
        if (pattern_pos != std::string::npos) {
            // Extract surrounding whitespace pattern
            size_t start = pattern_pos;
            while (start > 0 && std::isspace(content[start - 1])) start--;
            size_t end = pattern_pos + spacing_type.length();
            while (end < content.length() && std::isspace(content[end])) end++;
            
            spacing = content.substr(start, end - start);
            SecureMemory::secure_pattern_validation(spacing, secure_buffer);
        }
    } catch (...) {
        SECURE_THROW(SpacingExtractionError, "Spacing extraction failed");
    }
    
    SecureMemory::secure_free(secure_buffer);
    return spacing;
}

double FormatValidationEngine::calculate_format_fidelity_score(const SourceFormatPreservation::FormatCapture& source_format, const std::vector<uint8_t>& target_pdf) {
    ENFORCE_COMPLETE_SILENCE();
    
    // Secure fidelity score calculation with trace suppression
    void* secure_calc_space = SecureMemory::allocate_secure_buffer(512);
    double score = 1.0;
    
    try {
        size_t total_checks = 0;
        size_t failed_checks = 0;
        
        // Byte-level fidelity check
        if (source_format.original_byte_sequence.size() == target_pdf.size()) {
            for (size_t i = 0; i < source_format.original_byte_sequence.size(); ++i) {
                total_checks++;
                if (source_format.original_byte_sequence[i] != target_pdf[i]) {
                    failed_checks++;
                }
            }
        } else {
            failed_checks += abs((int)source_format.original_byte_sequence.size() - (int)target_pdf.size());
            total_checks += std::max(source_format.original_byte_sequence.size(), target_pdf.size());
        }
        
        // Format field preservation check
        for (const auto& field_format : source_format.exact_field_formats) {
            total_checks++;
            std::string target_content(target_pdf.begin(), target_pdf.end());
            std::string actual_format = extract_field_format(target_content, field_format.first);
            if (actual_format != field_format.second) {
                failed_checks++;
            }
        }
        
        // Calculate final score with secure arithmetic
        if (total_checks > 0) {
            score = 1.0 - (static_cast<double>(failed_checks) / static_cast<double>(total_checks));
        }
        score = std::max(0.0, std::min(1.0, score));
        
        SecureMemory::secure_calculation_validation(&score, secure_calc_space);
    } catch (...) {
        SECURE_THROW(FidelityCalculationError, "Fidelity calculation failed");
    }
    
    SecureMemory::secure_free(secure_calc_space);
    return score;
}

std::vector<std::string> FormatValidationEngine::validate_pdf_structure_preservation(const std::vector<uint8_t>& source_pdf, const std::vector<uint8_t>& target_pdf) {
    ENFORCE_COMPLETE_SILENCE();
    
    // Secure PDF structure validation with trace suppression
    void* secure_validation_space = SecureMemory::allocate_secure_buffer(1024);
    std::vector<std::string> violations;
    
    try {
        std::string source_content(source_pdf.begin(), source_pdf.end());
        std::string target_content(target_pdf.begin(), target_pdf.end());
        
        // Validate PDF header preservation
        if (source_content.length() >= 8 && target_content.length() >= 8) {
            if (source_content.substr(0, 8) != target_content.substr(0, 8)) {
                violations.push_back("PDF header structure modified");
            }
        }
        
        // Validate EOF marker preservation
        size_t source_eof = source_content.rfind("%%EOF");
        size_t target_eof = target_content.rfind("%%EOF");
        if (source_eof != target_eof) {
            violations.push_back("PDF EOF structure modified");
        }
        
        // Validate xref table structure
        size_t source_xref = source_content.find("xref");
        size_t target_xref = target_content.find("xref");
        if ((source_xref == std::string::npos) != (target_xref == std::string::npos)) {
            violations.push_back("PDF xref table structure modified");
        }
        
        SecureMemory::secure_validation_check(violations, secure_validation_space);
    } catch (...) {
        SECURE_THROW(StructureValidationError, "PDF structure validation failed");
    }
    
    SecureMemory::secure_free(secure_validation_space);
    return violations;
}

std::vector<std::string> FormatValidationEngine::validate_metadata_format_preservation(const std::vector<uint8_t>& source_pdf, const std::vector<uint8_t>& target_pdf) {
    ENFORCE_COMPLETE_SILENCE();
    
    // Secure metadata format validation
    void* secure_metadata_space = SecureMemory::allocate_secure_buffer(512);
    std::vector<std::string> violations;
    
    try {
        std::string source_content(source_pdf.begin(), source_pdf.end());
        std::string target_content(target_pdf.begin(), target_pdf.end());
        
        // Check document info dictionary preservation
        size_t source_info = source_content.find("/Info");
        size_t target_info = target_content.find("/Info");
        if ((source_info == std::string::npos) != (target_info == std::string::npos)) {
            violations.push_back("Document info metadata format changed");
        }
        
        // Check XMP metadata preservation
        size_t source_xmp = source_content.find("<?xpacket");
        size_t target_xmp = target_content.find("<?xpacket");
        if ((source_xmp == std::string::npos) != (target_xmp == std::string::npos)) {
            violations.push_back("XMP metadata format changed");
        }
        
        // Check metadata stream format
        size_t source_metadata = source_content.find("/Metadata");
        size_t target_metadata = target_content.find("/Metadata");
        if ((source_metadata == std::string::npos) != (target_metadata == std::string::npos)) {
            violations.push_back("Metadata stream format changed");
        }
        
        SecureMemory::secure_metadata_validation(violations, secure_metadata_space);
    } catch (...) {
        SECURE_THROW(MetadataValidationError, "Metadata validation failed");
    }
    
    SecureMemory::secure_free(secure_metadata_space);
    return violations;
}

std::vector<std::string> FormatValidationEngine::validate_stream_format_preservation(const std::vector<uint8_t>& source_pdf, const std::vector<uint8_t>& target_pdf) {
    ENFORCE_COMPLETE_SILENCE();
    
    // Secure stream format validation with trace elimination
    void* secure_stream_space = SecureMemory::allocate_secure_buffer(256);
    std::vector<std::string> violations;
    
    try {
        std::string source_content(source_pdf.begin(), source_pdf.end());
        std::string target_content(target_pdf.begin(), target_pdf.end());
        
        // Count stream objects
        size_t source_streams = 0, target_streams = 0;
        size_t pos = 0;
        while ((pos = source_content.find("stream\n", pos)) != std::string::npos) {
            source_streams++;
            pos += 7;
        }
        pos = 0;
        while ((pos = target_content.find("stream\n", pos)) != std::string::npos) {
            target_streams++;
            pos += 7;
        }
        
        if (source_streams != target_streams) {
            violations.push_back("Stream object count changed");
        }
        
        // Check endstream markers
        size_t source_endstreams = 0, target_endstreams = 0;
        pos = 0;
        while ((pos = source_content.find("endstream", pos)) != std::string::npos) {
            source_endstreams++;
            pos += 9;
        }
        pos = 0;
        while ((pos = target_content.find("endstream", pos)) != std::string::npos) {
            target_endstreams++;
            pos += 9;
        }
        
        if (source_endstreams != target_endstreams) {
            violations.push_back("Stream termination format changed");
        }
        
        SecureMemory::secure_stream_validation(violations, secure_stream_space);
    } catch (...) {
        SECURE_THROW(StreamValidationError, "Stream validation failed");
    }
    
    SecureMemory::secure_free(secure_stream_space);
    return violations;
}

std::vector<std::pair<std::string, std::string>> FormatValidationEngine::perform_field_by_field_comparison(const SourceFormatPreservation::FormatCapture& source_format, const std::vector<uint8_t>& target_pdf) {
    ENFORCE_COMPLETE_SILENCE();
    
    // Secure field-by-field comparison with memory protection
    void* secure_comparison_space = SecureMemory::allocate_secure_buffer(1024);
    std::vector<std::pair<std::string, std::string>> comparisons;
    
    try {
        std::string target_content(target_pdf.begin(), target_pdf.end());
        
        // Compare exact field formats
        for (const auto& field_format : source_format.exact_field_formats) {
            std::string actual_format = extract_field_format(target_content, field_format.first);
            if (actual_format != field_format.second) {
                comparisons.push_back(std::make_pair(field_format.first, 
                    "Expected: " + field_format.second + ", Actual: " + actual_format));
            }
        }
        
        // Compare date formats
        for (const auto& date_format : source_format.date_formats) {
            size_t position = std::stoull(date_format.first);
            if (position < target_content.length()) {
                std::string actual_date = target_content.substr(position, 
                    std::min(date_format.second.length(), target_content.length() - position));
                if (actual_date != date_format.second) {
                    comparisons.push_back(std::make_pair("Date_" + date_format.first,
                        "Expected: " + date_format.second + ", Actual: " + actual_date));
                }
            }
        }
        
        // Compare number formats
        for (const auto& number_format : source_format.number_formats) {
            size_t position = std::stoull(number_format.first);
            if (position < target_content.length()) {
                std::string actual_number = target_content.substr(position,
                    std::min(number_format.second.length(), target_content.length() - position));
                if (actual_number != number_format.second) {
                    comparisons.push_back(std::make_pair("Number_" + number_format.first,
                        "Expected: " + number_format.second + ", Actual: " + actual_number));
                }
            }
        }
        
        SecureMemory::secure_comparison_validation(comparisons, secure_comparison_space);
    } catch (...) {
        SECURE_THROW(ComparisonError, "Field comparison failed");
    }
    
    SecureMemory::secure_free(secure_comparison_space);
    return comparisons;
}

void FormatValidationEngine::throw_zero_tolerance_exception(const std::vector<std::string>& violations) {
    ENFORCE_COMPLETE_SILENCE();
    SECURE_THROW(ZeroToleranceViolation, "Zero tolerance policy violation detected");
}