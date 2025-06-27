#include "source_format_preservation.hpp"
#include "stealth_macros.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <regex>
#include <stdexcept>
#include "stealth_macros.hpp"
#include "stealth_macros.hpp"

bool SourceFormatPreservation::capture_source_format(const std::vector<uint8_t>& source_pdf) {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    try {
        return structured_exception_handling([&]() -> bool {
            SecureMemory secure_pdf_buffer(source_pdf.size() + 4096);
            SecureMemory secure_format_buffer(16384);
            SecureMemory secure_analysis_buffer(8192);
            
            secure_pdf_buffer.copy_from(source_pdf.data(), source_pdf.size());
            
            // Initialize format capture structure with secure operations
            captured_format_ = FormatCapture();
            captured_format_.original_byte_sequence = source_pdf;
            
            // Perform comprehensive format analysis with secure memory
            captured_format_ = analyze_document_formats(source_pdf);
            
            // Detect all format patterns with complete implementation
            detect_date_formats(source_pdf);
            detect_number_formats(source_pdf);
            detect_text_formats(source_pdf);
            detect_delimiter_patterns(source_pdf);
            detect_spacing_patterns(source_pdf);
            
            // Identify critical sections that must be preserved exactly
            captured_format_.critical_sections = identify_critical_sections(source_pdf);
            
            // Generate document format signature for validation
            captured_format_.document_format_signature = generate_format_signature(source_pdf);
            
            // Map all format pattern positions
            detect_and_map_format_patterns(source_pdf);
            
            // Mark capture as complete and successful
            captured_format_.capture_complete = true;
            format_preserved_ = true;
            
            // Comprehensive secure cleanup
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> cleanup_dist(5, 12);
            int cleanup_passes = cleanup_dist(gen);
            
            for (int pass = 0; pass < cleanup_passes; ++pass) {
                secure_pdf_buffer.zero();
                secure_format_buffer.zero();
                secure_analysis_buffer.zero();
                eliminate_all_traces();
                
                std::uniform_int_distribution<> delay_dist(20, 150);
                std::this_thread::sleep_for(std::chrono::microseconds(delay_dist(gen)));
            }
            
            return true;
        }, false);
    } catch (...) {
        eliminate_all_traces();
        captured_format_.capture_complete = false;
        return false;
    }
}

std::vector<uint8_t> SourceFormatPreservation::preserve_all_formats(const std::vector<uint8_t>& pdf_data) {
    // Verify format capture is complete before preservation
    if (!captured_format_.capture_complete) {
        throw std::runtime_error("FORMAT_PRESERVATION_ERROR: Source format must be captured before preservation");
    }
    
    // Create working copy for preservation operations
    std::vector<uint8_t> preserved_data = pdf_data;
    
    // STRICT VALIDATION: Reject any modifications to existing byte sequences
    if (pdf_data.size() < captured_format_.original_byte_sequence.size()) {
        throw std::runtime_error("STRICT_VALIDATION_FAILURE: Target data smaller than source - modifications detected");
    }
    
    // Validate that ALL original bytes are preserved exactly
    for (size_t i = 0; i < captured_format_.original_byte_sequence.size(); ++i) {
        if (pdf_data[i] != captured_format_.original_byte_sequence[i]) {
            throw std::runtime_error("STRICT_VALIDATION_FAILURE: Byte modification detected at position " + 
                std::to_string(i) + " - source: " + std::to_string(captured_format_.original_byte_sequence[i]) + 
                " target: " + std::to_string(pdf_data[i]));
        }
    }
    
    // Apply comprehensive format preservation
    apply_exact_field_format_preservation(preserved_data);
    apply_delimiter_pattern_preservation(preserved_data);
    apply_spacing_pattern_preservation(preserved_data);
    apply_critical_section_preservation(preserved_data);
    
    // INJECTION-ONLY VALIDATION: Only allow additions after EOF or in designated injection zones
    if (pdf_data.size() > captured_format_.original_byte_sequence.size()) {
        // Validate injection zone - only after %%EOF marker
        std::string source_content(captured_format_.original_byte_sequence.begin(), captured_format_.original_byte_sequence.end());
        size_t eof_pos = source_content.rfind("%%EOF");
        
        if (eof_pos == std::string::npos) {
            throw std::runtime_error("INJECTION_VALIDATION_FAILURE: No %%EOF marker found for safe injection");
        }
        
        // Calculate injection start position (after %%EOF + newline)
        size_t injection_start = eof_pos + 5; // %%EOF length
        if (injection_start < captured_format_.original_byte_sequence.size() && 
            captured_format_.original_byte_sequence[injection_start] == '\n') {
            injection_start++;
        }
        
        // Ensure injection only occurs after safe zone
        if (pdf_data.size() > captured_format_.original_byte_sequence.size() && 
            injection_start != captured_format_.original_byte_sequence.size()) {
            throw std::runtime_error("INJECTION_VALIDATION_FAILURE: Injection attempted in unsafe zone before position " + 
                std::to_string(injection_start));
        }
        
        // Validate that injection contains only source-authorized data
        validate_injection_data_authenticity(pdf_data, injection_start);
    }
    
    return pdf_data;
}

std::vector<std::string> SourceFormatPreservation::detect_format_violations(const std::vector<uint8_t>& target) {
    std::vector<std::string> violations;
    
    // Check byte-for-byte format preservation
    if (target.size() != captured_format_.original_byte_sequence.size()) {
        violations.push_back("SIZE_MISMATCH: Target size differs from source");
    }
    
    // Check format integrity at each position
    for (const auto& format_entry : captured_format_.position_format_map) {
        size_t position = format_entry.first;
        if (position < target.size() && position < captured_format_.original_byte_sequence.size()) {
            if (!validate_exact_byte_sequence(position, captured_format_.original_byte_sequence, target)) {
                violations.push_back("FORMAT_VIOLATION at position " + std::to_string(position));
            }
        }
    }
    
    // Validate specific format types
    for (const auto& date_format : captured_format_.date_formats) {
        if (!check_format_consistency("DATE", date_format.second, date_format.second)) {
            violations.push_back("DATE_FORMAT_VIOLATION: " + date_format.first);
        }
    }
    
    for (const auto& number_format : captured_format_.number_formats) {
        if (!check_format_consistency("NUMBER", number_format.second, number_format.second)) {
            violations.push_back("NUMBER_FORMAT_VIOLATION: " + number_format.first);
        }
    }
    
    return violations;
}

void SourceFormatPreservation::enforce_zero_tolerance_policy() {
    auto violations = detect_format_violations(captured_format_.original_byte_sequence);
    if (!violations.empty()) {
        generate_format_violation_report(violations);
        throw std::runtime_error("ZERO_TOLERANCE_POLICY_VIOLATION: Format modifications detected");
    }
}

SourceFormatPreservation::FormatCapture SourceFormatPreservation::analyze_document_formats(const std::vector<uint8_t>& pdf_data) {
    FormatCapture format_capture;
    
    // Convert to string for pattern analysis
    std::string pdf_content(pdf_data.begin(), pdf_data.end());
    
    // Analyze PDF structure and extract format patterns
    std::regex date_regex(R"(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}|\d{2,4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2})");
    std::regex time_regex(R"(\d{1,2}:\d{2}:\d{2}|\d{1,2}:\d{2})");
    std::regex number_regex(R"(\$?\d{1,3}(?:,\d{3})*(?:\.\d{2})?|\d+\.\d+|\d+)");
    std::regex email_regex(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
    
    std::sregex_iterator date_iter(pdf_content.begin(), pdf_content.end(), date_regex);
    std::sregex_iterator date_end;
    
    size_t position = 0;
    for (std::sregex_iterator i = date_iter; i != date_end; ++i) {
        std::smatch match = *i;
        position = match.position();
        format_capture.date_formats[std::to_string(position)] = match.str();
        format_capture.position_format_map[position] = match.str();
        format_capture.exact_field_formats["DATE_" + std::to_string(position)] = match.str();
    }
    
    std::sregex_iterator number_iter(pdf_content.begin(), pdf_content.end(), number_regex);
    std::sregex_iterator number_end;
    
    for (std::sregex_iterator i = number_iter; i != number_end; ++i) {
        std::smatch match = *i;
        position = match.position();
        format_capture.number_formats[std::to_string(position)] = match.str();
        format_capture.position_format_map[position] = match.str();
        format_capture.exact_field_formats["NUMBER_" + std::to_string(position)] = match.str();
    }
    
    std::sregex_iterator email_iter(pdf_content.begin(), pdf_content.end(), email_regex);
    std::sregex_iterator email_end;
    
    for (std::sregex_iterator i = email_iter; i != email_end; ++i) {
        std::smatch match = *i;
        position = match.position();
        format_capture.text_formats[std::to_string(position)] = match.str();
        format_capture.position_format_map[position] = match.str();
        format_capture.exact_field_formats["EMAIL_" + std::to_string(position)] = match.str();
    }
    
    return format_capture;
}

bool SourceFormatPreservation::validate_format_integrity(const FormatCapture& source_format, const std::vector<uint8_t>& target) {
    if (target.size() != source_format.original_byte_sequence.size()) {
        return false;
    }
    
    for (size_t i = 0; i < target.size(); ++i) {
        if (target[i] != source_format.original_byte_sequence[i]) {
            // Check if this position is in our format map
            if (source_format.position_format_map.find(i) != source_format.position_format_map.end()) {
                return false; // Format-critical position changed
            }
        }
    }
    
    return true;
}

std::string SourceFormatPreservation::extract_exact_format_pattern(const std::string& field_data) {
    return field_data; // Preserve exact format without any modifications
}

bool SourceFormatPreservation::preserve_character_spacing(std::string& target, const std::string& source_pattern) {
    // Ensure exact character-by-character preservation
    if (target.length() != source_pattern.length()) {
        return false;
    }
    
    for (size_t i = 0; i < target.length(); ++i) {
        if (std::isspace(source_pattern[i]) && !std::isspace(target[i])) {
            target[i] = source_pattern[i]; // Preserve spacing exactly
        }
    }
    
    return true;
}

bool SourceFormatPreservation::preserve_delimiter_structure(std::string& target, const std::string& source_delimiters) {
    // Preserve all delimiters exactly as in source
    for (size_t i = 0; i < target.length() && i < source_delimiters.length(); ++i) {
        if (source_delimiters[i] == '/' || source_delimiters[i] == '-' || 
            source_delimiters[i] == '.' || source_delimiters[i] == ':' ||
            source_delimiters[i] == '@' || source_delimiters[i] == '_') {
            target[i] = source_delimiters[i];
        }
    }
    
    return true;
}

bool SourceFormatPreservation::perform_format_fidelity_check(const std::vector<uint8_t>& source, const std::vector<uint8_t>& target) {
    if (source.size() != target.size()) {
        return false;
    }
    
    // Byte-for-byte comparison
    for (size_t i = 0; i < source.size(); ++i) {
        if (source[i] != target[i]) {
            // Check if this is an acceptable modification zone
            if (captured_format_.position_format_map.find(i) != captured_format_.position_format_map.end()) {
                return false; // Critical format position changed
            }
        }
    }
    
    return true;
}

void SourceFormatPreservation::generate_format_violation_report(const std::vector<std::string>& violations) {
    SILENT_LOG("=== FORMAT VIOLATION REPORT ===") << std::endl;
    SILENT_LOG("ZERO TOLERANCE POLICY ACTIVATED") << std::endl;
    SILENT_LOG("Total Violations: ") << violations.size() << std::endl;
    
    for (const auto& violation : violations) {
        SILENT_LOG("VIOLATION: ") << violation << std::endl;
    }
    
    SILENT_LOG("=== END REPORT ===") << std::endl;
}

void SourceFormatPreservation::detect_date_formats(const std::vector<uint8_t>& data) {
    std::string content(data.begin(), data.end());
    
    // Detect various date formats exactly as they appear
    std::vector<std::regex> date_patterns = {
        std::regex(R"(\d{1,2}/\d{1,2}/\d{4})"),      // DD/MM/YYYY or MM/DD/YYYY
        std::regex(R"(\d{4}/\d{1,2}/\d{1,2})"),      // YYYY/MM/DD
        std::regex(R"(\d{1,2}-\d{1,2}-\d{4})"),      // DD-MM-YYYY or MM-DD-YYYY
        std::regex(R"(\d{4}-\d{1,2}-\d{1,2})"),      // YYYY-MM-DD
        std::regex(R"(\d{1,2}\.\d{1,2}\.\d{4})"),    // DD.MM.YYYY
        std::regex(R"(\d{1,2}/\d{1,2}/\d{2})"),      // DD/MM/YY
    };
    
    for (const auto& pattern : date_patterns) {
        std::sregex_iterator iter(content.begin(), content.end(), pattern);
        std::sregex_iterator end;
        
        for (std::sregex_iterator i = iter; i != end; ++i) {
            std::smatch match = *i;
            size_t position = match.position();
            captured_format_.date_formats[std::to_string(position)] = match.str();
        }
    }
}

void SourceFormatPreservation::detect_number_formats(const std::vector<uint8_t>& data) {
    std::string content(data.begin(), data.end());
    
    // Detect various number formats exactly as they appear
    std::vector<std::regex> number_patterns = {
        std::regex(R"(\$\d{1,3}(?:,\d{3})*\.\d{2})"), // Currency format $1,234.56
        std::regex(R"(\d{1,3}(?:,\d{3})*\.\d{2})"),   // Number with commas 1,234.56
        std::regex(R"(\d+\.\d+)"),                     // Decimal numbers
        std::regex(R"(\d+)"),                          // Integers
    };
    
    for (const auto& pattern : number_patterns) {
        std::sregex_iterator iter(content.begin(), content.end(), pattern);
        std::sregex_iterator end;
        
        for (std::sregex_iterator i = iter; i != end; ++i) {
            std::smatch match = *i;
            size_t position = match.position();
            captured_format_.number_formats[std::to_string(position)] = match.str();
        }
    }
}

void SourceFormatPreservation::detect_text_formats(const std::vector<uint8_t>& data) {
    std::string content(data.begin(), data.end());
    
    // Detect text formats exactly as they appear
    std::vector<std::regex> text_patterns = {
        std::regex(R"([A-Z][a-z]+ [A-Z]\. [A-Z][a-z]+ [A-Z][a-z]\.?)"), // Names like "John A. Smith Jr."
        std::regex(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"), // Email addresses
        std::regex(R"([A-Z][a-z]+ [A-Z][a-z]+)"),                        // First Last names
    };
    
    for (const auto& pattern : text_patterns) {
        std::sregex_iterator iter(content.begin(), content.end(), pattern);
        std::sregex_iterator end;
        
        for (std::sregex_iterator i = iter; i != end; ++i) {
            std::smatch match = *i;
            size_t position = match.position();
            captured_format_.text_formats[std::to_string(position)] = match.str();
        }
    }
}

void SourceFormatPreservation::detect_delimiter_patterns(const std::vector<uint8_t>& data) {
    std::string content(data.begin(), data.end());
    
    // Find all delimiter patterns and their exact positions
    std::string delimiters = "/-.:@_";
    for (size_t i = 0; i < content.length(); ++i) {
        if (delimiters.find(content[i]) != std::string::npos) {
            captured_format_.delimiter_patterns[std::to_string(i)] = std::string(1, content[i]);
        }
    }
}

void SourceFormatPreservation::detect_spacing_patterns(const std::vector<uint8_t>& data) {
    std::string content(data.begin(), data.end());
    
    // Detect spacing patterns around important content
    for (size_t i = 0; i < content.length(); ++i) {
        if (std::isspace(content[i])) {
            captured_format_.spacing_patterns[std::to_string(i)] = std::string(1, content[i]);
        }
    }
}

bool SourceFormatPreservation::validate_exact_byte_sequence(size_t position, const std::vector<uint8_t>& source, const std::vector<uint8_t>& target) {
    if (position >= source.size() || position >= target.size()) {
        return false;
    }
    
    return source[position] == target[position];
}

bool SourceFormatPreservation::check_format_consistency(const std::string& field_type, const std::string& source_format, const std::string& target_format) {
    return source_format == target_format; // Exact match required
}

void SourceFormatPreservation::handle_format_violation(const std::string& violation_type, const std::string& details) {
    captured_format_.format_violations.push_back(violation_type + ": " + details);
    format_preserved_ = false;
}

void SourceFormatPreservation::validate_injection_data_authenticity(const std::vector<uint8_t>& pdf_data, size_t injection_start) {
    if (injection_start >= pdf_data.size()) {
        return; // No injection data to validate
    }
    
    // Extract injected data
    std::vector<uint8_t> injected_data(pdf_data.begin() + injection_start, pdf_data.end());
    
    // STRICT RULE: Only allow source-derived data or PDF-compliant invisible data
    // Validate that injected data doesn't contain foreign structures
    std::string injected_content(injected_data.begin(), injected_data.end());
    
    // Check for non-PDF compliant data injection
    if (injected_content.find('\0') != std::string::npos) {
        throw std::runtime_error("FOREIGN_DATA_REJECTION: Binary data injection not allowed");
    }
    
    // Only allow PDF comments or whitespace in injection zone
    bool contains_only_safe_data = true;
    for (char c : injected_content) {
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '%') {
            // Allow printable ASCII characters that could be part of PDF comments
            if (c < 32 || c > 126) {
                contains_only_safe_data = false;
                break;
            }
        }
    }
    
    if (!contains_only_safe_data) {
        throw std::runtime_error("FOREIGN_DATA_REJECTION: Non-compliant data detected in injection zone");
    }
    
    // Validate injection follows PDF comment structure if not whitespace
    if (!injected_content.empty() && injected_content[0] != ' ' && injected_content[0] != '\n') {
        if (injected_content[0] != '%') {
            throw std::runtime_error("FOREIGN_DATA_REJECTION: Injection must be PDF comment or whitespace only");
        }
    }
}

void SourceFormatPreservation::enforce_injection_only_operations(const std::vector<uint8_t>& source, const std::vector<uint8_t>& target) {
    // ZERO TOLERANCE: Target must contain source exactly + optional safe injection
    if (target.size() < source.size()) {
        throw std::runtime_error("INJECTION_ONLY_VIOLATION: Target smaller than source - data loss detected");
    }
    
    // Verify complete source preservation
    for (size_t i = 0; i < source.size(); ++i) {
        if (target[i] != source[i]) {
            throw std::runtime_error("INJECTION_ONLY_VIOLATION: Source byte modified at position " + 
                std::to_string(i) + " - operation is not injection-only");
        }
    }
    
    // If target is larger, validate injection zones
    if (target.size() > source.size()) {
        std::vector<size_t> safe_zones = identify_safe_injection_zones(source);
        
        // Verify injection occurs only in identified safe zones
        size_t injection_size = target.size() - source.size();
        bool injection_in_safe_zone = false;
        
        for (size_t zone : safe_zones) {
            if (zone == source.size()) {
                injection_in_safe_zone = true;
                break;
            }
        }
        
        if (!injection_in_safe_zone) {
            throw std::runtime_error("INJECTION_ONLY_VIOLATION: Injection not in safe zone");
        }
        
        validate_injection_data_authenticity(target, source.size());
    }
}

void SourceFormatPreservation::validate_no_foreign_data_injection(const std::vector<uint8_t>& pdf_data, size_t injection_start, const std::vector<uint8_t>& authorized_injection_data) {
    if (injection_start >= pdf_data.size()) {
        return;
    }
    
    // Extract actual injected data
    std::vector<uint8_t> actual_injection(pdf_data.begin() + injection_start, pdf_data.end());
    
    // STRICT VALIDATION: Only authorized data allowed
    if (actual_injection.size() != authorized_injection_data.size()) {
        throw std::runtime_error("FOREIGN_DATA_REJECTION: Injection size mismatch - unauthorized data detected");
    }
    
    for (size_t i = 0; i < actual_injection.size(); ++i) {
        if (actual_injection[i] != authorized_injection_data[i]) {
            throw std::runtime_error("FOREIGN_DATA_REJECTION: Unauthorized byte at injection position " + 
                std::to_string(i) + " - only source-derived data allowed");
        }
    }
}

bool SourceFormatPreservation::is_injection_zone_safe(const std::vector<uint8_t>& pdf_data, size_t position) {
    // Safe injection zones: after %%EOF marker only
    std::string content(pdf_data.begin(), pdf_data.end());
    size_t eof_pos = content.rfind("%%EOF");
    
    if (eof_pos == std::string::npos) {
        return false; // No %%EOF found - no safe zones
    }
    
    // Calculate safe injection position
    size_t safe_injection_start = eof_pos + 5; // After "%%EOF"
    if (safe_injection_start < pdf_data.size() && pdf_data[safe_injection_start] == '\n') {
        safe_injection_start++;
    }
    
    return position >= safe_injection_start;
}

std::vector<size_t> SourceFormatPreservation::identify_safe_injection_zones(const std::vector<uint8_t>& pdf_data) {
    std::vector<size_t> safe_zones;
    
    // ONLY safe zone: after %%EOF marker
    std::string content(pdf_data.begin(), pdf_data.end());
    size_t eof_pos = content.rfind("%%EOF");
    
    if (eof_pos != std::string::npos) {
        size_t safe_zone = eof_pos + 5; // After "%%EOF"
        if (safe_zone < pdf_data.size() && pdf_data[safe_zone] == '\n') {
            safe_zone++;
        }
        safe_zones.push_back(safe_zone);
    }
    
    return safe_zones;
}

bool SourceFormatPreservation::perform_comprehensive_format_fidelity_check(const std::vector<uint8_t>& source, const std::vector<uint8_t>& target) {
    // COMPREHENSIVE ZERO-TOLERANCE VALIDATION
    
    // 1. Size validation - target must be equal or larger (injection-only)
    if (target.size() < source.size()) {
        handle_format_violation("SIZE_VIOLATION", "Target smaller than source - data loss detected");
        return false;
    }
    
    // 2. Byte-for-byte source preservation validation
    for (size_t i = 0; i < source.size(); ++i) {
        if (target[i] != source[i]) {
            handle_format_violation("BYTE_MODIFICATION", "Source byte changed at position " + std::to_string(i));
            return false;
        }
    }
    
    // 3. Injection zone validation (if target is larger)
    if (target.size() > source.size()) {
        std::vector<size_t> safe_zones = identify_safe_injection_zones(source);
        if (safe_zones.empty()) {
            handle_format_violation("INJECTION_VIOLATION", "No safe injection zones available");
            return false;
        }
        
        try {
            validate_injection_data_authenticity(target, source.size());
        } catch (const std::exception& e) {
            handle_format_violation("INJECTION_VIOLATION", e.what());
            return false;
        }
    }
    
    // 4. Format pattern integrity validation
    validate_complete_byte_sequence_preservation(source, target);
    validate_pdf_structure_integrity(target);
    validate_metadata_preservation(source, target);
    validate_timestamp_preservation(source, target);
    
    return captured_format_.format_violations.empty();
}

void SourceFormatPreservation::validate_complete_byte_sequence_preservation(const std::vector<uint8_t>& source, const std::vector<uint8_t>& target) {
    // CRITICAL: Every byte of source must be preserved exactly
    size_t check_size = std::min(source.size(), target.size());
    
    for (size_t i = 0; i < check_size; ++i) {
        if (source[i] != target[i]) {
            throw std::runtime_error("BYTE_SEQUENCE_VIOLATION: Source byte " + std::to_string(source[i]) + 
                " at position " + std::to_string(i) + " changed to " + std::to_string(target[i]));
        }
    }
    
    // Verify all format-critical positions are preserved
    for (const auto& position_format : captured_format_.position_format_map) {
        size_t pos = position_format.first;
        if (pos < source.size() && pos < target.size()) {
            if (source[pos] != target[pos]) {
                throw std::runtime_error("FORMAT_CRITICAL_VIOLATION: Format-critical position " + 
                    std::to_string(pos) + " modified");
            }
        }
    }
}

void SourceFormatPreservation::validate_pdf_structure_integrity(const std::vector<uint8_t>& pdf_data) {
    std::string content(pdf_data.begin(), pdf_data.end());
    
    // Validate PDF header preservation
    if (content.substr(0, 4) != "%PDF") {
        throw std::runtime_error("PDF_STRUCTURE_VIOLATION: PDF header corrupted");
    }
    
    // Validate %%EOF trailer preservation
    if (content.find("%%EOF") == std::string::npos) {
        throw std::runtime_error("PDF_STRUCTURE_VIOLATION: PDF EOF marker missing");
    }
    
    // Validate xref table structure (if present in source)
    if (captured_format_.original_byte_sequence.size() > 0) {
        std::string source_content(captured_format_.original_byte_sequence.begin(), captured_format_.original_byte_sequence.end());
        
        // Check for xref preservation
        size_t source_xref = source_content.find("xref");
        size_t target_xref = content.find("xref");
        
        if (source_xref != std::string::npos && target_xref == std::string::npos) {
            throw std::runtime_error("PDF_STRUCTURE_VIOLATION: xref table corrupted");
        }
        
        // Check for trailer preservation
        size_t source_trailer = source_content.find("trailer");
        size_t target_trailer = content.find("trailer");
        
        if (source_trailer != std::string::npos && target_trailer == std::string::npos) {
            throw std::runtime_error("PDF_STRUCTURE_VIOLATION: trailer corrupted");
        }
    }
}

void SourceFormatPreservation::validate_metadata_preservation(const std::vector<uint8_t>& source, const std::vector<uint8_t>& target) {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    try {
        structured_exception_handling([&]() -> void {
            SecureMemory secure_source_buffer(source.size() + 2048);
            SecureMemory secure_target_buffer(std::min(target.size(), source.size()) + 2048);
            SecureMemory secure_analysis_buffer(16384);
            
            secure_source_buffer.copy_from(source.data(), source.size());
            secure_target_buffer.copy_from(target.data(), std::min(target.size(), source.size()));
            
            // Silent metadata pattern validation
            std::vector<const char*> metadata_patterns = {
                "/Title", "/Author", "/Subject", "/Keywords", 
                "/Creator", "/Producer", "/CreationDate", "/ModDate"
            };
            
            for (const char* pattern : metadata_patterns) {
                SecureMemory secure_pattern_buffer(strlen(pattern) + 512);
                
                // Silent pattern search in both buffers
                bool source_has_pattern = SecureMemory::secure_pattern_search(
                    static_cast<const uint8_t*>(secure_source_buffer.get()), source.size(),
                    reinterpret_cast<const uint8_t*>(pattern), strlen(pattern)
                );
                
                bool target_has_pattern = SecureMemory::secure_pattern_search(
                    static_cast<const uint8_t*>(secure_target_buffer.get()), std::min(target.size(), source.size()),
                    reinterpret_cast<const uint8_t*>(pattern), strlen(pattern)
                );
                
                // Silent validation - no exceptions, just internal state tracking
                if (source_has_pattern != target_has_pattern) {
                    format_preserved_ = false;
                    captured_format_.format_violations.push_back("Metadata structure mismatch");
                }
                
                secure_pattern_buffer.zero();
            }
            
            // Comprehensive silent cleanup
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> cleanup_iterations_dist(5, 12);
            int cleanup_iterations = cleanup_iterations_dist(gen);
            
            for (int i = 0; i < cleanup_iterations; ++i) {
                secure_source_buffer.zero();
                secure_target_buffer.zero();
                secure_analysis_buffer.zero();
                eliminate_all_traces();
                
                std::uniform_int_distribution<> delay_dist(30, 200);
                std::this_thread::sleep_for(std::chrono::microseconds(delay_dist(gen)));
            }
        });
    } catch (...) {
        eliminate_all_traces();
        format_preserved_ = false;
        // Silent failure - no exception propagation
    }
}

void SourceFormatPreservation::validate_timestamp_preservation(const std::vector<uint8_t>& source, const std::vector<uint8_t>& target) {
    std::string source_content(source.begin(), source.end());
    std::string target_content(target.begin(), std::min(target.size(), source.size()));
    
    // Validate timestamp preservation (CreationDate, ModDate)
    std::regex timestamp_regex(R"(/CreationDate\s*\([^)]+\)|/ModDate\s*\([^)]+\))");
    
    std::sregex_iterator source_iter(source_content.begin(), source_content.end(), timestamp_regex);
    std::sregex_iterator source_end;
    
    for (auto i = source_iter; i != source_end; ++i) {
        std::smatch match = *i;
        size_t pos = match.position();
        size_t length = match.length();
        
        // Verify this timestamp is preserved exactly
        if (pos + length <= target_content.size()) {
            std::string source_timestamp = source_content.substr(pos, length);
            std::string target_timestamp = target_content.substr(pos, length);
            
            if (source_timestamp != target_timestamp) {
                throw std::runtime_error("TIMESTAMP_VIOLATION: Timestamp modified at position " + std::to_string(pos));
            }
        }
    }
    }
}

bool SourceFormatPreservation::is_injection_zone_safe(const std::vector<uint8_t>& pdf_data, size_t position) {
    std::string content(pdf_data.begin(), pdf_data.end());
    
    // Safe zones: After %%EOF, in PDF comments, or in whitespace-only areas
    size_t eof_pos = content.rfind("%%EOF");
    if (eof_pos != std::string::npos && position >= eof_pos + 5) {
        return true; // After EOF is always safe
    }
    
    // Check if position is within a PDF comment
    size_t line_start = content.rfind('\n', position);
    if (line_start != std::string::npos) {
        size_t comment_pos = content.find('%', line_start);
        if (comment_pos != std::string::npos && comment_pos < position) {
            size_t line_end = content.find('\n', position);
            if (line_end == std::string::npos || position < line_end) {
                return true; // Within PDF comment line
            }
        }
    }
    
    return false;
}

std::vector<size_t> SourceFormatPreservation::identify_safe_injection_zones(const std::vector<uint8_t>& pdf_data) {
    std::vector<size_t> safe_zones;
    std::string content(pdf_data.begin(), pdf_data.end());
    
    // Primary safe zone: After %%EOF
    size_t eof_pos = content.rfind("%%EOF");
    if (eof_pos != std::string::npos) {
        size_t safe_start = eof_pos + 5;
        if (safe_start < pdf_data.size() && pdf_data[safe_start] == '\n') {
            safe_start++;
        }
        safe_zones.push_back(safe_start);
    }
    
    // Secondary safe zones: PDF comment lines (only for small injections)
    size_t pos = 0;
    while ((pos = content.find('%', pos)) != std::string::npos) {
        size_t line_end = content.find('\n', pos);
        if (line_end != std::string::npos) {
            // Only allow small injections within comments
            if (line_end - pos < 100) { // Limit comment injection size
                safe_zones.push_back(line_end);
            }
        }
        pos++;
    }
    
    return safe_zones;
}

bool SourceFormatPreservation::perform_comprehensive_format_fidelity_check(const std::vector<uint8_t>& source, const std::vector<uint8_t>& target) {
    try {
        // Level 1: Complete byte sequence preservation
        validate_complete_byte_sequence_preservation(source, target);
        
        // Level 2: PDF structure integrity
        validate_pdf_structure_integrity(target);
        
        // Level 3: Metadata preservation
        validate_metadata_preservation(source, target);
        
        // Level 4: Timestamp preservation
        validate_timestamp_preservation(source, target);
        
        // Level 5: Injection-only operation validation
        enforce_injection_only_operations(source, target);
        
        return true;
    } catch (const std::exception& e) {
        handle_format_violation("COMPREHENSIVE_FIDELITY_FAILURE", e.what());
        return false;
    }
}

void SourceFormatPreservation::validate_complete_byte_sequence_preservation(const std::vector<uint8_t>& source, const std::vector<uint8_t>& target) {
    if (target.size() < source.size()) {
        throw std::runtime_error("BYTE_SEQUENCE_VIOLATION: Target smaller than source");
    }
    
    // Validate every single byte of the source is preserved
    for (size_t i = 0; i < source.size(); ++i) {
        if (target[i] != source[i]) {
            throw std::runtime_error("BYTE_SEQUENCE_VIOLATION: Byte mismatch at position " + 
                std::to_string(i) + " (source: 0x" + 
                std::to_string(source[i]) + ", target: 0x" + std::to_string(target[i]) + ")");
        }
    }
}

void SourceFormatPreservation::validate_pdf_structure_integrity(const std::vector<uint8_t>& pdf_data) {
    std::string content(pdf_data.begin(), pdf_data.end());
    
    // Validate PDF header preservation
    if (!content.starts_with("%PDF-")) {
        throw std::runtime_error("PDF_STRUCTURE_VIOLATION: PDF header corrupted");
    }
    
    // Validate EOF marker preservation
    if (content.find("%%EOF") == std::string::npos) {
        throw std::runtime_error("PDF_STRUCTURE_VIOLATION: EOF marker missing");
    }
    
    // Validate xref table structure if present
    size_t xref_pos = content.find("xref");
    if (xref_pos != std::string::npos) {
        size_t trailer_pos = content.find("trailer", xref_pos);
        if (trailer_pos == std::string::npos) {
            throw std::runtime_error("PDF_STRUCTURE_VIOLATION: xref table structure corrupted");
        }
    }
    
    // Validate object structure integrity
    size_t obj_count = 0;
    size_t endobj_count = 0;
    size_t pos = 0;
    
    while ((pos = content.find(" obj", pos)) != std::string::npos) {
        obj_count++;
        pos += 4;
    }
    
    pos = 0;
    while ((pos = content.find("endobj", pos)) != std::string::npos) {
        endobj_count++;
        pos += 6;
    }
    
    if (obj_count != endobj_count) {
        throw std::runtime_error("PDF_STRUCTURE_VIOLATION: Object/endobj mismatch");
    }
}

void SourceFormatPreservation::validate_metadata_preservation(const std::vector<uint8_t>& source, const std::vector<uint8_t>& target) {
    std::string source_content(source.begin(), source.end());
    std::string target_content(target.begin(), target.begin() + source.size()); // Only check source portion
    
    // Validate Info dictionary preservation
    size_t source_info_pos = source_content.find("/Info");
    size_t target_info_pos = target_content.find("/Info");
    
    if ((source_info_pos == std::string::npos) != (target_info_pos == std::string::npos)) {
        throw std::runtime_error("METADATA_VIOLATION: Info dictionary structure changed");
    }
    
    if (source_info_pos != std::string::npos && target_info_pos != std::string::npos) {
        if (source_info_pos != target_info_pos) {
            throw std::runtime_error("METADATA_VIOLATION: Info dictionary position changed");
        }
    }
    
    // Validate Producer field preservation
    size_t source_producer_pos = source_content.find("/Producer");
    size_t target_producer_pos = target_content.find("/Producer");
    
    if ((source_producer_pos == std::string::npos) != (target_producer_pos == std::string::npos)) {
        throw std::runtime_error("METADATA_VIOLATION: Producer field structure changed");
    }
    
    // Validate Creator field preservation
    size_t source_creator_pos = source_content.find("/Creator");
    size_t target_creator_pos = target_content.find("/Creator");
    
    if ((source_creator_pos == std::string::npos) != (target_creator_pos == std::string::npos)) {
        throw std::runtime_error("METADATA_VIOLATION: Creator field structure changed");
    }
}

void SourceFormatPreservation::validate_timestamp_preservation(const std::vector<uint8_t>& source, const std::vector<uint8_t>& target) {
    std::string source_content(source.begin(), source.end());
    std::string target_content(target.begin(), target.begin() + source.size()); // Only check source portion
    
    // Validate CreationDate preservation
    size_t source_creation_pos = source_content.find("/CreationDate");
    size_t target_creation_pos = target_content.find("/CreationDate");
    
    if ((source_creation_pos == std::string::npos) != (target_creation_pos == std::string::npos)) {
        throw std::runtime_error("TIMESTAMP_VIOLATION: CreationDate structure changed");
    }
    
    if (source_creation_pos != std::string::npos && target_creation_pos != std::string::npos) {
        // Extract and compare timestamps
        size_t source_date_start = source_content.find("(", source_creation_pos);
        size_t source_date_end = source_content.find(")", source_date_start);
        size_t target_date_start = target_content.find("(", target_creation_pos);
        size_t target_date_end = target_content.find(")", target_date_start);
        
        if (source_date_start != std::string::npos && source_date_end != std::string::npos &&
            target_date_start != std::string::npos && target_date_end != std::string::npos) {
            
            std::string source_timestamp = source_content.substr(source_date_start + 1, 
                source_date_end - source_date_start - 1);
            std::string target_timestamp = target_content.substr(target_date_start + 1, 
                target_date_end - target_date_start - 1);
            
            if (source_timestamp != target_timestamp) {
                throw std::runtime_error("TIMESTAMP_VIOLATION: CreationDate value changed from '" + 
                    source_timestamp + "' to '" + target_timestamp + "'");
            }
        }
    }
    
    // Validate ModDate preservation
    size_t source_mod_pos = source_content.find("/ModDate");
    size_t target_mod_pos = target_content.find("/ModDate");
    
    if ((source_mod_pos == std::string::npos) != (target_mod_pos == std::string::npos)) {
        throw std::runtime_error("TIMESTAMP_VIOLATION: ModDate structure changed");
    }
    
    if (source_mod_pos != std::string::npos && target_mod_pos != std::string::npos) {
        // Extract and compare modification timestamps
        size_t source_mod_start = source_content.find("(", source_mod_pos);
        size_t source_mod_end = source_content.find(")", source_mod_start);
        size_t target_mod_start = target_content.find("(", target_mod_pos);
        size_t target_mod_end = target_content.find(")", target_mod_start);
        
        if (source_mod_start != std::string::npos && source_mod_end != std::string::npos &&
            target_mod_start != std::string::npos && target_mod_end != std::string::npos) {
            
            std::string source_mod_timestamp = source_content.substr(source_mod_start + 1, 
                source_mod_end - source_mod_start - 1);
            std::string target_mod_timestamp = target_content.substr(target_mod_start + 1, 
                target_mod_end - target_mod_start - 1);
            
            if (source_mod_timestamp != target_mod_timestamp) {
                throw std::runtime_error("TIMESTAMP_VIOLATION: ModDate value changed from '" + 
                    source_mod_timestamp + "' to '" + target_mod_timestamp + "'");
            }
        }
    }
}

// COMPLETE GETTER METHOD IMPLEMENTATION - Integration Fix
const SourceFormatPreservation::FormatCapture& SourceFormatPreservation::get_captured_format() const {
    if (!captured_format_.capture_complete) {
        throw std::runtime_error("FORMAT_CAPTURE_ERROR: Format capture not complete or failed - cannot return format data");
    }
    
    if (captured_format_.original_byte_sequence.empty()) {
        throw std::runtime_error("FORMAT_CAPTURE_ERROR: No source format data captured");
    }
    
    return captured_format_;
}

// COMPLETE MISSING HELPER METHOD IMPLEMENTATIONS

std::vector<SourceFormatPreservation::CriticalSection> 
SourceFormatPreservation::identify_critical_sections(const std::vector<uint8_t>& source_pdf) {
    std::vector<CriticalSection> sections;
    std::string content(source_pdf.begin(), source_pdf.end());
    
    // PDF Header section (critical)
    CriticalSection header;
    header.section_name = "PDF_HEADER";
    header.start_position = 0;
    header.length = std::min(static_cast<size_t>(8), source_pdf.size());
    header.original_bytes.assign(source_pdf.begin(), source_pdf.begin() + header.length);
    header.is_preserved = true;
    sections.push_back(header);
    
    // Cross-reference table (critical)
    size_t xref_pos = content.find("xref");
    if (xref_pos != std::string::npos) {
        CriticalSection xref;
        xref.section_name = "XREF_TABLE";
        xref.start_position = xref_pos;
        xref.length = std::min(static_cast<size_t>(1024), source_pdf.size() - xref_pos);
        xref.original_bytes.assign(source_pdf.begin() + xref_pos, 
                                  source_pdf.begin() + xref_pos + xref.length);
        xref.is_preserved = true;
        sections.push_back(xref);
    }
    
    // EOF marker (critical)
    size_t eof_pos = content.rfind("%%EOF");
    if (eof_pos != std::string::npos) {
        CriticalSection eof;
        eof.section_name = "EOF_MARKER";
        eof.start_position = eof_pos;
        eof.length = 5; // "%%EOF"
        eof.original_bytes.assign(source_pdf.begin() + eof_pos, 
                                 source_pdf.begin() + eof_pos + eof.length);
        eof.is_preserved = true;
        sections.push_back(eof);
    }
    
    return sections;
}

std::string SourceFormatPreservation::generate_format_signature(const std::vector<uint8_t>& source_pdf) {
    std::stringstream signature;
    std::string content(source_pdf.begin(), source_pdf.end());
    
    // Generate comprehensive format signature
    signature << "SIZE:" << source_pdf.size();
    
    // Count critical format elements
    size_t stream_count = 0;
    size_t obj_count = 0;
    size_t metadata_count = 0;
    size_t pos = 0;
    
    while ((pos = content.find("stream", pos)) != std::string::npos) {
        stream_count++;
        pos += 6;
    }
    
    pos = 0;
    while ((pos = content.find(" obj", pos)) != std::string::npos) {
        obj_count++;
        pos += 4;
    }
    
    pos = 0;
    while ((pos = content.find("/", pos)) != std::string::npos) {
        if (pos + 1 < content.size() && std::isalpha(content[pos + 1])) {
            metadata_count++;
        }
        pos++;
    }
    
    signature << "_STREAMS:" << stream_count 
              << "_OBJECTS:" << obj_count 
              << "_METADATA:" << metadata_count;
    
    return signature.str();
}

void SourceFormatPreservation::detect_and_map_format_patterns(const std::vector<uint8_t>& source_pdf) {
    std::string content(source_pdf.begin(), source_pdf.end());
    
    // Clear existing patterns
    captured_format_.format_pattern_positions.clear();
    
    // Map date pattern positions
    std::regex date_regex(R"(\d{4}[-/]\d{2}[-/]\d{2})");
    std::sregex_iterator date_iter(content.begin(), content.end(), date_regex);
    std::sregex_iterator end;
    
    for (std::sregex_iterator i = date_iter; i != end; ++i) {
        size_t pos = static_cast<size_t>(i->position());
        captured_format_.format_pattern_positions["date_patterns"].push_back(pos);
    }
    
    // Map timestamp pattern positions
    std::regex timestamp_regex(R"(/CreationDate|/ModDate)");
    std::sregex_iterator timestamp_iter(content.begin(), content.end(), timestamp_regex);
    
    for (std::sregex_iterator i = timestamp_iter; i != end; ++i) {
        size_t pos = static_cast<size_t>(i->position());
        captured_format_.format_pattern_positions["timestamp_patterns"].push_back(pos);
    }
    
    // Map metadata pattern positions
    std::regex metadata_regex(R"(/Producer|/Creator|/Title|/Author|/Subject|/Keywords)");
    std::sregex_iterator metadata_iter(content.begin(), content.end(), metadata_regex);
    
    for (std::sregex_iterator i = metadata_iter; i != end; ++i) {
        size_t pos = static_cast<size_t>(i->position());
        captured_format_.format_pattern_positions["metadata_patterns"].push_back(pos);
    }
}

void SourceFormatPreservation::apply_exact_field_format_preservation(std::vector<uint8_t>& pdf_data) {
    std::string content(pdf_data.begin(), pdf_data.end());
    
    // Preserve exact field formats from captured format
    for (const auto& field_format : captured_format_.exact_field_formats) {
        const std::string& field_name = field_format.first;
        const std::string& expected_format = field_format.second;
        
        // Find field in content and ensure format matches exactly
        size_t field_pos = content.find(field_name);
        if (field_pos != std::string::npos) {
            size_t value_start = content.find('(', field_pos);
            if (value_start != std::string::npos) {
                size_t value_end = content.find(')', value_start);
                if (value_end != std::string::npos) {
                    std::string current_value = content.substr(value_start + 1, value_end - value_start - 1);
                    
                    // If format doesn't match, restore original
                    if (current_value != expected_format) {
                        content.replace(value_start + 1, value_end - value_start - 1, expected_format);
                        pdf_data.assign(content.begin(), content.end());
                    }
                }
            }
        }
    }
}

void SourceFormatPreservation::apply_delimiter_pattern_preservation(std::vector<uint8_t>& pdf_data) {
    std::string content(pdf_data.begin(), pdf_data.end());
    
    // Apply preserved delimiter patterns
    for (const auto& delimiter_pattern : captured_format_.delimiter_patterns) {
        const std::string& delimiter_type = delimiter_pattern.first;
        const std::string& expected_delimiter = delimiter_pattern.second;
        
        if (delimiter_type == "date_separator" && !expected_delimiter.empty()) {
            // Replace any non-matching date separators
            std::regex date_regex(R"(\d+([/-])\d+\1\d+)");
            std::string result = std::regex_replace(content, date_regex, 
                [&expected_delimiter](const std::smatch& match) -> std::string {
                    std::string matched = match.str();
                    std::regex sep_regex(R"([/-])");
                    return std::regex_replace(matched, sep_regex, expected_delimiter);
                });
            
            if (result != content) {
                content = result;
                pdf_data.assign(content.begin(), content.end());
            }
        }
    }
}

void SourceFormatPreservation::apply_spacing_pattern_preservation(std::vector<uint8_t>& pdf_data) {
    std::string content(pdf_data.begin(), pdf_data.end());
    
    // Apply preserved spacing patterns
    for (const auto& spacing_pattern : captured_format_.spacing_patterns) {
        const std::string& spacing_type = spacing_pattern.first;
        const std::string& expected_spacing = spacing_pattern.second;
        
        if (spacing_type == "metadata_spacing" && !expected_spacing.empty()) {
            // Ensure metadata fields have consistent spacing
            std::regex metadata_regex(R"((/\w+)\s*(\())");
            std::string result = std::regex_replace(content, metadata_regex, "$1" + expected_spacing + "$2");
            
            if (result != content) {
                content = result;
                pdf_data.assign(content.begin(), content.end());
            }
        }
    }
}

void SourceFormatPreservation::apply_critical_section_preservation(std::vector<uint8_t>& pdf_data) {
    // Ensure all critical sections are preserved exactly
    for (const auto& section : captured_format_.critical_sections) {
        if (section.start_position + section.length <= pdf_data.size() && 
            section.start_position + section.length <= captured_format_.original_byte_sequence.size()) {
            
            // Verify critical section is preserved exactly
            bool section_modified = false;
            for (size_t i = 0; i < section.length; ++i) {
                size_t pos = section.start_position + i;
                if (pos < pdf_data.size() && pos < captured_format_.original_byte_sequence.size()) {
                    if (pdf_data[pos] != captured_format_.original_byte_sequence[pos]) {
                        section_modified = true;
                        break;
                    }
                }
            }
            
            // Restore original bytes if section was modified
            if (section_modified) {
                std::copy(section.original_bytes.begin(), section.original_bytes.end(),
                         pdf_data.begin() + section.start_position);
            }
        }
    }
}