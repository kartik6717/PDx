#include "pdf_integrity_checker.hpp"
#include "stealth_macros.hpp"
#include "complete_silence_enforcer.hpp"
#include "secure_memory.hpp"
#include "secure_exceptions.hpp"
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <cstring>
#include <algorithm>
#include <regex>
#include <memory>

PDFIntegrityChecker::PDFIntegrityChecker() {
    ENFORCE_COMPLETE_SILENCE();
    try {
        is_active_ = false;
        strict_mode_ = true;
        secure_workspace_ = SecureMemory::allocate_secure(WORKSPACE_SIZE);
        
        if (!secure_workspace_) {
            throw SecureException("Failed to allocate secure workspace for PDF integrity checker");
        }
        
        initialize_silent_checking();
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
        secure_workspace_ = nullptr;
    }
}

PDFIntegrityChecker::~PDFIntegrityChecker() {
    try {
        if (secure_workspace_) {
            SecureMemory::secure_zero(secure_workspace_, WORKSPACE_SIZE);
            SecureMemory::deallocate_secure(secure_workspace_, WORKSPACE_SIZE);
            secure_workspace_ = nullptr;
        }
        
        perform_final_integrity_cleanup();
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

void PDFIntegrityChecker::activate_checking() {
    ENFORCE_COMPLETE_SILENCE();
    try {
        if (!secure_workspace_) {
            throw SecureException("Secure workspace not initialized for integrity checking activation");
        }
        is_active_ = true;
        eliminate_integrity_traces();
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

void PDFIntegrityChecker::deactivate_checking() {
    ENFORCE_COMPLETE_SILENCE();
    try {
        is_active_ = false;
        perform_deactivation_integrity_cleanup();
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

bool PDFIntegrityChecker::verify_pdf_structure(const std::vector<uint8_t>& pdf_data) {
    ENFORCE_COMPLETE_SILENCE();
    
    if (!is_active_ || pdf_data.empty()) {
        return false;
    }
    
    try {
        std::string content(pdf_data.begin(), pdf_data.end());
        
        // Check PDF header
        if (!verify_pdf_header(content)) {
            record_integrity_issue("Invalid PDF header");
            return false;
        }
        
        // Check EOF marker
        if (!verify_eof_marker(content)) {
            record_integrity_issue("Missing or invalid EOF marker");
            return false;
        }
        
        // Check xref table
        if (!verify_xref_table(content)) {
            record_integrity_issue("Invalid or missing xref table");
            return false;
        }
        
        // Check trailer
        if (!verify_trailer(content)) {
            record_integrity_issue("Invalid or missing trailer");
            return false;
        }
        
        // Check object structure
        if (!verify_object_structure(content)) {
            record_integrity_issue("Invalid object structure");
            return false;
        }
        
        return true;
        
    } catch (...) {
        record_integrity_issue("Exception during structure verification");
        return false;
    }
}

bool PDFIntegrityChecker::verify_byte_fidelity(const std::vector<uint8_t>& original, 
                                               const std::vector<uint8_t>& processed) {
    ENFORCE_COMPLETE_SILENCE();
    
    if (!is_active_) {
        return false;
    }
    
    try {
        // Size check - processed can only be larger (appended data)
        if (processed.size() < original.size()) {
            record_integrity_issue("Processed file smaller than original");
            return false;
        }
        
        // Byte-by-byte comparison of original content
        for (size_t i = 0; i < original.size(); ++i) {
            if (original[i] != processed[i]) {
                record_integrity_issue("Original byte modified at position " + std::to_string(i));
                return false;
            }
        }
        
        // If size increased, verify appended data is after EOF
        if (processed.size() > original.size()) {
            if (!verify_safe_append_zone(original, processed)) {
                record_integrity_issue("Unsafe data appended");
                return false;
            }
        }
        
        return true;
        
    } catch (...) {
        record_integrity_issue("Exception during byte fidelity verification");
        return false;
    }
}

std::string PDFIntegrityChecker::calculate_content_hash(const std::vector<uint8_t>& data, 
                                                        HashAlgorithm algorithm) {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        if (algorithm == HashAlgorithm::SHA256) {
            unsigned char digest[SHA256_DIGEST_LENGTH];
            SHA256(data.data(), data.size(), digest);
            
            std::string result;
            for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                char hex[3];
                snprintf(hex, sizeof(hex), "%02x", digest[i]);
                result += hex;
            }
            return result;
        } else if (algorithm == HashAlgorithm::MD5) {
            unsigned char digest[MD5_DIGEST_LENGTH];
            MD5(data.data(), data.size(), digest);
            
            std::string result;
            for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
                char hex[3];
                snprintf(hex, sizeof(hex), "%02x", digest[i]);
                result += hex;
            }
            return result;
        }
    } catch (...) {
        return "";
    }
    
    return "";
}

bool PDFIntegrityChecker::verify_hash_consistency(const std::vector<uint8_t>& original, 
                                                  const std::vector<uint8_t>& processed) {
    ENFORCE_COMPLETE_SILENCE();
    
    if (!is_active_) {
        return false;
    }
    
    try {
        // Extract original portion from processed data
        std::vector<uint8_t> processed_original(processed.begin(), 
                                                processed.begin() + std::min(original.size(), processed.size()));
        
        // Calculate hashes
        std::string original_hash = calculate_content_hash(original, HashAlgorithm::SHA256);
        std::string processed_hash = calculate_content_hash(processed_original, HashAlgorithm::SHA256);
        
        // Constant-time comparison
        if (original_hash.length() != processed_hash.length()) {
            record_integrity_issue("Hash length mismatch");
            return false;
        }
        
        int result = 0;
        for (size_t i = 0; i < original_hash.length(); ++i) {
            result |= original_hash[i] ^ processed_hash[i];
        }
        
        if (result != 0) {
            record_integrity_issue("Hash verification failed");
            return false;
        }
        
        return true;
        
    } catch (...) {
        record_integrity_issue("Exception during hash verification");
        return false;
    }
}

PDFIntegrityChecker::IntegrityReport PDFIntegrityChecker::perform_comprehensive_check(
    const std::vector<uint8_t>& original, 
    const std::vector<uint8_t>& processed) {
    
    ENFORCE_COMPLETE_SILENCE();
    IntegrityReport report;
    
    try {
        // Structure verification
        report.structure_valid = verify_pdf_structure(processed);
        
        // Byte fidelity verification
        report.byte_fidelity_valid = verify_byte_fidelity(original, processed);
        
        // Hash consistency verification
        report.hash_consistent = verify_hash_consistency(original, processed);
        
        // Content integrity verification
        report.content_integrity_valid = verify_content_integrity(processed);
        
        // Overall integrity assessment
        report.overall_integrity = report.structure_valid && 
                                  report.byte_fidelity_valid && 
                                  report.hash_consistent && 
                                  report.content_integrity_valid;
        
        // Copy issues
        report.issues = integrity_issues_;
        
        // Generate checksums
        report.original_checksum = calculate_content_hash(original, HashAlgorithm::SHA256);
        report.processed_checksum = calculate_content_hash(processed, HashAlgorithm::SHA256);
        
        check_count_++;
        
    } catch (...) {
        report.overall_integrity = false;
        record_integrity_issue("Exception during comprehensive check");
    }
    
    return report;
}

bool PDFIntegrityChecker::verify_pdf_header(const std::string& content) {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        if (content.length() < 8) {
            return false;
        }
        
        std::string header = content.substr(0, 8);
        return header.substr(0, 4) == "%PDF";
        
    } catch (...) {
        return false;
    }
}

bool PDFIntegrityChecker::verify_eof_marker(const std::string& content) {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        return content.find("%%EOF") != std::string::npos;
    } catch (...) {
        return false;
    }
}

bool PDFIntegrityChecker::verify_xref_table(const std::string& content) {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        // Check for traditional xref table or XRefStm
        return content.find("xref") != std::string::npos || 
               content.find("/XRefStm") != std::string::npos;
    } catch (...) {
        return false;
    }
}

bool PDFIntegrityChecker::verify_trailer(const std::string& content) {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        return content.find("trailer") != std::string::npos;
    } catch (...) {
        return false;
    }
}

bool PDFIntegrityChecker::verify_object_structure(const std::string& content) {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        // Basic check for object structure
        std::regex obj_pattern(R"(\d+\s+\d+\s+obj)");
        std::regex endobj_pattern(R"(endobj)");
        
        std::sregex_iterator obj_begin(content.begin(), content.end(), obj_pattern);
        std::sregex_iterator obj_end;
        
        std::sregex_iterator endobj_begin(content.begin(), content.end(), endobj_pattern);
        std::sregex_iterator endobj_end;
        
        int obj_count = std::distance(obj_begin, obj_end);
        int endobj_count = std::distance(endobj_begin, endobj_end);
        
        // Allow some flexibility for malformed PDFs that still function
        return obj_count > 0 && endobj_count > 0;
        
    } catch (...) {
        return false;
    }
}

bool PDFIntegrityChecker::verify_safe_append_zone(const std::vector<uint8_t>& original, 
                                                  const std::vector<uint8_t>& processed) {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        std::string original_content(original.begin(), original.end());
        size_t eof_pos = original_content.rfind("%%EOF");
        
        if (eof_pos == std::string::npos) {
            return false;
        }
        
        // Calculate safe append position
        size_t safe_pos = eof_pos + 5; // After "%%EOF"
        while (safe_pos < original.size() && 
               (original[safe_pos] == '\n' || original[safe_pos] == '\r')) {
            safe_pos++;
        }
        
        return safe_pos == original.size();
        
    } catch (...) {
        return false;
    }
}

bool PDFIntegrityChecker::verify_content_integrity(const std::vector<uint8_t>& pdf_data) {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        std::string content(pdf_data.begin(), pdf_data.end());
        
        // Check for basic content integrity
        // Verify that essential PDF structures are present and properly formatted
        
        // Check for catalog
        if (content.find("/Type /Catalog") == std::string::npos) {
            record_integrity_issue("Missing or invalid catalog");
            return false;
        }
        
        // Check for pages object
        if (content.find("/Type /Pages") == std::string::npos) {
            record_integrity_issue("Missing or invalid pages object");
            return false;
        }
        
        return true;
        
    } catch (...) {
        return false;
    }
}

void PDFIntegrityChecker::record_integrity_issue(const std::string& issue) {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        integrity_issues_.push_back(issue);
    } catch (...) {
        // Silent failure
    }
}

void PDFIntegrityChecker::clear_integrity_issues() {
    ENFORCE_COMPLETE_SILENCE();
    integrity_issues_.clear();
}

std::vector<std::string> PDFIntegrityChecker::get_integrity_issues() const {
    return integrity_issues_;
}

void PDFIntegrityChecker::set_strict_mode(bool strict) {
    ENFORCE_COMPLETE_SILENCE();
    strict_mode_ = strict;
}

bool PDFIntegrityChecker::is_strict_mode() const {
    return strict_mode_;
}

size_t PDFIntegrityChecker::get_check_count() const {
    return check_count_;
}

void PDFIntegrityChecker::reset_check_count() {
    ENFORCE_COMPLETE_SILENCE();
    check_count_ = 0;
}

bool PDFIntegrityChecker::is_checking_active() const {
    return is_active_;
}

// Static instance for global access
PDFIntegrityChecker& PDFIntegrityChecker::getInstance() {
    static PDFIntegrityChecker instance;
    return instance;
}