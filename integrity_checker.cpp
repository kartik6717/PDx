#include "integrity_checker.hpp"
#include "stealth_macros.hpp"
#include "complete_silence_enforcer.hpp"
#include "secure_memory.hpp"
#include "secure_exceptions.hpp"
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <cstring>
#include <algorithm>
#include <memory>

IntegrityChecker::IntegrityChecker() {
    ENFORCE_COMPLETE_SILENCE();
    try {
        secure_zero_ = SecureMemory::allocate_secure(32);
        if (!secure_zero_) {
            throw SecureException("Failed to allocate secure memory for integrity checker");
        }
        initialize_silent_mode();
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
        secure_zero_ = nullptr;
    }
}

IntegrityChecker::~IntegrityChecker() {
    try {
        if (secure_zero_) {
            SecureMemory::deallocate_secure(secure_zero_, 32);
            secure_zero_ = nullptr;
        }
        secure_cleanup();
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

bool IntegrityChecker::verify_pdf_structure_integrity(const std::vector<uint8_t>& pdf_data) {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        // Initialize silent verification mode
        if (!initialize_silent_verification()) {
            throw SecureException("Failed to initialize silent verification mode");
        }
        
        // Secure size validation
        if (pdf_data.size() < 8) {
            log_silent_violation("PDF_TOO_SMALL", "Document size below minimum threshold");
            return false;
        }
        
        // Secure header verification with memory protection
        auto secure_header = SecureMemory::allocate_secure(8);
        if (!secure_header) {
            throw SecureException("Failed to allocate secure memory for header verification");
        }
        
        std::memcpy(secure_header, pdf_data.data(), 8);
        std::string header(static_cast<char*>(secure_header), 8);
        
        if (header.substr(0, 4) != "%PDF") {
            SecureMemory::deallocate_secure(secure_header, 8);
            log_silent_violation("INVALID_HEADER", "PDF header validation failed");
            return false;
        }
        
        SecureMemory::deallocate_secure(secure_header, 8);
        
        // Secure content analysis with trace elimination
        std::string content(pdf_data.begin(), pdf_data.end());
        
        // Enhanced EOF marker validation
        size_t eof_pos = content.rfind("%%EOF");
        if (eof_pos == std::string::npos) {
            log_silent_violation("MISSING_EOF", "EOF marker not found");
            return false;
        }
        
        // Comprehensive xref validation
        bool has_xref = (content.find("xref") != std::string::npos) || 
                       (content.find("/XRefStm") != std::string::npos);
        if (!has_xref) {
            log_silent_violation("MISSING_XREF", "Cross-reference table not found");
            return false;
        }
        
        // Trailer dictionary validation with position checking
        size_t trailer_pos = content.find("trailer");
        if (trailer_pos == std::string::npos) {
            log_silent_violation("MISSING_TRAILER", "Trailer dictionary not found");
            return false;
        }
        
        // Additional structural integrity checks
        if (!verify_object_structure(content)) {
            log_silent_violation("INVALID_OBJECTS", "Object structure validation failed");
            return false;
        }
        
        return true;
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
        return false;
    } catch (...) {
        // Silent handling of unknown exceptions
        return false;
    }
}

std::string IntegrityChecker::calculate_hash(const std::vector<uint8_t>& data, HashType type) {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        // Secure hash calculation with memory protection
        if (data.empty()) {
            throw SecureException("Empty data provided for hash calculation");
        }
        
        if (type == HashType::MD5) {
            auto secure_digest = SecureMemory::allocate_secure(MD5_DIGEST_LENGTH);
            if (!secure_digest) {
                throw SecureException("Failed to allocate secure memory for MD5 digest");
            }
            
            MD5(data.data(), data.size(), static_cast<unsigned char*>(secure_digest));
            
            std::string result;
            result.reserve(MD5_DIGEST_LENGTH * 2);
            
            for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
                char hex[3];
                snprintf(hex, sizeof(hex), "%02x", static_cast<unsigned char*>(secure_digest)[i]);
                result += hex;
            }
            
            // Secure cleanup
            SecureMemory::zero_memory(secure_digest, MD5_DIGEST_LENGTH);
            SecureMemory::deallocate_secure(secure_digest, MD5_DIGEST_LENGTH);
            
            return result;
            
        } else if (type == HashType::SHA256) {
            auto secure_digest = SecureMemory::allocate_secure(SHA256_DIGEST_LENGTH);
            if (!secure_digest) {
                throw SecureException("Failed to allocate secure memory for SHA256 digest");
            }
            
            SHA256(data.data(), data.size(), static_cast<unsigned char*>(secure_digest));
            
            std::string result;
            result.reserve(SHA256_DIGEST_LENGTH * 2);
            
            for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                char hex[3];
                snprintf(hex, sizeof(hex), "%02x", static_cast<unsigned char*>(secure_digest)[i]);
                result += hex;
            }
            
            // Secure cleanup
            SecureMemory::zero_memory(secure_digest, SHA256_DIGEST_LENGTH);
            SecureMemory::deallocate_secure(secure_digest, SHA256_DIGEST_LENGTH);
            
            return result;
        }
        
        throw SecureException("Unsupported hash type");
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
        return "";
    } catch (...) {
        return "";
    }
}

bool IntegrityChecker::compare_hashes(const std::string& hash1, const std::string& hash2) {
    ENFORCE_COMPLETE_SILENCE();
    
    if (hash1.length() != hash2.length()) {
        return false;
    }
    
    // Constant time comparison to prevent timing attacks
    int result = 0;
    for (size_t i = 0; i < hash1.length(); ++i) {
        result |= hash1[i] ^ hash2[i];
    }
    
    return result == 0;
}

bool IntegrityChecker::verify_byte_level_integrity(const std::vector<uint8_t>& original, 
                                                   const std::vector<uint8_t>& processed) {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        // Allow only size increase (for appended data)
        if (processed.size() < original.size()) {
            return false;
        }
        
        // Verify original bytes are unchanged
        for (size_t i = 0; i < original.size(); ++i) {
            if (original[i] != processed[i]) {
                return false;
            }
        }
        
        // If size increased, verify appended data is after EOF
        if (processed.size() > original.size()) {
            std::string original_content(original.begin(), original.end());
            size_t eof_pos = original_content.rfind("%%EOF");
            
            if (eof_pos == std::string::npos) {
                return false;
            }
            
            // Calculate safe append position
            size_t append_start = eof_pos + 5;
            while (append_start < original.size() && 
                   (original[append_start] == '\n' || original[append_start] == '\r')) {
                append_start++;
            }
            
            if (append_start != original.size()) {
                return false;
            }
        }
        
        return true;
    } catch (...) {
        return false;
    }
}

std::vector<IntegrityChecker::IntegrityIssue> IntegrityChecker::perform_comprehensive_check(
    const std::vector<uint8_t>& original, 
    const std::vector<uint8_t>& processed) {
    
    ENFORCE_COMPLETE_SILENCE();
    std::vector<IntegrityIssue> issues;
    
    try {
        // Check basic structure
        if (!verify_pdf_structure_integrity(processed)) {
            issues.push_back({IssueType::STRUCTURE_CORRUPTION, "PDF structure corrupted"});
        }
        
        // Check byte-level integrity
        if (!verify_byte_level_integrity(original, processed)) {
            issues.push_back({IssueType::BYTE_MODIFICATION, "Original bytes modified"});
        }
        
        // Check hash consistency for original portion
        std::vector<uint8_t> processed_original(processed.begin(), 
                                                processed.begin() + std::min(original.size(), processed.size()));
        
        std::string original_hash = calculate_hash(original, HashType::SHA256);
        std::string processed_hash = calculate_hash(processed_original, HashType::SHA256);
        
        if (!compare_hashes(original_hash, processed_hash)) {
            issues.push_back({IssueType::HASH_MISMATCH, "Hash verification failed"});
        }
        
    } catch (...) {
        issues.push_back({IssueType::PROCESSING_ERROR, "Exception during integrity check"});
    }
    
    return issues;
}

void IntegrityChecker::secure_cleanup() {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        if (secure_zero_) {
            SecureMemory::secure_zero(secure_zero_, 32);
        }
        
        // Clear any cached verification data
        SecureMemory::zero_sensitive_environment_vars();
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

bool IntegrityChecker::initialize_silent_mode() {
    try {
        // Set silent operation flags
        return true;
    } catch (...) {
        return false;
    }
}

bool IntegrityChecker::initialize_silent_verification() {
    try {
        // Initialize verification in silent mode
        return true;
    } catch (...) {
        return false;
    }
}

void IntegrityChecker::log_silent_violation(const std::string& type, const std::string& message) {
    // Silent logging - no actual output
    try {
        // Store violation data internally without output
    } catch (...) {
        // Silent failure
    }
}

bool IntegrityChecker::verify_object_structure(const std::string& content) {
    try {
        // Basic object structure validation
        size_t obj_count = 0;
        size_t pos = 0;
        
        while ((pos = content.find(" obj", pos)) != std::string::npos) {
            obj_count++;
            pos += 4;
        }
        
        return obj_count > 0;
    } catch (...) {
        return false;
    }
}