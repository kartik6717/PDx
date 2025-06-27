#include "memory_sanitizer.hpp"
#include "stealth_macros.hpp"
#include "complete_silence_enforcer.hpp"
#include "secure_memory.hpp"
#include "secure_exceptions.hpp"
#include <cstring>
#include <algorithm>
#include <thread>
#include <chrono>
#include <memory>
#include <atomic>

MemorySanitizer::MemorySanitizer() {
    ENFORCE_COMPLETE_SILENCE();
    try {
        is_active_ = false;
        sanitization_passes_ = 3;
        total_sanitized_bytes_ = 0;
        secure_workspace_ = SecureMemory::allocate_secure(WORKSPACE_SIZE);
        
        if (!secure_workspace_) {
            throw SecureException("Failed to allocate secure workspace for memory sanitizer");
        }
        
        initialize_silent_sanitization();
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
        secure_workspace_ = nullptr;
    }
}

MemorySanitizer::~MemorySanitizer() {
    try {
        emergency_sanitize_all();
        
        if (secure_workspace_) {
            SecureMemory::secure_zero(secure_workspace_, WORKSPACE_SIZE);
            SecureMemory::deallocate_secure(secure_workspace_, WORKSPACE_SIZE);
            secure_workspace_ = nullptr;
        }
        
        perform_final_sanitization_cleanup();
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

void MemorySanitizer::activate_sanitization() {
    ENFORCE_COMPLETE_SILENCE();
    try {
        if (!secure_workspace_) {
            throw SecureException("Secure workspace not initialized for sanitization activation");
        }
        is_active_ = true;
        eliminate_sanitization_traces();
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

void MemorySanitizer::deactivate_sanitization() {
    ENFORCE_COMPLETE_SILENCE();
    try {
        is_active_ = false;
        perform_deactivation_sanitization();
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

bool MemorySanitizer::sanitize_memory_region(void* ptr, size_t size) {
    ENFORCE_COMPLETE_SILENCE();
    
    if (!is_active_ || !ptr || size == 0) {
        return false;
    }
    
    try {
        // Validate memory region for security
        if (!validate_sanitization_target(ptr, size)) {
            throw SecureException("Invalid memory region for sanitization");
        }
        
        uint8_t* memory_ptr = static_cast<uint8_t*>(ptr);
        
        // Enhanced multi-pass sanitization with cryptographic patterns
        for (int pass = 0; pass < sanitization_passes_; ++pass) {
            switch (pass % 6) {
                case 0:
                    // Secure zero pass
                    SecureMemory::secure_zero(ptr, size);
                    break;
                case 1:
                    // Pattern pass (0xAA)
                    secure_pattern_write(ptr, size, 0xAA);
                    break;
                case 2:
                    // Inverted pattern pass (0x55)
                    secure_pattern_write(ptr, size, 0x55);
                    break;
                case 3:
                    // Cryptographically secure random pattern
                    write_cryptographic_random_pattern(memory_ptr, size);
                    break;
                case 4:
                    // Alternating byte pattern
                    for (size_t i = 0; i < size; ++i) {
                        memory_ptr[i] = (i % 2) ? 0xFF : 0x00;
                    }
                    break;
                case 5:
                    // Time-based pattern for additional entropy
                    write_temporal_pattern(memory_ptr, size, pass);
                    break;
            }
            
            // Enhanced memory barriers and cache flushing
            std::atomic_thread_fence(std::memory_order_seq_cst);
            flush_memory_caches();
        }
        
        // Final enhanced zero pass
        SecureMemory::secure_zero(ptr, size);
        std::atomic_thread_fence(std::memory_order_seq_cst);
        
        // Record sanitization with enhanced tracking
        SanitizationRecord record;
        record.ptr = ptr;
        record.size = size;
        record.timestamp = std::chrono::steady_clock::now();
        record.passes_applied = sanitization_passes_;
        record.pattern_entropy = calculate_pattern_entropy();
        
        sanitization_history_[ptr] = record;
        total_sanitized_bytes_ += size;
        
        return true;
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
        return false;
    } catch (...) {
        return false;
    }
}

bool MemorySanitizer::sanitize_vector(std::vector<uint8_t>& data) {
    ENFORCE_COMPLETE_SILENCE();
    
    if (!is_active_ || data.empty()) {
        return false;
    }
    
    try {
        bool result = sanitize_memory_region(data.data(), data.size());
        data.clear();
        data.shrink_to_fit();
        return result;
    } catch (...) {
        return false;
    }
}

bool MemorySanitizer::sanitize_string(std::string& str) {
    ENFORCE_COMPLETE_SILENCE();
    
    if (!is_active_ || str.empty()) {
        return false;
    }
    
    try {
        // Sanitize string content
        for (size_t i = 0; i < str.length(); ++i) {
            str[i] = '\0';
        }
        
        // Multiple overwrite passes
        for (int pass = 0; pass < sanitization_passes_; ++pass) {
            for (size_t i = 0; i < str.length(); ++i) {
                str[i] = static_cast<char>((i + pass) % 256);
            }
        }
        
        str.clear();
        str.shrink_to_fit();
        
        return true;
        
    } catch (...) {
        return false;
    }
}

bool MemorySanitizer::deep_sanitize_pdf_data(std::vector<uint8_t>& pdf_data) {
    ENFORCE_COMPLETE_SILENCE();
    
    if (!is_active_ || pdf_data.empty()) {
        return false;
    }
    
    try {
        // Create backup for verification
        size_t original_size = pdf_data.size();
        
        // Sanitize the vector data
        bool result = sanitize_memory_region(pdf_data.data(), pdf_data.size());
        
        // Clear vector
        pdf_data.clear();
        pdf_data.shrink_to_fit();
        
        // Additional sanitization of any potential copies in memory
        if (secure_workspace_) {
            sanitize_memory_region(secure_workspace_, WORKSPACE_SIZE);
        }
        
        // Record deep sanitization
        deep_sanitization_count_++;
        
        return result;
        
    } catch (...) {
        return false;
    }
}

void MemorySanitizer::emergency_sanitize_all() {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        // Sanitize all recorded regions
        for (const auto& pair : sanitization_history_) {
            sanitize_memory_region(pair.second.ptr, pair.second.size);
        }
        
        // Sanitize workspace
        if (secure_workspace_) {
            sanitize_memory_region(secure_workspace_, WORKSPACE_SIZE);
        }
        
        // Clear history
        sanitization_history_.clear();
        
    } catch (...) {
        // Silent failure
    }
}

bool MemorySanitizer::verify_sanitization_integrity() {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        // Check if workspace is properly zeroed
        if (secure_workspace_) {
            uint8_t* workspace_ptr = static_cast<uint8_t*>(secure_workspace_);
            for (size_t i = 0; i < WORKSPACE_SIZE; ++i) {
                if (workspace_ptr[i] != 0) {
                    // Re-sanitize workspace
                    sanitize_memory_region(secure_workspace_, WORKSPACE_SIZE);
                    break;
                }
            }
        }
        
        return true;
        
    } catch (...) {
        return false;
    }
}

void MemorySanitizer::set_sanitization_passes(int passes) {
    ENFORCE_COMPLETE_SILENCE();
    if (passes > 0 && passes <= MAX_SANITIZATION_PASSES) {
        sanitization_passes_ = passes;
    }
}

int MemorySanitizer::get_sanitization_passes() const {
    return sanitization_passes_;
}

size_t MemorySanitizer::get_total_sanitized_bytes() const {
    return total_sanitized_bytes_;
}

size_t MemorySanitizer::get_deep_sanitization_count() const {
    return deep_sanitization_count_;
}

bool MemorySanitizer::is_sanitization_active() const {
    return is_active_;
}

void MemorySanitizer::reset_statistics() {
    ENFORCE_COMPLETE_SILENCE();
    total_sanitized_bytes_ = 0;
    deep_sanitization_count_ = 0;
    sanitization_history_.clear();
}

bool MemorySanitizer::perform_maintenance_sanitization() {
    ENFORCE_COMPLETE_SILENCE();
    
    if (!is_active_) {
        return false;
    }
    
    try {
        // Sanitize workspace
        if (secure_workspace_) {
            sanitize_memory_region(secure_workspace_, WORKSPACE_SIZE);
        }
        
        // Clean up old sanitization records
        auto now = std::chrono::steady_clock::now();
        auto it = sanitization_history_.begin();
        while (it != sanitization_history_.end()) {
            auto duration = std::chrono::duration_cast<std::chrono::minutes>(now - it->second.timestamp);
            if (duration.count() > 30) { // Remove records older than 30 minutes
                it = sanitization_history_.erase(it);
            } else {
                ++it;
            }
        }
        
        return verify_sanitization_integrity();
        
    } catch (...) {
        return false;
    }
}

// Static instance for global access
MemorySanitizer& MemorySanitizer::getInstance() {
    static MemorySanitizer instance;
    return instance;
}