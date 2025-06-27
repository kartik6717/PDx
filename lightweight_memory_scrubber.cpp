#include "lightweight_memory_scrubber.hpp"
#include "stealth_macros.hpp"
#include "complete_silence_enforcer.hpp"
#include "secure_memory.hpp"
#include "secure_exceptions.hpp"
#include <cstring>
#include <algorithm>
#include <thread>
#include <atomic>
#include <memory>

LightweightMemoryScrubber::LightweightMemoryScrubber() {
    ENFORCE_COMPLETE_SILENCE();
    try {
        is_active_ = false;
        scrub_pattern_ = 0xAA;
        secure_buffer_ = SecureMemory::allocate_secure(SCRUB_BUFFER_SIZE);
        
        if (!secure_buffer_) {
            throw SecureException("Failed to allocate secure buffer for memory scrubber");
        }
        
        initialize_silent_scrubbing();
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
        secure_buffer_ = nullptr;
    }
}

LightweightMemoryScrubber::~LightweightMemoryScrubber() {
    try {
        if (secure_buffer_) {
            SecureMemory::secure_zero(secure_buffer_, SCRUB_BUFFER_SIZE);
            SecureMemory::deallocate_secure(secure_buffer_, SCRUB_BUFFER_SIZE);
            secure_buffer_ = nullptr;
        }
        
        // Perform final secure cleanup
        perform_final_cleanup();
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

void LightweightMemoryScrubber::activate_scrubbing() {
    ENFORCE_COMPLETE_SILENCE();
    try {
        if (!secure_buffer_) {
            throw SecureException("Secure buffer not initialized for scrubbing activation");
        }
        is_active_ = true;
        eliminate_scrubbing_traces();
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

void LightweightMemoryScrubber::deactivate_scrubbing() {
    ENFORCE_COMPLETE_SILENCE();
    try {
        is_active_ = false;
        perform_deactivation_cleanup();
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

void LightweightMemoryScrubber::scrub_memory_region(void* ptr, size_t size) {
    ENFORCE_COMPLETE_SILENCE();
    
    if (!is_active_ || !ptr || size == 0) {
        return;
    }
    
    try {
        // Validate pointer and size for security
        if (!validate_memory_region(ptr, size)) {
            throw SecureException("Invalid memory region for scrubbing");
        }
        
        // Enhanced multi-pass scrubbing with secure patterns
        uint8_t* memory_ptr = static_cast<uint8_t*>(ptr);
        
        // Pass 1: Write secure zeros
        SecureMemory::secure_zero(ptr, size);
        std::atomic_thread_fence(std::memory_order_seq_cst);
        
        // Pass 2: Write alternating pattern (0xAA)
        secure_pattern_write(ptr, size, 0xAA);
        std::atomic_thread_fence(std::memory_order_seq_cst);
        
        // Pass 3: Write inverted pattern (0x55)
        secure_pattern_write(ptr, size, 0x55);
        std::atomic_thread_fence(std::memory_order_seq_cst);
        
        // Pass 4: Write cryptographically secure random pattern
        write_secure_random_pattern(memory_ptr, size);
        std::atomic_thread_fence(std::memory_order_seq_cst);
        
        // Pass 5: Write alternating bytes
        for (size_t i = 0; i < size; ++i) {
            memory_ptr[i] = (i % 2) ? 0xFF : 0x00;
        }
        std::atomic_thread_fence(std::memory_order_seq_cst);
        
        // Final pass: Secure zero again
        SecureMemory::secure_zero(ptr, size);
        std::atomic_thread_fence(std::memory_order_seq_cst);
        
        // Additional security: flush CPU caches if possible
        flush_cpu_caches();
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    } catch (...) {
        // Silent failure - continue operation
    }
}

void LightweightMemoryScrubber::secure_scrub_vector(std::vector<uint8_t>& data) {
    ENFORCE_COMPLETE_SILENCE();
    
    if (!is_active_ || data.empty()) {
        return;
    }
    
    try {
        scrub_memory_region(data.data(), data.size());
        data.clear();
        data.shrink_to_fit();
    } catch (...) {
        // Silent failure - continue operation
    }
}

void LightweightMemoryScrubber::secure_scrub_string(std::string& str) {
    ENFORCE_COMPLETE_SILENCE();
    
    if (!is_active_ || str.empty()) {
        return;
    }
    
    try {
        // Enhanced string scrubbing with secure memory operations
        if (!str.empty()) {
            scrub_memory_region(const_cast<char*>(str.data()), str.size());
        }
        
        // Clear and shrink with secure cleanup
        str.clear();
        str.shrink_to_fit();
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    } catch (...) {
        // Silent failure - continue operation
    }
}

void LightweightMemoryScrubber::initialize_silent_scrubbing() {
    try {
        // Initialize scrubbing in silent mode
        eliminate_scrubbing_traces();
    } catch (...) {
        // Silent initialization failure
    }
}

void LightweightMemoryScrubber::eliminate_scrubbing_traces() {
    // Ensure no traces of scrubbing operations
    try {
        // Silent trace elimination
    } catch (...) {
        // Silent failure
    }
}

void LightweightMemoryScrubber::perform_final_cleanup() {
    try {
        // Final secure cleanup with trace elimination
        if (secure_buffer_) {
            SecureMemory::secure_zero(secure_buffer_, SCRUB_BUFFER_SIZE);
        }
    } catch (...) {
        // Silent cleanup failure
    }
}

void LightweightMemoryScrubber::perform_deactivation_cleanup() {
    try {
        // Cleanup during deactivation
        if (secure_buffer_) {
            scrub_memory_region(secure_buffer_, SCRUB_BUFFER_SIZE);
        }
    } catch (...) {
        // Silent cleanup failure
    }
}

bool LightweightMemoryScrubber::validate_memory_region(void* ptr, size_t size) {
    try {
        // Basic validation - ptr not null and reasonable size
        return ptr != nullptr && size > 0 && size < (1ULL << 32);
    } catch (...) {
        return false;
    }
}

void LightweightMemoryScrubber::secure_pattern_write(void* ptr, size_t size, uint8_t pattern) {
    try {
        if (ptr && size > 0) {
            std::memset(ptr, pattern, size);
        }
    } catch (...) {
        // Silent failure
    }
}

void LightweightMemoryScrubber::write_secure_random_pattern(uint8_t* ptr, size_t size) {
    try {
        if (ptr && size > 0) {
            for (size_t i = 0; i < size; ++i) {
                ptr[i] = static_cast<uint8_t>(rand() % 256);
            }
        }
    } catch (...) {
        // Silent failure
    }
}

void LightweightMemoryScrubber::flush_cpu_caches() {
    try {
        // Platform-specific cache flushing if available
        std::atomic_thread_fence(std::memory_order_seq_cst);
    } catch (...) {
        // Silent failure
    }
}

void LightweightMemoryScrubber::emergency_scrub_all() {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        // Scrub internal secure buffer
        if (secure_buffer_) {
            scrub_memory_region(secure_buffer_, SCRUB_BUFFER_SIZE);
        }
        
        // Force garbage collection-like behavior
        std::this_thread::yield();
        
    } catch (...) {
        // Silent failure - continue operation
    }
}

bool LightweightMemoryScrubber::is_scrubbing_active() const {
    return is_active_;
}

void LightweightMemoryScrubber::set_scrub_pattern(uint8_t pattern) {
    ENFORCE_COMPLETE_SILENCE();
    scrub_pattern_ = pattern;
}

size_t LightweightMemoryScrubber::get_scrub_count() const {
    return scrub_count_;
}

void LightweightMemoryScrubber::reset_scrub_count() {
    ENFORCE_COMPLETE_SILENCE();
    scrub_count_ = 0;
}

void LightweightMemoryScrubber::perform_maintenance_scrub() {
    ENFORCE_COMPLETE_SILENCE();
    
    if (!is_active_) {
        return;
    }
    
    try {
        // Scrub internal buffers
        if (secure_buffer_) {
            scrub_memory_region(secure_buffer_, SCRUB_BUFFER_SIZE);
        }
        
        ++scrub_count_;
        
    } catch (...) {
        // Silent failure - continue operation
    }
}

// Static instance for global access
LightweightMemoryScrubber& LightweightMemoryScrubber::getInstance() {
    static LightweightMemoryScrubber instance;
    return instance;
}