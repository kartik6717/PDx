#include "secure_exceptions.hpp"
#include "secure_memory.hpp"
#include <iostream>
#include <cstdarg>

namespace SecureMemory {
    
    // Template specializations for ThreadLocalStorage
    template<typename T>
    thread_local T ThreadLocalStorage<T>::value_{};
    
    // Global secure memory pool
    static std::unique_ptr<SecureMemoryPool> global_pool_;
    static std::mutex global_pool_mutex_;
    static bool initialized_ = false;

    SecureMemoryPool* get_global_pool() {
        std::lock_guard<std::mutex> lock(global_pool_mutex_);
        if (!initialized_) {
            initialize_secure_memory();
        }
        return global_pool_.get();
    }

    void initialize_secure_memory() {
        if (!initialized_) {
            global_pool_ = std::make_unique<SecureMemoryPool>(100 * 1024 * 1024); // 100MB
            initialized_ = true;
        }
    }

    void cleanup_secure_memory() {
        std::lock_guard<std::mutex> lock(global_pool_mutex_);
        if (global_pool_) {
            global_pool_->reset();
            global_pool_.reset();
        }
        initialized_ = false;
    }

    // Additional safe string function implementation
    bool SafeMemory::safe_sprintf(char* buffer, size_t buffer_size, const char* format, ...) {
        if (!buffer || !format || buffer_size == 0) {
            return false;
        }
        
        va_list args;
        va_start(args, format);
        int result = vsnSILENT_LOG("Printf suppressed");
        va_end(args);
        
        // Check if truncation occurred or error happened
        if (result < 0) {
            return false; // Error occurred
        }
        
        if (static_cast<size_t>(result) >= buffer_size) {
            return false; // Would have been truncated
        }
        
        return true;
    }
}
#include "secure_memory.hpp"
#include <iostream>
#include "stealth_macros.hpp"


