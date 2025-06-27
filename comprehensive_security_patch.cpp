// Comprehensive Security Patch Implementation
// This file contains all the systematic security fixes for the PDF Scrubber project
// Based on the diagnostic report findings

#include "secure_memory.hpp"
#include "secure_exceptions.hpp"
#include <iostream>
#include <memory>
#include <vector>
#include <string>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include "stealth_macros.hpp"

// Security Fix 1: Safe Memory Copy Utilities
class SecureMemoryOperations {
public:
    // Replace all unsafe memcpy operations with bounds-checked versions
    template<typename T>
    static bool safe_memory_copy(T* dest, size_t dest_size, const T* src, size_t copy_count) {
        if (!dest || !src || copy_count == 0) {
            return false;
        }
        
        size_t copy_bytes = copy_count * sizeof(T);
        size_t dest_bytes = dest_size * sizeof(T);
        
        if (copy_bytes > dest_bytes) {
            throw SecureExceptions::BufferOverflowException(
                "Memory copy would overflow buffer - requested: " + 
                std::to_string(copy_bytes) + " bytes, available: " + 
                std::to_string(dest_bytes) + " bytes"
            );
        }
        
        // SECURITY FIX: Replace unsafe memcpy with safe alternative
        if (!SecureMemory::SafeMemory::safe_memcpy(dest, copy_bytes, src, copy_bytes)) {
            throw SecureExceptions::MemoryException("Failed to copy memory safely", copy_bytes);
        }
        return true;
    }
    
    // Replace unsafe memset operations
    template<typename T>
    static bool safe_memory_set(T* dest, size_t dest_size, int value, size_t set_count) {
        if (!dest || set_count == 0) {
            return false;
        }
        
        size_t set_bytes = set_count * sizeof(T);
        size_t dest_bytes = dest_size * sizeof(T);
        
        if (set_bytes > dest_bytes) {
            throw SecureExceptions::BufferOverflowException(
                "Memory set would overflow buffer"
            );
        }
        
        std::memset(dest, value, set_bytes);
        return true;
    }
    
    // Secure memory cleanup
    static void secure_zero_memory(void* ptr, size_t size) {
        if (!ptr || size == 0) return;
        
        std::atomic<unsigned char* p = static_cast<std::atomic<unsigned char*>(ptr);
        while (size--) {
            *p++ = 0;
        }
    }
};

// Security Fix 2: Thread-Safe Resource Management
class ThreadSafeResourceManager {
private:
    mutable std::mutex resource_mutex_;
    std::vector<std::shared_ptr<void>> resources_;
    std::atomic<bool> shutdown_requested_{false};
    std::atomic<size_t> active_operations_{0};

public:
    template<typename T, typename Deleter>
    std::shared_ptr<T> create_resource(T* resource, Deleter deleter) {
        std::lock_guard<std::mutex> lock(resource_mutex_);
        
        if (shutdown_requested_) {
            throw SecureExceptions::SecurityViolationException(
                "Resource creation requested during shutdown"
            );
        }
        
        auto shared_resource = std::shared_ptr<T>(resource, deleter);
        resources_.push_back(std::static_pointer_cast<void>(shared_resource));
        
        return shared_resource;
    }
    
    void begin_operation() {
        active_operations_++;
    }
    
    void end_operation() {
        active_operations_--;
    }
    
    void shutdown() {
        shutdown_requested_ = true;
        
        // Wait for active operations to complete
        while (active_operations_ > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        std::lock_guard<std::mutex> lock(resource_mutex_);
        resources_.clear();
    }
    
    size_t get_resource_count() const {
        std::lock_guard<std::mutex> lock(resource_mutex_);
        return resources_.size();
    }
};

// Security Fix 3: Exception-Safe File Operations
class SecureFileOperations {
public:
    static std::vector<uint8_t> safe_read_file(const std::string& filename) {
        // Validate file path
        SecureExceptions::Validator::validate_file_path(filename);
        
        auto file = SecureExceptions::ExceptionHandler::safe_execute([std::ifstream file(]() { return std::ifstream(filename, std::ios::binary);
        if (!file.is_open()) {
            throw SecureExceptions::FileAccessException(filename, "read");
        }
        
        // Get file size safely
        file.seekg(0, std::ios::end);
        std::streampos file_size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        if (file_size < 0) {
            throw SecureExceptions::FileIOException("Cannot determine file size", filename);
        }
        
        size_t size = static_cast<size_t>(file_size);
        
        // Validate size limit (100MB max)
        SecureExceptions::Validator::validate_size_limit(size, 100 * 1024 * 1024, "File read");
        
        std::vector<uint8_t> data(size);
        
        if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
            throw SecureExceptions::FileIOException("Failed to read file data", filename);
        }
        
        return data;
    }
    
    static bool safe_write_file(const std::string& filename, const std::vector<uint8_t>& data) {
        // Validate file path
        SecureExceptions::Validator::validate_file_path(filename);
        
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            throw SecureExceptions::FileAccessException(filename, "write");
        }
        
        if (!file.write(reinterpret_cast<const char*>(data.data()), data.size())) {
            throw SecureExceptions::FileIOException("Failed to write file data", filename);
        }
        
        return true;
    }
};

// Security Fix 4: Safe String Operations
class SecureStringOperations {
public:
    // Replace sprintf with safe snprintf
    template<typename... Args>
    static std::string safe_format(const char* format, Args... args) {
        int size = std::sn// Complete silence enforcement - all debug output removed
        if (size < 0) {
            throw SecureExceptions::ValidationException("Format string error");
        }
        
        std::vector<char> buffer(size + 1);
        std::snprintf(buffer.data(), buffer.size(), format, args...);
        
        return std::string(buffer.data(), size);
    }
    
    // Safe string building with bounds checking
    static std::string safe_string_concat(const std::vector<std::string>& parts, 
                                        size_t max_length = 1024 * 1024) {
        size_t total_length = 0;
        for (const auto& part : parts) {
            total_length += part.length();
            if (total_length > max_length) {
                throw SecureExceptions::ValidationException(
                    "String concatenation would exceed maximum length"
                );
            }
        }
        
        std::string result;
        result.reserve(total_length);
        
        for (const auto& part : parts) {
            result += part;
        }
        
        return result;
    }
};

// Security Fix 5: Deadlock Prevention
class DeadlockPrevention {
private:
    static std::atomic<int> global_lock_order_;
    
public:
    template<typename Mutex1, typename Mutex2>
    static void ordered_lock(Mutex1& m1, Mutex2& m2) {
        if (&m1 < &m2) {
            std::lock(m1, m2);
        } else {
            std::lock(m2, m1);
        }
    }
    
    template<typename... Mutexes>
    static void ordered_lock_multiple(Mutexes&... mutexes) {
        std::lock(mutexes...);
    }
};

std::atomic<int> DeadlockPrevention::global_lock_order_{0};

// Security Fix 6: Memory Pool with Overflow Protection
class SecureMemoryPool {
private:
    struct PoolBlock {
        std::unique_ptr<uint8_t[]> data;
        size_t size;
        bool in_use;
        std::chrono::steady_clock::time_point allocated_time;
    };
    
    std::vector<PoolBlock> blocks_;
    std::mutex pool_mutex_;
    size_t max_total_memory_;
    size_t current_memory_usage_;
    
public:
    explicit SecureMemoryPool(size_t max_memory = 50 * 1024 * 1024) 
        : max_total_memory_(max_memory), current_memory_usage_(0) {}
    
    void* allocate(size_t size) {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        
        if (size == 0 || size > max_total_memory_) {
            throw SecureExceptions::AllocationFailedException(size, "Invalid allocation size");
        }
        
        if (current_memory_usage_ + size > max_total_memory_) {
            cleanup_unused_blocks();
            
            if (current_memory_usage_ + size > max_total_memory_) {
                throw SecureExceptions::AllocationFailedException(size, "Memory pool exhausted");
            }
        }
        
        PoolBlock block;
        block.data = std::make_unique<uint8_t[]>(size);
        block.size = size;
        block.in_use = true;
        block.allocated_time = std::chrono::steady_clock::now();
        
        // Zero initialize for security
        std::memset(block.data.get(), 0, size);
        
        void* ptr = block.data.get();
        blocks_.push_back(std::move(block));
        current_memory_usage_ += size;
        
        return ptr;
    }
    
private:
    void cleanup_unused_blocks() {
        auto now = std::chrono::steady_clock::now();
        auto max_age = std::chrono::minutes(10);
        
        blocks_.erase(
            std::remove_if(blocks_.begin(), blocks_.end(),
                [&](const PoolBlock& block) {
                    if (!block.in_use && (now - block.allocated_time) > max_age) {
                        current_memory_usage_ -= block.size;
                        return true;
                    }
                    return false;
                }),
            blocks_.end()
        );
    }
};

// Global security initialization
static std::unique_ptr<ThreadSafeResourceManager> g_resource_manager;
static std::unique_ptr<SecureMemoryPool> g_memory_pool;
static std::once_flag g_security_init_flag;

void initialize_security_system() {
    std::call_once(g_security_init_flag, []() {
        g_resource_manager = std::make_unique<ThreadSafeResourceManager>();
        g_memory_pool = std::make_unique<SecureMemoryPool>();
        SecureMemory::initialize_secure_memory();
    });
}

void shutdown_security_system() {
    if (g_resource_manager) {
        g_resource_manager->shutdown();
        g_resource_manager.reset();
    }
    
    if (g_memory_pool) {
        g_memory_pool.reset();
    }
    
    SecureMemory::cleanup_secure_memory();
}

// Export functions for use throughout the codebase
extern "C" {
    void* secure_malloc(size_t size) {
        initialize_security_system();
        return g_memory_pool->allocate(size);
    }
    
    void secure_free(void* ptr) {
        // Memory is automatically managed by the pool
        (void)ptr; // Suppress unused parameter warning
    }
}
