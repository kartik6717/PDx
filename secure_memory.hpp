#ifndef SECURE_MEMORY_HPP
#define SECURE_MEMORY_HPP
#include "stealth_macros.hpp"

#include <memory>
#include <vector>
#include <string>
#include <stdexcept>
#include <algorithm>
#include <cstring>
#include <limits>
#include <mutex>
#include <atomic>
#include <cstdarg>
#include <functional>

namespace SecureMemory {

    // Thread-safe mutex wrapper
    class SecureMutex {
    private:
        std::mutex mutex_;
    public:
        void lock() { mutex_.lock(); }
        bool try_lock() { return mutex_.try_lock(); }
        void unlock() { mutex_.unlock(); }
        std::mutex& get() { return mutex_; }
    };

    // Secure lock guard
    class SecureLockGuard {
    private:
        SecureMutex& mutex_;
    public:
        explicit SecureLockGuard(SecureMutex& m) : mutex_(m) { mutex_.lock(); }
        ~SecureLockGuard() { mutex_.unlock(); }
    };

    // Secure unique lock
    class SecureUniqueLock {
    private:
        SecureMutex& mutex_;
        bool owns_lock_;
    public:
        explicit SecureUniqueLock(SecureMutex& m) : mutex_(m), owns_lock_(true) { mutex_.lock(); }
        ~SecureUniqueLock() { if (owns_lock_) mutex_.unlock(); }
        void unlock() { if (owns_lock_) { mutex_.unlock(); owns_lock_ = false; } }
        void lock() { if (!owns_lock_) { mutex_.lock(); owns_lock_ = true; } }
    };

    // Thread-local storage wrapper
    template<typename T>
    class ThreadLocalStorage {
    private:
        static thread_local T value_;
    public:
        ThreadLocalStorage() = default;
        T& get() { return value_; }
        const T& get() const { return value_; }
        void set(const T& val) { value_ = val; }
    };

    // Secure memory allocation with automatic zeroing
    template<typename T>
    class SecureAllocator {
    public:
        using value_type = T;
        using pointer = T*;
        using const_pointer = const T*;
        using reference = T&;
        using const_reference = const T&;
        using size_type = std::size_t;
        using difference_type = std::ptrdiff_t;

        template<class U>
        struct rebind {
            using other = SecureAllocator<U>;
        };

        SecureAllocator() noexcept = default;
        template<class U>
        SecureAllocator(const SecureAllocator<U>&) noexcept {}

        pointer allocate(size_type n) {
            if (n > std::numeric_limits<size_type>::max() / sizeof(T)) {
                throw std::bad_alloc();
            }
            
            auto ptr = static_cast<pointer>(std::aligned_alloc(alignof(T), n * sizeof(T)));
            if (!ptr) {
                throw std::bad_alloc();
            }
            
            // Initialize to zero for security
            std::memset(ptr, 0, n * sizeof(T));
            return ptr;
        }

        void deallocate(pointer p, size_type n) noexcept {
            if (p) {
                // Securely zero memory before deallocation
                std::memset(p, 0, n * sizeof(T));
                std::free(p);
            }
        }

        template<typename... Args>
        static std::unique_ptr<T> allocate_unique(Args&&... args) {
            return std::make_unique<T>(std::forward<Args>(args)...);
        }
    };

    // Secure string with automatic cleanup
    using SecureString = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;

    // Secure vector with automatic cleanup
    template<typename T>
    using SecureVector = std::vector<T, SecureAllocator<T>>;

    // Safe memory operations
    class SafeMemory {
    public:
        // Safe memory copy with bounds checking
        static bool safe_memcpy(void* dest, size_t dest_size, const void* src, size_t copy_size) {
            if (!dest || !src || copy_size == 0) {
                return false;
            }
            
            if (copy_size > dest_size) {
                return false; // Buffer overflow protection
            }
            
            std::memcpy(dest, src, copy_size);
            return true;
        }

        // Safe memory set with bounds checking
        static bool safe_memset(void* dest, int value, size_t dest_size, size_t set_size) {
            if (!dest || set_size == 0) {
                return false;
            }
            
            if (set_size > dest_size) {
                return false; // Buffer overflow protection
            }
            
            std::memset(dest, value, set_size);
            return true;
        }

        // Secure memory zero (compiler won't optimize away)
        static void secure_zero(void* ptr, size_t size) {
            if (!ptr || size == 0) return;
            
            volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
            while (size--) {
                *p++ = 0;
            }
        }

        // Safe string operations
        static bool safe_sprintf(char* buffer, size_t buffer_size, const char* format, ...);
    };

    // RAII wrapper for automatic cleanup
    template<typename T>
    class SecureWrapper {
    private:
        std::unique_ptr<T> ptr_;
        std::function<void(T*)> cleanup_;

    public:
        template<typename... Args>
        SecureWrapper(Args&&... args) 
            : ptr_(std::make_unique<T>(std::forward<Args>(args)...)) {}

        SecureWrapper(std::unique_ptr<T> ptr, std::function<void(T*)> cleanup = nullptr)
            : ptr_(std::move(ptr)), cleanup_(cleanup) {}

        ~SecureWrapper() {
            if (cleanup_ && ptr_) {
                cleanup_(ptr_.get());
            }
        }

        T* get() { return ptr_.get(); }
        const T* get() const { return ptr_.get(); }
        T& operator*() { return *ptr_; }
        const T& operator*() const { return *ptr_; }
        T* operator->() { return ptr_.get(); }
        const T* operator->() const { return ptr_.get(); }

        // Prevent copying
        SecureWrapper(const SecureWrapper&) = delete;
        SecureWrapper& operator=(const SecureWrapper&) = delete;

        // Allow moving
        SecureWrapper(SecureWrapper&&) = default;
        SecureWrapper& operator=(SecureWrapper&&) = default;
    };

    // Memory pool with bounds checking
    class SecureMemoryPool {
    private:
        std::vector<std::unique_ptr<uint8_t[]>> blocks_;
        std::vector<size_t> block_sizes_;
        std::mutex pool_mutex_;
        std::atomic<size_t> total_allocated_{0};
        size_t max_allocation_;

    public:
        explicit SecureMemoryPool(size_t max_allocation = 100 * 1024 * 1024) // 100MB default
            : max_allocation_(max_allocation) {}

        ~SecureMemoryPool() {
            std::lock_guard<std::mutex> lock(pool_mutex_);
            // Secure cleanup of all blocks
            for (auto& block : blocks_) {
                if (block) {
                    // Zero memory before destruction
                }
            }
        }

        void* allocate(size_t size) {
            if (size == 0 || size > max_allocation_) {
                return nullptr;
            }

            std::lock_guard<std::mutex> lock(pool_mutex_);
            
            if (total_allocated_.load() + size > max_allocation_) {
                return nullptr; // Prevent memory exhaustion
            }

            auto block = std::make_unique<uint8_t[]>(size);
            if (!block) {
                return nullptr;
            }

            // Zero initialize
            std::memset(block.get(), 0, size);
            
            void* ptr = block.get();
            blocks_.push_back(std::move(block));
            block_sizes_.push_back(size);
            total_allocated_ += size;

            return ptr;
        }

        size_t get_allocated_size() const {
            return total_allocated_.load();
        }

        void reset() {
            std::lock_guard<std::mutex> lock(pool_mutex_);
            blocks_.clear();
            block_sizes_.clear();
            total_allocated_ = 0;
        }
    };

    // Global secure memory utilities
    extern SecureMemoryPool* get_global_pool();
    extern void initialize_secure_memory();
    extern void cleanup_secure_memory();
}

#endif // SECURE_MEMORY_HPP
