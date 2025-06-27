#ifndef MEMORY_GUARD_HPP
#define MEMORY_GUARD_HPP

#include <unordered_map>
#include <cstdint>
#include <cstddef>

class MemoryGuard {
public:
    struct GuardedAllocation {
        void* data_ptr;
        void* total_ptr;
        size_t data_size;
        size_t total_size;
        bool is_active;
    };
    
    struct MemoryProtection {
        void* ptr;
        size_t size;
        int original_prot;
    };
    
    MemoryGuard();
    ~MemoryGuard();
    
    bool activate_protection();
    void deactivate_protection();
    void* allocate_guarded_memory(size_t size);
    bool deallocate_guarded_memory(void* ptr);
    bool is_pointer_guarded(void* ptr) const;
    size_t get_protected_memory_size() const;
    bool verify_guard_integrity();
    void emergency_cleanup();
    void cleanup_all_guards();
    bool protect_existing_memory(void* ptr, size_t size);
    bool unprotect_memory(void* ptr);
    
    static MemoryGuard& getInstance();
    
private:
    bool is_active_;
    size_t page_size_;
    size_t total_protected_memory_;
    std::unordered_map<void*, GuardedAllocation> guarded_allocations_;
    std::unordered_map<void*, MemoryProtection> protected_regions_;
};

#endif // MEMORY_GUARD_HPP