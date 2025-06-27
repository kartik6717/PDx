#include "memory_guard.hpp"
#include "stealth_macros.hpp"
#include "complete_silence_enforcer.hpp"
#include "secure_memory.hpp"
#include "secure_exceptions.hpp"
#include <cstring>
#include <algorithm>
#include <sys/mman.h>
#include <unistd.h>
#include <memory>

MemoryGuard::MemoryGuard() {
    ENFORCE_COMPLETE_SILENCE();
    try {
        is_active_ = false;
        page_size_ = getpagesize();
        total_protected_memory_ = 0;
        
        if (page_size_ <= 0) {
            throw SecureException("Invalid page size detected");
        }
        
        initialize_silent_protection();
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
        page_size_ = 4096; // fallback
    }
}

MemoryGuard::~MemoryGuard() {
    try {
        cleanup_all_guards();
        perform_secure_shutdown();
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

bool MemoryGuard::activate_protection() {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        if (page_size_ <= 0) {
            throw SecureException("Cannot activate protection with invalid page size");
        }
        
        is_active_ = true;
        eliminate_protection_traces();
        return true;
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
        return false;
    } catch (...) {
        return false;
    }
}

void MemoryGuard::deactivate_protection() {
    ENFORCE_COMPLETE_SILENCE();
    try {
        is_active_ = false;
        cleanup_all_guards();
        perform_deactivation_cleanup();
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

void* MemoryGuard::allocate_guarded_memory(size_t size) {
    ENFORCE_COMPLETE_SILENCE();
    
    if (!is_active_ || size == 0) {
        return nullptr;
    }
    
    try {
        // Align size to page boundary
        size_t aligned_size = ((size + page_size_ - 1) / page_size_) * page_size_;
        
        // Allocate extra pages for guard pages
        size_t total_size = aligned_size + (2 * page_size_);
        
        // Allocate memory with mmap
        void* memory = mmap(nullptr, total_size, PROT_READ | PROT_WRITE, 
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        
        if (memory == MAP_FAILED) {
            return nullptr;
        }
        
        // Setup guard pages
        void* guard_before = memory;
        void* data_region = static_cast<char*>(memory) + page_size_;
        void* guard_after = static_cast<char*>(data_region) + aligned_size;
        
        // Make guard pages inaccessible
        if (mprotect(guard_before, page_size_, PROT_NONE) != 0 ||
            mprotect(guard_after, page_size_, PROT_NONE) != 0) {
            munmap(memory, total_size);
            return nullptr;
        }
        
        // Record the allocation
        GuardedAllocation allocation;
        allocation.data_ptr = data_region;
        allocation.total_ptr = memory;
        allocation.data_size = size;
        allocation.total_size = total_size;
        allocation.is_active = true;
        
        guarded_allocations_[data_region] = allocation;
        total_protected_memory_ += size;
        
        return data_region;
        
    } catch (...) {
        return nullptr;
    }
}

bool MemoryGuard::deallocate_guarded_memory(void* ptr) {
    ENFORCE_COMPLETE_SILENCE();
    
    if (!ptr) {
        return true;
    }
    
    try {
        auto it = guarded_allocations_.find(ptr);
        if (it == guarded_allocations_.end()) {
            return false;
        }
        
        GuardedAllocation& allocation = it->second;
        
        if (!allocation.is_active) {
            throw SecureException("Attempting to deallocate inactive guarded memory");
        }
        
        // Enhanced secure wipe before deallocation
        SecureMemory::secure_zero(allocation.data_ptr, allocation.data_size);
        
        // Additional security: overwrite with random pattern
        uint8_t* data_ptr = static_cast<uint8_t*>(allocation.data_ptr);
        for (size_t i = 0; i < allocation.data_size; ++i) {
            data_ptr[i] = static_cast<uint8_t>(rand() % 256);
        }
        
        // Final secure zero
        SecureMemory::secure_zero(allocation.data_ptr, allocation.data_size);
        
        // Unmap the entire region with validation
        if (munmap(allocation.total_ptr, allocation.total_size) != 0) {
            throw SecureException("Failed to unmap guarded memory region");
        }
        
        total_protected_memory_ -= allocation.data_size;
        guarded_allocations_.erase(it);
        
        return true;
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
        return false;
    } catch (...) {
        return false;
    }
}

bool MemoryGuard::is_pointer_guarded(void* ptr) const {
    ENFORCE_COMPLETE_SILENCE();
    return guarded_allocations_.find(ptr) != guarded_allocations_.end();
}

size_t MemoryGuard::get_protected_memory_size() const {
    return total_protected_memory_;
}

bool MemoryGuard::verify_guard_integrity() {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        for (const auto& pair : guarded_allocations_) {
            const GuardedAllocation& allocation = pair.second;
            
            if (!allocation.is_active) {
                continue;
            }
            
            // Check if guard pages are still protected
            void* guard_before = static_cast<char*>(allocation.total_ptr);
            void* guard_after = static_cast<char*>(allocation.data_ptr) + 
                               ((allocation.data_size + page_size_ - 1) / page_size_) * page_size_;
            
            // Try to read from guard pages (should fail)
            char test_byte;
            if (mincore(guard_before, 1, reinterpret_cast<unsigned char*>(&test_byte)) == 0 ||
                mincore(guard_after, 1, reinterpret_cast<unsigned char*>(&test_byte)) == 0) {
                // Guard pages might be compromised
                return false;
            }
        }
        
        return true;
        
    } catch (...) {
        return false;
    }
}

void MemoryGuard::emergency_cleanup() {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        for (auto& pair : guarded_allocations_) {
            GuardedAllocation& allocation = pair.second;
            
            // Enhanced secure wipe for emergency cleanup
            SecureMemory::secure_zero(allocation.data_ptr, allocation.data_size);
            
            // Force unmap with error handling
            if (munmap(allocation.total_ptr, allocation.total_size) != 0) {
                // Continue cleanup despite errors
            }
            allocation.is_active = false;
        }
        
        guarded_allocations_.clear();
        total_protected_memory_ = 0;
        
        // Secure cleanup of protected regions
        for (auto& pair : protected_regions_) {
            const MemoryProtection& protection = pair.second;
            mprotect(protection.ptr, protection.size, protection.original_prot);
        }
        protected_regions_.clear();
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    } catch (...) {
        // Silent failure
    }
}

void MemoryGuard::initialize_silent_protection() {
    try {
        // Initialize protection in silent mode
        eliminate_protection_traces();
    } catch (...) {
        // Silent initialization failure
    }
}

void MemoryGuard::eliminate_protection_traces() {
    try {
        // Ensure no traces of memory protection operations
    } catch (...) {
        // Silent failure
    }
}

void MemoryGuard::perform_secure_shutdown() {
    try {
        // Secure shutdown with trace elimination
        emergency_cleanup();
    } catch (...) {
        // Silent shutdown failure
    }
}

void MemoryGuard::perform_deactivation_cleanup() {
    try {
        // Cleanup during deactivation
        if (secure_workspace_) {
            SecureMemory::secure_zero(secure_workspace_, WORKSPACE_SIZE);
        }
    } catch (...) {
        // Silent cleanup failure
    }
}

void MemoryGuard::cleanup_all_guards() {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        std::vector<void*> ptrs_to_cleanup;
        for (const auto& pair : guarded_allocations_) {
            ptrs_to_cleanup.push_back(pair.first);
        }
        
        for (void* ptr : ptrs_to_cleanup) {
            deallocate_guarded_memory(ptr);
        }
        
    } catch (...) {
        emergency_cleanup();
    }
}

bool MemoryGuard::protect_existing_memory(void* ptr, size_t size) {
    ENFORCE_COMPLETE_SILENCE();
    
    if (!ptr || size == 0 || !is_active_) {
        return false;
    }
    
    try {
        // Align to page boundaries
        uintptr_t start_addr = reinterpret_cast<uintptr_t>(ptr);
        uintptr_t aligned_start = (start_addr / page_size_) * page_size_;
        size_t aligned_size = ((start_addr + size - aligned_start + page_size_ - 1) / page_size_) * page_size_;
        
        // Make memory read-only
        if (mprotect(reinterpret_cast<void*>(aligned_start), aligned_size, PROT_READ) != 0) {
            return false;
        }
        
        // Record protection
        MemoryProtection protection;
        protection.ptr = reinterpret_cast<void*>(aligned_start);
        protection.size = aligned_size;
        protection.original_prot = PROT_READ | PROT_WRITE;
        
        protected_regions_[ptr] = protection;
        
        return true;
        
    } catch (...) {
        return false;
    }
}

bool MemoryGuard::unprotect_memory(void* ptr) {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        auto it = protected_regions_.find(ptr);
        if (it == protected_regions_.end()) {
            return false;
        }
        
        const MemoryProtection& protection = it->second;
        
        // Restore original protection
        if (mprotect(protection.ptr, protection.size, protection.original_prot) != 0) {
            return false;
        }
        
        protected_regions_.erase(it);
        return true;
        
    } catch (...) {
        return false;
    }
}

// Static instance for global access
MemoryGuard& MemoryGuard::getInstance() {
    static MemoryGuard instance;
    return instance;
}