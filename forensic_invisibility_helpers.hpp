#ifndef FORENSIC_INVISIBILITY_HELPERS_HPP
#define FORENSIC_INVISIBILITY_HELPERS_HPP

#include "secure_memory.hpp"
#include "complete_silence_enforcer.hpp"
#include "stealth_macros.hpp"
#include <functional>

// Helper function for structured exception handling with complete silence
template<typename Func>
inline auto structured_exception_handling(Func&& func, bool silent_failure_result = true) -> decltype(func()) {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        return func();
    } catch (const std::exception& e) {
        // Silent exception handling - no output
        if constexpr (std::is_same_v<decltype(func()), bool>) {
            return silent_failure_result;
        } else if constexpr (std::is_same_v<decltype(func()), void>) {
            return;
        } else {
            return decltype(func()){}; // Default constructed return value
        }
    } catch (...) {
        // Silent handling of all exceptions
        if constexpr (std::is_same_v<decltype(func()), bool>) {
            return silent_failure_result;
        } else if constexpr (std::is_same_v<decltype(func()), void>) {
            return;
        } else {
            return decltype(func()){}; // Default constructed return value
        }
    }
}

// Function to eliminate all traces with secure memory cleanup
inline void eliminate_all_traces() {
    ENFORCE_COMPLETE_SILENCE();
    
    // Multi-pass secure memory cleanup
    SecureMemory::zero_sensitive_memory();
    
    // Clear any temporary buffers
    SecureMemory::clear_all_buffers();
    
    // Ensure complete trace elimination
    CompleteSilenceEnforcer::eliminate_debug_traces();
}

// Macro for suppressing all traces
#define SUPPRESS_ALL_TRACES() do { \
    ENFORCE_COMPLETE_SILENCE(); \
    eliminate_all_traces(); \
} while(0)

#endif // FORENSIC_INVISIBILITY_HELPERS_HPP