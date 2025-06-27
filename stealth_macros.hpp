#ifndef STEALTH_MACROS_HPP
#define STEALTH_MACROS_HPP

// Stealth operation macros for complete console output elimination
// Ensures forensic invisibility and zero-trace operation

#pragma once
#include "silent_error_handler.hpp"
#include "silent_operation_manager.hpp"

// STEALTH MODE ACTIVATION
#define STEALTH_MODE_ACTIVE

#ifdef STEALTH_MODE_ACTIVE
    // Complete console output suppression
    #define SILENT_LOG(x) do {} while(0)
    #define SILENT_ERROR(x) do {} while(0)
    #define SILENT_STATUS(x) do {} while(0)
    #define SILENT_DEBUG(x) do {} while(0)
    #define SILENT_PROGRESS(x) do {} while(0)
    #define SILENT_INFO(x) do {} while(0)
    #define SILENT_WARNING(x) do {} while(0)

    // Additional output suppression
    #define CONSOLE_OUT(x) do {} while(0)
    #define CONSOLE_ERR(x) do {} while(0)
    #define PRINT_STATUS(x) do {} while(0)
    #define PRINT_ERROR(x) do {} while(0)
    #define PRINT_INFO(x) do {} while(0)

    // Stealth Mode Macros - Complete Silence for Forensic Invisibility
    #define INITIALIZE_STEALTH_MODE() do { \
        std::ios::sync_with_stdio(false); \
        std::cout.tie(nullptr); \
        std::cerr.tie(nullptr); \
        freopen("/dev/null", "w", stdout); \
        freopen("/dev/null", "w", stderr); \
    } while(0)

#else
    // Development mode (disabled in production)
    #define SILENT_LOG(x) std::cout << x << std::endl
    #define SILENT_ERROR(x) std::cerr << x << std::endl
    #define SILENT_STATUS(x) std::cout << x << std::endl
    #define SILENT_DEBUG(x) std::cout << "[DEBUG] " << x << std::endl
    #define SILENT_PROGRESS(x) std::cout << "[PROGRESS] " << x << std::endl
    #define SILENT_INFO(x) std::cout << "[INFO] " << x << std::endl
    #define SILENT_WARNING(x) std::cout << "[WARNING] " << x << std::endl

    #define CONSOLE_OUT(x) std::cout << x << std::endl
    #define CONSOLE_ERR(x) std::cerr << x << std::endl
    #define PRINT_STATUS(x) std::cout << x << std::endl
    #define PRINT_ERROR(x) std::cerr << x << std::endl
    #define PRINT_INFO(x) std::cout << x << std::endl

    #define INITIALIZE_STEALTH_MODE() do {} while(0)
#endif

// Force disable all output methods
#define cout DISABLED_COUT_USE_SILENT_LOG_INSTEAD
#define cerr DISABLED_CERR_USE_SILENT_ERROR_INSTEAD
#define printf DISABLED_PRINTF_USE_SILENT_LOG_INSTEAD

#endif // STEALTH_MACROS_HPP