#ifndef SILENT_OPERATIONS_HPP
#define SILENT_OPERATIONS_HPP

// Comprehensive silent operation header for complete console output elimination
// Include this in all C++ files to ensure forensic invisibility

#include "stealth_macros.hpp"
#include "silent_operation_manager.hpp"
#include "silent_error_handler.hpp"
#include "silent_status_tracker.hpp"
#include "silent_execution_wrappers.hpp"

// Disable all console output globally
#define STEALTH_MODE_ACTIVE

// Override standard output operations
#ifdef STEALTH_MODE_ACTIVE
    #undef cout
    #undef cerr
    #undef clog
    #define cout if(false) std::cout
    #define cerr if(false) std::cerr
    #define clog if(false) std::clog
#endif

// Disable printf family
#ifdef STEALTH_MODE_ACTIVE
    #define printf(...) ((void)0)
    #define fprintf(...) ((void)0)
    #define vprintf(...) ((void)0)
    #define vfprintf(...) ((void)0)
    #define sprintf(...) ((void)0)
    #define snprintf(...) ((void)0)
#endif

// Disable puts family
#ifdef STEALTH_MODE_ACTIVE
    #define puts(...) ((void)0)
    #define fputs(...) ((void)0)
    #define putchar(...) ((void)0)
    #define fputc(...) ((void)0)
#endif

// Disable perror
#ifdef STEALTH_MODE_ACTIVE
    #define perror(...) ((void)0)
#endif

// Silent initialization macro
#define INITIALIZE_SILENT_MODE() \
    do { \
        SilentOperationManager::enable_stealth_mode(); \
        SilentStatusTracker::reset_all(); \
    } while(0)

// Silent main wrapper
#define SILENT_MAIN_BEGIN() \
    INITIALIZE_SILENT_MODE(); \
    SILENT_EXECUTE({

#define SILENT_MAIN_END() \
    }); \
    return 0;

#endif // SILENT_OPERATIONS_HPP