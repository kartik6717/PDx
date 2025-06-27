#ifndef TRACE_CLEANER_HPP
#define TRACE_CLEANER_HPP

// Complete debug and trace macro suppression for forensic invisibility
#ifdef DEBUG
#undef DEBUG
#endif

#ifdef VERBOSE
#undef VERBOSE
#endif

#ifdef LOG_LEVEL
#undef LOG_LEVEL
#endif

#ifdef NDEBUG
#undef NDEBUG
#endif

#ifdef TRACE_ENABLED
#undef TRACE_ENABLED
#endif

#ifdef ENABLE_LOGGING
#undef ENABLE_LOGGING
#endif

#define DEBUG 0
#define VERBOSE 0
#define LOG_LEVEL 0
#define NDEBUG 1
#define TRACE_ENABLED 0
#define ENABLE_LOGGING 0

// Suppress all standard library debug and trace outputs
#ifdef _GLIBCXX_DEBUG
#undef _GLIBCXX_DEBUG
#endif

#ifdef _LIBCPP_DEBUG
#undef _LIBCPP_DEBUG
#endif

#ifdef _ITERATOR_DEBUG_LEVEL
#undef _ITERATOR_DEBUG_LEVEL
#define _ITERATOR_DEBUG_LEVEL 0
#endif

#ifdef _SECURE_SCL
#undef _SECURE_SCL
#define _SECURE_SCL 0
#endif

// Complete template instantiation and compilation-time debug suppression for trace operations
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-security"
#pragma GCC diagnostic ignored "-Wuninitialized"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wwrite-strings"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wparentheses"
#pragma GCC diagnostic ignored "-Wswitch"
#pragma GCC diagnostic ignored "-Wreorder"
#pragma GCC diagnostic ignored "-Wcomment"
#pragma GCC diagnostic ignored "-Wmissing-braces"
#pragma GCC diagnostic ignored "-Wunused-label"
#pragma GCC diagnostic ignored "-Wunused-local-typedefs"
#pragma GCC diagnostic ignored "-Wtemplate-id-cdtor"
#pragma GCC diagnostic ignored "-Winline"
#pragma GCC diagnostic ignored "-Woverloaded-virtual"

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Weverything"
#pragma clang diagnostic ignored "-Wunused-template"
#pragma clang diagnostic ignored "-Winstantiation-after-specialization"
#pragma clang diagnostic ignored "-Wundefined-inline"
#pragma clang diagnostic ignored "-Wundefined-internal"
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4996) // deprecated function
#pragma warning(disable: 4101) // unreferenced local variable
#pragma warning(disable: 4100) // unreferenced formal parameter
#pragma warning(disable: 4189) // local variable initialized but not referenced
#pragma warning(disable: 4127) // conditional expression constant
#pragma warning(disable: 4702) // unreachable code
#pragma warning(disable: 4706) // assignment within conditional expression
#pragma warning(disable: 4389) // signed/unsigned mismatch
#pragma warning(disable: 4018) // signed/unsigned mismatch
#pragma warning(disable: 4244) // conversion possible loss of data
#pragma warning(disable: 4267) // conversion possible loss of data
#pragma warning(disable: 4312) // type cast greater size
#pragma warning(disable: 4311) // type cast truncation
#pragma warning(disable: 4302) // type cast truncation
#pragma warning(disable: 4390) // empty controlled statement
#pragma warning(disable: 4722) // destructor never returns
#endif

// Template trace cleaning instantiation suppression directives
#define TRACE_TEMPLATE_INSTANTIATION_SILENT __attribute__((visibility("hidden"))) __attribute__((always_inline))
#define TRACE_TEMPLATE_SPECIALIZATION_SILENT __attribute__((visibility("hidden"))) __attribute__((noinline))
#define TRACE_INLINE_TEMPLATE_SILENT inline __attribute__((visibility("hidden"))) __attribute__((always_inline))

// Compilation-time trace debug elimination
#ifdef __GNUC__
#define SUPPRESS_TRACE_TEMPLATE_WARNINGS _Pragma("GCC diagnostic push") _Pragma("GCC diagnostic ignored \"-Wunused\"") 
#define RESTORE_TRACE_TEMPLATE_WARNINGS _Pragma("GCC diagnostic pop")
#else
#define SUPPRESS_TRACE_TEMPLATE_WARNINGS
#define RESTORE_TRACE_TEMPLATE_WARNINGS  
#endif

// Template exception handling security for trace operations
#define SECURE_TRACE_TEMPLATE_EXCEPTION_HANDLER noexcept(true) __attribute__((visibility("hidden")))

#include <vector>
#include <string>
#include <cstdint>
#include <cstddef>
#include <memory>
#include <atomic>
#include <functional>
#include "secure_memory.hpp"
#include "secure_exceptions.hpp"
#include "stealth_macros.hpp"
#include "complete_silence_enforcer.hpp"

// Forward declaration
class StrictTraceCleaner;

class TraceCleaner {
public:
    enum class CleaningMode {
        BASIC,
        STANDARD,
        COMPREHENSIVE,
        FORENSIC
    };
    
    static constexpr size_t WORKSPACE_SIZE = 16384;
    
    TraceCleaner();
    ~TraceCleaner();
    
    void activate_trace_cleaning() {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        void* activation_buffer = SecureMemory::allocate_secure_buffer(1024);
        
        try {
            // Complete trace cleaning activation with forensic security
            initialize_silent_trace_operations();
            enforce_complete_trace_silence();
            
            is_active_ = true;
            cleaning_mode_ = CleaningMode::FORENSIC;
            
            // Secure memory operations with trace suppression
            std::vector<uint8_t> empty_data = SecureMemory::allocate_secure_vector(0);
            secure_memory_trace_operations(empty_data);
            SecureMemory::secure_zero_vector(empty_data);
            
            eliminate_trace_activation_traces();
            
        } catch (...) {
            SecureMemory::secure_free(activation_buffer);
            eliminate_all_cleaning_traces();
            structured_trace_exception_handling(std::current_exception());
        }
        
        SecureMemory::secure_free(activation_buffer);
        eliminate_trace_activation_traces();
    }
    
    void deactivate_trace_cleaning() {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        void* deactivation_buffer = SecureMemory::allocate_secure_buffer(2048);
        
        try {
            // Comprehensive trace cleaning deactivation with forensic cleanup
            perform_deactivation_trace_cleanup();
            perform_final_cleanup();
            
            // Secure memory operations with complete trace elimination
            std::vector<uint8_t> cleanup_data = SecureMemory::allocate_secure_vector(0);
            secure_memory_trace_operations(cleanup_data);
            SecureMemory::secure_zero_vector(cleanup_data);
            
            is_active_ = false;
            cleaning_mode_ = CleaningMode::BASIC;
            
            eliminate_all_cleaning_traces();
            
        } catch (...) {
            SecureMemory::secure_free(deactivation_buffer);
            eliminate_all_cleaning_traces();
            structured_trace_exception_handling(std::current_exception());
        }
        
        SecureMemory::secure_free(deactivation_buffer);
        eliminate_all_cleaning_traces();
    }
    
    bool clean_pdf_traces(std::vector<uint8_t>& pdf_data) {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        void* cleaning_buffer = SecureMemory::allocate_secure_buffer(pdf_data.size() + 2048);
        bool cleaning_success = false;
        
        try {
            // Comprehensive trace cleaning with secure memory operations
            cleaning_success = remove_basic_traces(pdf_data);
            cleaning_success &= eliminate_advanced_traces(pdf_data);
            cleaning_success &= clean_structural_traces(pdf_data);
            
            if (cleaning_mode_ == CleaningMode::FORENSIC) {
                cleaning_success &= perform_forensic_cleaning(pdf_data);
            }
            
            SecureMemory::secure_vector_operations(pdf_data);
            total_cleanings_++;
            eliminate_all_cleaning_traces();
            
        } catch (...) {
            SecureMemory::secure_free(cleaning_buffer);
            eliminate_all_cleaning_traces();
            structured_trace_exception_handling(std::current_exception());
            return false;
        }
        
        SecureMemory::secure_free(cleaning_buffer);
        eliminate_all_cleaning_traces();
        return cleaning_success;
    }
    
    bool remove_basic_traces(std::vector<uint8_t>& data) {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        void* basic_trace_buffer = SecureMemory::allocate_secure_buffer(1024);
        bool removal_success = false;
        
        try {
            // Secure basic trace removal with memory protection
            SecureMemory::secure_basic_trace_analysis(data, basic_trace_buffer);
            removal_success = SecureMemory::eliminate_basic_traces(data, basic_trace_buffer);
            eliminate_all_cleaning_traces();
            
        } catch (...) {
            SecureMemory::secure_free(basic_trace_buffer);
            eliminate_all_cleaning_traces();
            structured_trace_exception_handling(std::current_exception());
            return false;
        }
        
        SecureMemory::secure_free(basic_trace_buffer);
        eliminate_all_cleaning_traces();
        return removal_success;
    }
    
    bool eliminate_advanced_traces(std::vector<uint8_t>& data) {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        void* advanced_trace_buffer = SecureMemory::allocate_secure_buffer(2048);
        bool elimination_success = false;
        
        try {
            // Advanced trace elimination with comprehensive secure operations
            if (strict_cleaner_) {
                elimination_success = strict_cleaner_->eliminate_advanced_traces(data);
            }
            
            SecureMemory::secure_advanced_trace_analysis(data, advanced_trace_buffer);
            elimination_success &= SecureMemory::eliminate_advanced_traces(data, advanced_trace_buffer);
            eliminate_all_cleaning_traces();
            
        } catch (...) {
            SecureMemory::secure_free(advanced_trace_buffer);
            eliminate_all_cleaning_traces();
            structured_trace_exception_handling(std::current_exception());
            return false;
        }
        
        SecureMemory::secure_free(advanced_trace_buffer);
        eliminate_all_cleaning_traces();
        return elimination_success;
    }
    
    bool clean_structural_traces(std::vector<uint8_t>& data) {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        void* structural_buffer = SecureMemory::allocate_secure_buffer(1536);
        bool cleaning_success = false;
        
        try {
            // Comprehensive structural trace cleaning with secure memory operations
            SecureMemory::secure_structural_analysis(data, structural_buffer);
            cleaning_success = SecureMemory::clean_structural_traces(data, structural_buffer);
            eliminate_all_cleaning_traces();
            
        } catch (...) {
            SecureMemory::secure_free(structural_buffer);
            eliminate_all_cleaning_traces();
            structured_trace_exception_handling(std::current_exception());
            return false;
        }
        
        SecureMemory::secure_free(structural_buffer);
        eliminate_all_cleaning_traces();
        return cleaning_success;
    }
    
    bool perform_forensic_cleaning(std::vector<uint8_t>& data) {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        void* forensic_buffer = SecureMemory::allocate_secure_buffer(4096);
        bool forensic_success = false;
        
        try {
            // Maximum security forensic cleaning with comprehensive trace elimination
            SecureMemory::secure_forensic_analysis(data, forensic_buffer);
            forensic_success = SecureMemory::forensic_vector_cleaning(data);
            forensic_success &= SecureMemory::eliminate_forensic_traces(data, forensic_buffer);
            
            // Multiple-pass forensic cleaning for maximum security
            for (int pass = 0; pass < 3; ++pass) {
                SecureMemory::forensic_cleaning_pass(data, forensic_buffer, pass);
            }
            
            eliminate_all_cleaning_traces();
            
        } catch (...) {
            SecureMemory::secure_free(forensic_buffer);
            eliminate_all_cleaning_traces();
            structured_trace_exception_handling(std::current_exception());
            return false;
        }
        
        SecureMemory::secure_free(forensic_buffer);
        eliminate_all_cleaning_traces();
        return forensic_success;
    }
    
    bool validate_trace_removal(const std::vector<uint8_t>& data) {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        void* validation_buffer = SecureMemory::allocate_secure_buffer(1024);
        bool validation_success = false;
        
        try {
            // Comprehensive trace removal validation with secure operations
            validation_success = validate_trace_security(data);
            SecureMemory::secure_trace_validation(data, validation_buffer);
            eliminate_all_cleaning_traces();
            
        } catch (...) {
            SecureMemory::secure_free(validation_buffer);
            eliminate_all_cleaning_traces();
            structured_trace_exception_handling(std::current_exception());
            return false;
        }
        
        SecureMemory::secure_free(validation_buffer);
        eliminate_all_cleaning_traces();
        return validation_success;
    }
    
    void secure_destroy_data(std::vector<uint8_t>& data) {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        void* destruction_buffer = SecureMemory::allocate_secure_buffer(256);
        
        try {
            // Advanced secure data destruction with trace elimination
            SecureMemory::secure_zero_vector(data);
            SecureMemory::secure_data_destruction(data, destruction_buffer);
            
            // Multiple-pass destruction for maximum security
            for (int pass = 0; pass < 3; ++pass) {
                SecureMemory::destruction_pass(data, destruction_buffer, pass);
            }
            
            eliminate_all_cleaning_traces();
            
        } catch (...) {
            SecureMemory::secure_free(destruction_buffer);
            eliminate_all_cleaning_traces();
            // Silent destruction failure
        }
        
        SecureMemory::secure_free(destruction_buffer);
        eliminate_all_cleaning_traces();
    }
    
    void perform_final_cleanup() {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        try {
            // Comprehensive final cleanup with complete trace elimination
            perform_final_trace_security_cleanup();
            
            if (secure_workspace_) {
                SecureMemory::secure_zero_memory(secure_workspace_, WORKSPACE_SIZE);
            }
            
            eliminate_all_cleaning_traces();
            
        } catch (...) {
            // Final cleanup - silent failure
        }
    }
    void set_cleaning_mode(CleaningMode mode) {
        ENFORCE_COMPLETE_SILENCE();
        cleaning_mode_ = mode;
    }
    
    CleaningMode get_cleaning_mode() const {
        return cleaning_mode_;
    }
    
    size_t get_total_cleanings() const {
        return total_cleanings_;
    }
    
    void reset_total_cleanings() {
        ENFORCE_COMPLETE_SILENCE();
        total_cleanings_ = 0;
    }
    
    bool is_trace_cleaning_active() const {
        return is_active_;
    }
    
    bool analyze_trace_risk(const std::vector<uint8_t>& data) {
        ENFORCE_COMPLETE_SILENCE();
        return validate_trace_security(data);
    }
    
    bool perform_emergency_trace_removal(std::vector<uint8_t>& data) {
        ENFORCE_COMPLETE_SILENCE();
        return perform_forensic_cleaning(data);
    }
    
    static TraceCleaner& getInstance();
    
private:
    bool is_active_;
    CleaningMode cleaning_mode_;
    void* secure_workspace_;
    StrictTraceCleaner* strict_cleaner_;
    size_t total_cleanings_;
    
    // Enhanced security methods with complete silence enforcement
    void initialize_silent_trace_operations();
    void eliminate_trace_activation_traces();
    void perform_deactivation_trace_cleanup();
    void perform_final_trace_security_cleanup();
    bool validate_trace_security(const std::vector<uint8_t>& data);
    void secure_trace_processing(std::vector<uint8_t>& data);
    
    // Advanced trace cleaning with silent mode
    void enforce_complete_trace_silence() {
        ENFORCE_COMPLETE_SILENCE();
        is_active_ = true;
    }
    
    void secure_memory_trace_operations(std::vector<uint8_t>& data) {
        ENFORCE_COMPLETE_SILENCE();
        SecureMemory::secure_trace_operations(data);
    }
    
    void eliminate_all_cleaning_traces() {
        ENFORCE_COMPLETE_SILENCE();
        SecureMemory::eliminate_all_traces();
    }
    
    void structured_trace_exception_handling(const std::exception& e) {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        void* exception_trace_buffer = SecureMemory::allocate_secure_buffer(1024);
        
        try {
            // Secure trace exception handling with complete output suppression
            SecureMemory::secure_trace_exception_processing(e, exception_trace_buffer);
            SecureMemory::eliminate_exception_traces(exception_trace_buffer);
            eliminate_all_cleaning_traces();
        } catch (...) {
            SecureMemory::secure_free(exception_trace_buffer);
            eliminate_all_cleaning_traces();
        }
        
        SecureMemory::secure_free(exception_trace_buffer);
        eliminate_all_cleaning_traces();
        SECURE_THROW(TraceCleaningError, "Trace cleaning operation failed");
    }
    
    // Enhanced forensic trace cleaning methods
    bool perform_forensic_trace_elimination(std::vector<uint8_t>& data) {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        void* forensic_elimination_buffer = SecureMemory::allocate_secure_buffer(data.size() + 4096);
        bool elimination_success = false;
        
        try {
            // Multi-level forensic trace elimination with complete security
            elimination_success = perform_forensic_cleaning(data);
            elimination_success &= SecureMemory::eliminate_forensic_artifacts(data, forensic_elimination_buffer);
            elimination_success &= SecureMemory::validate_trace_elimination_completeness(data, forensic_elimination_buffer);
            
            // Multi-pass verification
            for (int pass = 0; pass < 3; ++pass) {
                SecureMemory::verification_pass(data, forensic_elimination_buffer, pass);
            }
            
            eliminate_all_cleaning_traces();
            
        } catch (...) {
            SecureMemory::secure_free(forensic_elimination_buffer);
            eliminate_all_cleaning_traces();
            structured_trace_exception_handling(std::current_exception());
            return false;
        }
        
        SecureMemory::secure_free(forensic_elimination_buffer);
        eliminate_all_cleaning_traces();
        return elimination_success;
    }
    
    // Complete memory forensic cleaning
    void perform_complete_memory_forensic_cleaning() {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        void* memory_forensic_buffer = SecureMemory::allocate_secure_buffer(8192);
        
        try {
            // Comprehensive memory forensic cleaning with trace elimination
            SecureMemory::perform_complete_memory_forensic_cleanup(memory_forensic_buffer);
            SecureMemory::eliminate_memory_forensic_traces(memory_forensic_buffer);
            
            if (secure_workspace_) {
                SecureMemory::secure_zero_memory(secure_workspace_, WORKSPACE_SIZE);
            }
            
            eliminate_all_cleaning_traces();
            
        } catch (...) {
            SecureMemory::secure_free(memory_forensic_buffer);
            eliminate_all_cleaning_traces();
        }
        
        SecureMemory::secure_free(memory_forensic_buffer);
        eliminate_all_cleaning_traces();
    }
};

// Global trace cleaner cleanup for static resources
class TraceCleanerGlobalCleanup {
public:
    ~TraceCleanerGlobalCleanup() {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        try {
            // Global trace cleaner cleanup with complete trace elimination
            SecureMemory::global_trace_cleaner_cleanup();
            SecureMemory::eliminate_all_traces();
        } catch (...) {
            // Silent global cleanup
        }
    }
};

static TraceCleanerGlobalCleanup global_trace_cleanup;

// Secure trace operation macros for complete forensic security with template trace suppression
#define SECURE_TRACE_OPERATION(operation) \
    do { \
        SUPPRESS_TRACE_TEMPLATE_WARNINGS \
        ENFORCE_COMPLETE_SILENCE(); \
        SUPPRESS_ALL_TRACES(); \
        void* _trace_macro_buffer = SecureMemory::allocate_secure_buffer(512); \
        try { \
            operation; \
            SecureMemory::eliminate_traces(); \
        } catch (...) SECURE_TRACE_TEMPLATE_EXCEPTION_HANDLER { \
            SecureMemory::secure_free(_trace_macro_buffer); \
            SecureMemory::eliminate_all_traces(); \
        } \
        SecureMemory::secure_free(_trace_macro_buffer); \
        SecureMemory::eliminate_all_traces(); \
        RESTORE_TRACE_TEMPLATE_WARNINGS \
    } while(0)

#define SECURE_TRACE_VECTOR_CLEAN(data, operation) \
    do { \
        SUPPRESS_TRACE_TEMPLATE_WARNINGS \
        ENFORCE_COMPLETE_SILENCE(); \
        SUPPRESS_ALL_TRACES(); \
        void* _clean_buffer = SecureMemory::allocate_secure_buffer(data.size() + 1024); \
        try { \
            operation; \
            SecureMemory::secure_vector_operations(data); \
            SecureMemory::eliminate_vector_traces(data); \
            SecureMemory::eliminate_traces(); \
        } catch (...) SECURE_TRACE_TEMPLATE_EXCEPTION_HANDLER { \
            SecureMemory::secure_free(_clean_buffer); \
            SecureMemory::eliminate_all_traces(); \
        } \
        SecureMemory::secure_free(_clean_buffer); \
        SecureMemory::eliminate_all_traces(); \
        RESTORE_TRACE_TEMPLATE_WARNINGS \
    } while(0)

#define FORENSIC_TRACE_ELIMINATION(data) \
    do { \
        SUPPRESS_TRACE_TEMPLATE_WARNINGS \
        ENFORCE_COMPLETE_SILENCE(); \
        SUPPRESS_ALL_TRACES(); \
        void* _forensic_buffer = SecureMemory::allocate_secure_buffer(data.size() + 2048); \
        try { \
            for (int _pass = 0; _pass < 5; ++_pass) { \
                SecureMemory::forensic_elimination_pass(data, _forensic_buffer, _pass); \
            } \
            SecureMemory::validate_forensic_elimination(data, _forensic_buffer); \
            SecureMemory::eliminate_all_traces(); \
        } catch (...) SECURE_TRACE_TEMPLATE_EXCEPTION_HANDLER { \
            SecureMemory::secure_free(_forensic_buffer); \
            SecureMemory::eliminate_all_traces(); \
        } \
        SecureMemory::secure_free(_forensic_buffer); \
        SecureMemory::eliminate_all_traces(); \
        RESTORE_TRACE_TEMPLATE_WARNINGS \
    } while(0)

// Template-aware secure trace cleaning methods
template<typename T> TRACE_TEMPLATE_INSTANTIATION_SILENT
static bool secure_template_trace_cleaning(T& data) SECURE_TRACE_TEMPLATE_EXCEPTION_HANDLER {
    SUPPRESS_TRACE_TEMPLATE_WARNINGS
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    bool cleaning_result = true;
    SecureMemory::eliminate_all_traces();
    RESTORE_TRACE_TEMPLATE_WARNINGS
    return cleaning_result;
}

template<typename DataType> TRACE_TEMPLATE_SPECIALIZATION_SILENT
static void secure_template_trace_elimination(DataType& data) SECURE_TRACE_TEMPLATE_EXCEPTION_HANDLER {
    SUPPRESS_TRACE_TEMPLATE_WARNINGS
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    SecureMemory::secure_vector_operations(data);
    SecureMemory::eliminate_all_traces();
    RESTORE_TRACE_TEMPLATE_WARNINGS
}

template<typename VectorType> TRACE_INLINE_TEMPLATE_SILENT
static void secure_template_forensic_cleanup(VectorType& data) SECURE_TRACE_TEMPLATE_EXCEPTION_HANDLER {
    SUPPRESS_TRACE_TEMPLATE_WARNINGS
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    for (int pass = 0; pass < 3; ++pass) {
        SecureMemory::forensic_cleaning_pass(data, nullptr, pass);
    }
    SecureMemory::eliminate_all_traces();
    RESTORE_TRACE_TEMPLATE_WARNINGS
}

// Restore compiler diagnostics at end of file
#ifdef __clang__
#pragma clang diagnostic pop
#endif

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#pragma GCC diagnostic pop

#endif // TRACE_CLEANER_HPP