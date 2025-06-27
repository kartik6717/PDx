#pragma once

#include "logger.hpp"
#include <functional>
#include <memory>
#include <map>
#include <vector>
#include <chrono>
#include <future>
#include <queue>

// Error categories for different types of errors
enum class ErrorCategory {
    SYSTEM_ERROR,
    PARSING_ERROR,
    VALIDATION_ERROR,
    SECURITY_ERROR,
    MEMORY_ERROR,
    IO_ERROR,
    NETWORK_ERROR,
    CONFIG_ERROR,
    AUTHENTICATION_ERROR,
    AUTHORIZATION_ERROR,
    TIMEOUT_ERROR,
    RESOURCE_ERROR
};

// Error recovery strategies
enum class RecoveryStrategy {
    NONE,           // No recovery possible
    RETRY,          // Retry the operation
    FALLBACK,       // Use fallback mechanism
    SKIP,           // Skip and continue
    ABORT,          // Abort current operation
    RESTART,        // Restart component
    ESCALATE        // Escalate to higher level
};

// Error context for detailed error information
struct ErrorContext {
    std::string operation;
    std::string component;
    std::string user_id;
    std::string session_id;
    std::string resource;
    std::map<std::string, std::string> parameters;
    std::chrono::system_clock::time_point occurrence_time;
    size_t attempt_count;
    std::vector<std::string> call_stack;
};

// Recovery action definition
struct RecoveryAction {
    RecoveryStrategy strategy;
    std::function<bool(const ErrorContext&)> action;
    std::chrono::milliseconds delay;
    size_t max_attempts;
    std::string description;
};

// Exception hierarchy for different error types
class PDFToolException : public std::exception {
public:
    PDFToolException(const std::string& message, ErrorCategory category,
                     ErrorSeverity severity = ErrorSeverity::MEDIUM,
                     const std::string& error_code = "");
    
    virtual ~PDFToolException() = default;
    
    const char* what() const noexcept override;
    ErrorCategory category() const noexcept;
    ErrorSeverity severity() const noexcept;
    const std::string& error_code() const noexcept;
    void set_context(const ErrorContext& context);
    const ErrorContext& context() const noexcept;

protected:
    std::string message_;
    ErrorCategory category_;
    ErrorSeverity severity_;
    std::string error_code_;
    ErrorContext context_;
};

// Specific exception types
class ParseException : public PDFToolException {
public:
    ParseException(const std::string& message, const std::string& file_path = "",
                   size_t position = 0, const std::string& expected = "");
    
    const std::string& file_path() const;
    size_t position() const;
    const std::string& expected() const;

private:
    std::string file_path_;
    size_t position_;
    std::string expected_;
};

class ValidationException : public PDFToolException {
public:
    ValidationException(const std::string& message, const std::string& field = "",
                       const std::string& value = "", const std::string& constraint = "");
    
    const std::string& field() const;
    const std::string& value() const;
    const std::string& constraint() const;

private:
    std::string field_;
    std::string value_;
    std::string constraint_;
};

class SecurityException : public PDFToolException {
public:
    SecurityException(const std::string& message, const std::string& threat_type = "",
                     const std::string& source = "");
    
    const std::string& threat_type() const;
    const std::string& source() const;

private:
    std::string threat_type_;
    std::string source_;
};

class ResourceException : public PDFToolException {
public:
    ResourceException(const std::string& message, const std::string& resource_type = "",
                     size_t requested = 0, size_t available = 0);
    
    const std::string& resource_type() const;
    size_t requested() const;
    size_t available() const;

private:
    std::string resource_type_;
    size_t requested_;
    size_t available_;
};

// Circuit breaker for preventing cascading failures
class CircuitBreaker {
public:
    enum class State {
        CLOSED,     // Normal operation
        OPEN,       // Blocking requests
        HALF_OPEN   // Testing if service is recovered
    };
    
    CircuitBreaker(const std::string& name, size_t failure_threshold = 5,
                   std::chrono::milliseconds timeout = std::chrono::milliseconds(60000));
    
    template<typename Func>
    auto execute(Func&& func) -> decltype(func()) {
        if (state_ == State::OPEN) {
            if (std::chrono::steady_clock::now() - last_failure_time_ > timeout_) {
                state_ = State::HALF_OPEN;
                test_request_count_ = 0;
            } else {
                SecureExceptions::ExceptionHandler::handle_exception(
                    SecureExceptions::SecurityViolationException("Circuit breaker is OPEN"));
            }
        }
        
        try {
            auto result = func();
            on_success();
            return result;
        } catch (...) {
            on_failure();
            throw;
        }
    }
    
    State get_state() const;
    size_t get_failure_count() const;
    std::chrono::steady_clock::time_point get_last_failure_time() const;

private:
    void on_success();
    void on_failure();
    
    std::string name_;
    State state_;
    size_t failure_count_;
    size_t failure_threshold_;
    std::chrono::milliseconds timeout_;
    std::chrono::steady_clock::time_point last_failure_time_;
    size_t test_request_count_;
    mutable std::mutex mutex_;
};

// Retry policy for failed operations
class RetryPolicy {
public:
    RetryPolicy(size_t max_attempts = 3, std::chrono::milliseconds initial_delay = std::chrono::milliseconds(1000),
                double backoff_multiplier = 2.0, std::chrono::milliseconds max_delay = std::chrono::milliseconds(30000));
    
    template<typename Func>
    auto execute(Func&& func, const std::string& operation = "") -> decltype(func()) {
        size_t attempt = 0;
        auto delay = initial_delay_;
        
        while (attempt < max_attempts_) {
            try {
                attempt++;
                LOG_DEBUG("Attempting operation: " + operation + " (attempt " + 
                         std::to_string(attempt) + "/" + std::to_string(max_attempts_) + ")");
                
                return func();
            } catch (const PDFToolException& e) {
                if (attempt >= max_attempts_ || !is_retryable(e.category())) {
                    LOG_ERROR("Operation failed after " + std::to_string(attempt) + 
                             " attempts: " + e.what());
                    throw;
                }
                
                LOG_WARN("Operation failed, retrying in " + std::to_string(delay.count()) + 
                        "ms: " + e.what());
                
                std::this_thread::sleep_for(delay);
                delay = std::min(static_cast<std::chrono::milliseconds>(
                    static_cast<long long>(delay.count() * backoff_multiplier_)), max_delay_);
            }
        }
        
        SecureExceptions::ExceptionHandler::handle_exception(
            SecureExceptions::SecurityViolationException("Max retry attempts exceeded"));
    }
    
    bool is_retryable(ErrorCategory category);

private:
    size_t max_attempts_;
    std::chrono::milliseconds initial_delay_;
    double backoff_multiplier_;
    std::chrono::milliseconds max_delay_;
};

// Error recovery manager
class ErrorRecoveryManager {
public:
    static ErrorRecoveryManager& getInstance();
    
    // Register recovery actions for specific error types
    void register_recovery_action(ErrorCategory category, const RecoveryAction& action);
    void register_recovery_action(const std::string& error_code, const RecoveryAction& action);
    
    // Attempt to recover from an error
    bool attempt_recovery(const PDFToolException& error);
    bool attempt_recovery(const ErrorContext& context, ErrorCategory category);
    
    // Get recovery statistics
    struct RecoveryStats {
        size_t total_attempts;
        size_t successful_recoveries;
        size_t failed_recoveries;
        std::map<ErrorCategory, size_t> category_attempts;
        std::map<RecoveryStrategy, size_t> strategy_usage;
    };
    
    RecoveryStats get_statistics() const;
    void reset_statistics();

private:
    ErrorRecoveryManager() = default;
    
    std::map<ErrorCategory, std::vector<RecoveryAction>> category_actions_;
    std::map<std::string, std::vector<RecoveryAction>> code_actions_;
    
    mutable std::mutex mutex_;
    RecoveryStats stats_;
};

// RAII error context manager
class ErrorContextManager {
public:
    ErrorContextManager(const std::string& operation, const std::string& component = "");
    ~ErrorContextManager();
    
    void add_parameter(const std::string& key, const std::string& value);
    void set_resource(const std::string& resource);
    void set_user_id(const std::string& user_id);
    void set_session_id(const std::string& session_id);
    
    ErrorContext get_context() const;

private:
    ErrorContext context_;
};

// Exception safety guarantees helper
template<typename Func>
class ExceptionSafeGuard {
public:
    ExceptionSafeGuard(Func&& cleanup_func) : cleanup_func_(std::forward<Func>(cleanup_func)), active_(true) {}
    
    ~ExceptionSafeGuard() {
        if (active_) {
            try {
                cleanup_func_();
            } catch (...) {
                // Log cleanup error but don't throw
                LOG_ERROR("Exception during cleanup operation");
            }
        }
    }
    
    void dismiss() { active_ = false; }

private:
    Func cleanup_func_;
    bool active_;
};

// Helper function to create exception safe guards
template<typename Func>
auto make_exception_guard(Func&& func) {
    return ExceptionSafeGuard<Func>(std::forward<Func>(func));
}

// Deadlock detection and prevention
class DeadlockDetector {
public:
    static DeadlockDetector& getInstance();
    
    void register_lock_order(const std::string& lock1, const std::string& lock2);
    bool would_cause_deadlock(const std::string& current_lock, const std::string& requested_lock);
    void report_potential_deadlock(const std::string& lock1, const std::string& lock2);

private:
    DeadlockDetector() = default;
    
    std::map<std::string, std::vector<std::string>> lock_dependencies_;
    mutable std::mutex mutex_;
};

// Memory leak detection helper
class MemoryTracker {
public:
    static MemoryTracker& getInstance();
    
    void register_allocation(void* ptr, size_t size, const std::string& component);
    void register_deallocation(void* ptr);
    
    struct MemoryStats {
        size_t total_allocated;
        size_t total_deallocated;
        size_t current_usage;
        size_t peak_usage;
        std::map<std::string, size_t> component_usage;
        std::vector<std::string> potential_leaks;
    };
    
    MemoryStats get_statistics() const;
    void check_for_leaks();

private:
    MemoryTracker() = default;
    
    struct AllocationInfo {
        size_t size;
        std::string component;
        std::chrono::system_clock::time_point timestamp;
    };
    
    std::map<void*, AllocationInfo> allocations_;
    MemoryStats stats_;
    mutable std::mutex mutex_;
};

// Error reporting and alerting
class ErrorReporter {
public:
    static ErrorReporter& getInstance();
    
    void report_error(const PDFToolException& error);
    void report_critical_error(const PDFToolException& error);
    void send_alert(const std::string& message, ErrorSeverity severity);
    
    void set_alert_threshold(ErrorCategory category, size_t count, std::chrono::minutes window);
    void enable_email_alerts(const std::string& smtp_server, const std::vector<std::string>& recipients);
    void enable_webhook_alerts(const std::string& webhook_url);

private:
    ErrorReporter() = default;
    
    struct AlertThreshold {
        size_t count;
        std::chrono::minutes window;
        std::queue<std::chrono::system_clock::time_point> occurrences;
    };
    
    std::map<ErrorCategory, AlertThreshold> thresholds_;
    std::string smtp_server_;
    std::vector<std::string> email_recipients_;
    std::string webhook_url_;
    
    mutable std::mutex mutex_;
};

// Macros for convenient error handling
#define SAFE_EXECUTE(operation, error_category) \
    try { \
        operation; \
    } catch (const std::exception& e) { \
        LOG_ERROR("Operation failed: " + std::string(e.what())); \
        SecureExceptions::ExceptionHandler::handle_exception( \
            SecureExceptions::SecurityViolationException(e.what())); \
    }

#define WITH_ERROR_CONTEXT(operation, component) \
    ErrorContextManager _error_ctx(operation, component); \
    auto _guard = make_exception_guard([&]() { \
        LOG_ERROR("Exception in " + std::string(operation)); \
    });

#define RETRY_ON_FAILURE(operation, max_attempts) \
    RetryPolicy _retry_policy(max_attempts); \
    _retry_policy.execute([&]() { operation; }, #operation)

#define WITH_CIRCUIT_BREAKER(name, operation) \
    static CircuitBreaker _cb(name); \
    _cb.execute([&]() { operation; })

#define VALIDATE_PARAMETER(condition, parameter, value) \
    if (!(condition)) { \
        SecureExceptions::ExceptionHandler::handle_exception( \
            SecureExceptions::InvalidInputException("Invalid parameter: " #parameter)); \
    }

#define VALIDATE_NOT_NULL(pointer, name) \
    if ((pointer) == nullptr) { \
        SecureExceptions::ExceptionHandler::handle_exception( \
            SecureExceptions::InvalidInputException("Null pointer: " #name)); \
    }

#define VALIDATE_RANGE(value, min_val, max_val, name) \
    if ((value) < (min_val) || (value) > (max_val)) { \
        SecureExceptions::ExceptionHandler::handle_exception( \
            SecureExceptions::InvalidInputException("Value out of range: " #name)); \
    }

// Utility functions
std::string format_exception(const std::exception& e);
std::string get_stack_trace();
std::string get_error_code(ErrorCategory category, const std::string& specific_code = "");
bool is_recoverable_error(ErrorCategory category);
ErrorSeverity categorize_error_severity(const std::exception& e);
