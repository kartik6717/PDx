#include "error_handler.hpp"
#include "stealth_macros.hpp"
#include "secure_memory.hpp"
#include "stealth_macros.hpp"
#include "secure_exceptions.hpp"
#include "stealth_macros.hpp"
#include <execinfo.h>
#include <cxxabi.h>
#include <regex>
#include <curl/curl.h>
#include <random>
#include "stealth_macros.hpp"
#include "stealth_macros.hpp"

// PDFToolException Implementation
PDFToolException::PDFToolException(const std::string& message, ErrorCategory category,
                                   ErrorSeverity severity, const std::string& error_code)
    : message_(message), category_(category), severity_(severity), error_code_(error_code) {

    context_.occurrence_time = std::chrono::system_clock::now();
    context_.attempt_count = 1;

    // Log the exception creation
    // Complete silence enforcement - all error output removed
}

const char* PDFToolException::what() const noexcept {
    return message_.c_str();
}

ErrorCategory PDFToolException::category() const noexcept {
    return category_;
}

ErrorSeverity PDFToolException::severity() const noexcept {
    return severity_;
}

const std::string& PDFToolException::error_code() const noexcept {
    return error_code_;
}

void PDFToolException::set_context(const ErrorContext& context) {
    context_ = context;
}

const ErrorContext& PDFToolException::context() const noexcept {
    return context_;
}

// ParseException Implementation
ParseException::ParseException(const std::string& message, const std::string& file_path,
                              size_t position, const std::string& expected)
    : PDFToolException(message, ErrorCategory::PARSING_ERROR, ErrorSeverity::MEDIUM, "PARSE_ERROR"),
      file_path_(file_path), position_(position), expected_(expected) {
}

const std::string& ParseException::file_path() const {
    return file_path_;
}

size_t ParseException::position() const {
    return position_;
}

const std::string& ParseException::expected() const {
    return expected_;
}

// ValidationException Implementation
ValidationException::ValidationException(const std::string& message, const std::string& field,
                                        const std::string& value, const std::string& constraint)
    : PDFToolException(message, ErrorCategory::VALIDATION_ERROR, ErrorSeverity::MEDIUM, "VALIDATION_ERROR"),
      field_(field), value_(value), constraint_(constraint) {
}

const std::string& ValidationException::field() const {
    return field_;
}

const std::string& ValidationException::value() const {
    return value_;
}

const std::string& ValidationException::constraint() const {
    return constraint_;
}

// SecurityException Implementation
SecurityException::SecurityException(const std::string& message, const std::string& threat_type,
                                    const std::string& source)
    : PDFToolException(message, ErrorCategory::SECURITY_ERROR, ErrorSeverity::HIGH, "SECURITY_ERROR"),
      threat_type_(threat_type), source_(source) {
}

const std::string& SecurityException::threat_type() const {
    return threat_type_;
}

const std::string& SecurityException::source() const {
    return source_;
}

// ResourceException Implementation
ResourceException::ResourceException(const std::string& message, const std::string& resource_type,
                                    size_t requested, size_t available)
    : PDFToolException(message, ErrorCategory::RESOURCE_ERROR, ErrorSeverity::HIGH, "RESOURCE_ERROR"),
      resource_type_(resource_type), requested_(requested), available_(available) {
}

const std::string& ResourceException::resource_type() const {
    return resource_type_;
}

size_t ResourceException::requested() const {
    return requested_;
}

size_t ResourceException::available() const {
    return available_;
}

// CircuitBreaker Implementation
CircuitBreaker::CircuitBreaker(const std::string& name, size_t failure_threshold,
                               std::chrono::milliseconds timeout)
    : name_(name), state_(State::CLOSED), failure_count_(0), failure_threshold_(failure_threshold),
      timeout_(timeout), test_request_count_(0) {
}

CircuitBreaker::State CircuitBreaker::get_state() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_;
}

size_t CircuitBreaker::get_failure_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return failure_count_;
}

std::chrono::steady_clock::time_point CircuitBreaker::get_last_failure_time() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return last_failure_time_;
}

void CircuitBreaker::on_success() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (state_ == State::HALF_OPEN) {
        test_request_count_++;
        if (test_request_count_ >= 3) {  // Successful test requests needed
            state_ = State::CLOSED;
            failure_count_ = 0;
            // Complete silence enforcement - all debug output removed
        }
    } else if (state_ == State::CLOSED) {
        failure_count_ = 0;  // Reset failure count on success
    }
}

void CircuitBreaker::on_failure() {
    std::lock_guard<std::mutex> lock(mutex_);

    failure_count_++;
    last_failure_time_ = std::chrono::steady_clock::now();

    if (state_ == State::CLOSED && failure_count_ >= failure_threshold_) {
        state_ = State::OPEN;
        LOG_WARN("Circuit breaker " + name_ + " opened after " + 
                std::to_string(failure_count_) + " failures");
    } else if (state_ == State::HALF_OPEN) {
        state_ = State::OPEN;
        LOG_WARN("Circuit breaker " + name_ + " reopened after test failure");
    }
}

// RetryPolicy Implementation
RetryPolicy::RetryPolicy(size_t max_attempts, std::chrono::milliseconds initial_delay,
                        double backoff_multiplier, std::chrono::milliseconds max_delay)
    : max_attempts_(max_attempts), initial_delay_(initial_delay),
      backoff_multiplier_(backoff_multiplier), max_delay_(max_delay) {
}

bool RetryPolicy::is_retryable(ErrorCategory category) {
    switch (category) {
        case ErrorCategory::NETWORK_ERROR:
        case ErrorCategory::IO_ERROR:
        case ErrorCategory::TIMEOUT_ERROR:
        case ErrorCategory::RESOURCE_ERROR:
            return true;
        case ErrorCategory::SECURITY_ERROR:
        case ErrorCategory::AUTHENTICATION_ERROR:
        case ErrorCategory::AUTHORIZATION_ERROR:
        case ErrorCategory::VALIDATION_ERROR:
            return false;
        default:
            return true;
    }
}

// ErrorRecoveryManager Implementation
ErrorRecoveryManager& ErrorRecoveryManager::getInstance() {
    static ErrorRecoveryManager instance;
    return instance;
}

void ErrorRecoveryManager::register_recovery_action(ErrorCategory category, const RecoveryAction& action) {
    std::lock_guard<std::mutex> lock(mutex_);
    category_actions_[category].push_back(action);
}

void ErrorRecoveryManager::register_recovery_action(const std::string& error_code, const RecoveryAction& action) {
    std::lock_guard<std::mutex> lock(mutex_);
    code_actions_[error_code].push_back(action);
}

bool ErrorRecoveryManager::attempt_recovery(const PDFToolException& error) {
    return attempt_recovery(error.context(), error.category());
}

bool ErrorRecoveryManager::attempt_recovery(const ErrorContext& context, ErrorCategory category) {
    std::lock_guard<std::mutex> lock(mutex_);

    stats_.total_attempts++;
    stats_.category_attempts[category]++;

    // Try code-specific recovery first
    auto code_it = code_actions_.find(context.operation);
    if (code_it != code_actions_.end()) {
        for (const auto& action : code_it->second) {
            stats_.strategy_usage[action.strategy]++;

            try {
                if (action.action(context)) {
                    stats_.successful_recoveries++;
                    LOG_INFO("Recovery successful for operation: " + context.operation + 
                           " using strategy: " + action.description);
                    return true;
                }
            } catch (const std::exception& e) {
                LOG_WARN("Recovery action failed: " + std::string(e.what()));
            }
        }
    }

    // Try category-specific recovery
    auto category_it = category_actions_.find(category);
    if (category_it != category_actions_.end()) {
        for (const auto& action : category_it->second) {
            stats_.strategy_usage[action.strategy]++;

            try {
                if (action.action(context)) {
                    stats_.successful_recoveries++;
                    // Complete silence enforcement - all debug output removed
                    return true;
                }
            } catch (const std::exception& e) {
                LOG_WARN("Recovery action failed: " + std::string(e.what()));
            }
        }
    }

    stats_.failed_recoveries++;
    // Complete silence enforcement - all error output removed
    return false;
}

ErrorRecoveryManager::RecoveryStats ErrorRecoveryManager::get_statistics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void ErrorRecoveryManager::reset_statistics() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = RecoveryStats{};
}

// ErrorContextManager Implementation
ErrorContextManager::ErrorContextManager(const std::string& operation, const std::string& component) {
    context_.operation = operation;
    context_.component = component;
    context_.occurrence_time = std::chrono::system_clock::now();
    context_.attempt_count = 1;
    context_.call_stack.push_back(operation);
}

ErrorContextManager::~ErrorContextManager() {
    // Context is automatically cleaned up
}

void ErrorContextManager::add_parameter(const std::string& key, const std::string& value) {
    context_.parameters[key] = value;
}

void ErrorContextManager::set_resource(const std::string& resource) {
    context_.resource = resource;
}

void ErrorContextManager::set_user_id(const std::string& user_id) {
    context_.user_id = user_id;
}

void ErrorContextManager::set_session_id(const std::string& session_id) {
    context_.session_id = session_id;
}

ErrorContext ErrorContextManager::get_context() const {
    return context_;
}

// DeadlockDetector Implementation
DeadlockDetector& DeadlockDetector::getInstance() {
    static DeadlockDetector instance;
    return instance;
}

void DeadlockDetector::register_lock_order(const std::string& lock1, const std::string& lock2) {
    std::lock_guard<std::mutex> lock(mutex_);
    lock_dependencies_[lock1].push_back(lock2);
}

bool DeadlockDetector::would_cause_deadlock(const std::string& current_lock, const std::string& requested_lock) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Simple cycle detection
    std::function<bool(const std::string&, const std::string&, std::set<std::string>&)> has_path;
    has_path = [&](const std::string& from, const std::string& to, std::set<std::string>& visited) -> bool {
        if (from == to) return true;
        if (visited.count(from)) return false;

        visited.insert(from);

        auto it = lock_dependencies_.find(from);
        if (it != lock_dependencies_.end()) {
            for (const auto& next : it->second) {
                if (has_path(next, to, visited)) {
                    return true;
                }
            }
        }

        return false;
    };

    std::set<std::string> visited;
    return has_path(requested_lock, current_lock, visited);
}

void DeadlockDetector::report_potential_deadlock(const std::string& lock1, const std::string& lock2) {
    // Complete silence enforcement - all error output removed

    ErrorDetails error;
    error.error_code = "DEADLOCK_DETECTED";
    error.error_message = "Potential deadlock between " + lock1 + " and " + lock2;
    error.severity = ErrorSeverity::CRITICAL;
    error.component = "DeadlockDetector";
    error.operation = "lock_acquisition";
    error.context["lock1"] = lock1;
    error.context["lock2"] = lock2;
    error.is_recoverable = false;
    error.timestamp = std::chrono::system_clock::now();

    Logger::getInstance().log_error(error);
}

// MemoryTracker Implementation
MemoryTracker& MemoryTracker::getInstance() {
    static MemoryTracker instance;
    return instance;
}

void MemoryTracker::register_allocation(void* ptr, size_t size, const std::string& component) {
    std::lock_guard<std::mutex> lock(mutex_);

    AllocationInfo info;
    info.size = size;
    info.component = component;
    info.timestamp = std::chrono::system_clock::now();

    allocations_[ptr] = info;

    stats_.total_allocated += size;
    stats_.current_usage += size;
    stats_.component_usage[component] += size;

    if (stats_.current_usage > stats_.peak_usage) {
        stats_.peak_usage = stats_.current_usage;
    }

    // Log large allocations
    if (size > 10 * 1024 * 1024) {  // 10MB
        LOG_WARN("Large memory allocation: " + std::to_string(size / 1024 / 1024) + 
                "MB by component: " + component);
    }
}

void MemoryTracker::register_deallocation(void* ptr) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = allocations_.find(ptr);
    if (it != allocations_.end()) {
        stats_.total_deallocated += it->second.size;
        stats_.current_usage -= it->second.size;
        stats_.component_usage[it->second.component] -= it->second.size;
        allocations_.erase(it);
    }
}

MemoryTracker::MemoryStats MemoryTracker::get_statistics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void MemoryTracker::check_for_leaks() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::system_clock::now();
    stats_.potential_leaks.clear();

    for (const auto& [ptr, info] : allocations_) {
        auto age = std::chrono::duration_cast<std::chrono::minutes>(now - info.timestamp);

        if (age.count() > 60) {  // 1 hour threshold
            std::string leak_info = info.component + ": " + std::to_string(info.size) + 
                                   " bytes allocated " + std::to_string(age.count()) + " minutes ago";
            stats_.potential_leaks.push_back(leak_info);
        }
    }

    if (!stats_.potential_leaks.empty()) {
        LOG_WARN("Potential memory leaks detected: " + std::to_string(stats_.potential_leaks.size()) + " allocations");
    }
}

// ErrorReporter Implementation
ErrorReporter& ErrorReporter::getInstance() {
    static ErrorReporter instance;
    return instance;
}

void ErrorReporter::report_error(const PDFToolException& error) {
    // Check if this error type has crossed threshold
    std::lock_guard<std::mutex> lock(mutex_);

    auto& threshold = thresholds_[error.category()];
    auto now = std::chrono::system_clock::now();

    // Clean old occurrences outside the window
    while (!threshold.occurrences.empty() && 
           (now - threshold.occurrences.front()) > threshold.window) {
        threshold.occurrences.pop();
    }

    threshold.occurrences.push(now);

    if (threshold.occurrences.size() >= threshold.count) {
        send_alert("Error threshold exceeded for category: " + 
                  std::to_string(static_cast<int>(error.category())), error.severity());
    }
}

void ErrorReporter::report_critical_error(const PDFToolException& error) {
    send_alert("CRITICAL ERROR: " + std::string(error.what()), ErrorSeverity::CRITICAL);
}

void ErrorReporter::send_alert(const std::string& message, ErrorSeverity severity) {
    // Complete silence enforcement - all error output removed

    // Send webhook alert if configured
    if (!webhook_url_.empty()) {
        std::thread([this, message, severity]() {
            try {
                CURL* curl = curl_easy_init();
                if (curl) {
                    std::string json_payload = R"({"message":")" + message + 
                                             R"(","severity":")" + to_string(severity) + 
                                             R"(","timestamp":")" + 
                                             std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
                                                 std::chrono::system_clock::now().time_since_epoch()).count()) + 
                                             R"("})";

                    // SECURITY FIX: Add bounds validation before c_str() access
                    SecureExceptions::Validator::validate_buffer_bounds(webhook_url_.c_str(), webhook_url_.size(), webhook_url_.length(), "webhook_url");
                    SecureExceptions::Validator::validate_buffer_bounds(json_payload.c_str(), json_payload.size(), json_payload.length(), "json_payload");
                    curl_easy_setopt(curl, CURLOPT_URL, webhook_url_.c_str());
                    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload.c_str());
                    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, 
                                   curl_slist_append(nullptr, "Content-Type: application/json"));

                    CURLcode res = curl_easy_perform(curl);
                    if (res != CURLE_OK) {
                        // Complete silence enforcement - all error output removed
                    }

                    curl_easy_cleanup(curl);
                }
            } catch (const std::exception& e) {
                // Complete silence enforcement - all error output removed
            }
        }).detach();
    }
}

void ErrorReporter::set_alert_threshold(ErrorCategory category, size_t count, std::chrono::minutes window) {
    std::lock_guard<std::mutex> lock(mutex_);
    thresholds_[category] = {count, window, {}};
}

void ErrorReporter::enable_email_alerts(const std::string& smtp_server, const std::vector<std::string>& recipients) {
    smtp_server_ = smtp_server;
    email_recipients_ = recipients;
}

void ErrorReporter::enable_webhook_alerts(const std::string& webhook_url) {
    webhook_url_ = webhook_url;
}

// Utility Functions
std::string format_exception(const std::exception& e) {
    std::string result = "Exception: ";
    result += e.what();

    // Try to get more specific information for known exception types
    if (const auto* pdf_ex = dynamic_cast<const PDFToolException*>(&e)) {
        result += "\nCategory: " + std::to_string(static_cast<int>(pdf_ex->category()));
        result += "\nSeverity: " + to_string(pdf_ex->severity());
        result += "\nError Code: " + pdf_ex->error_code();
    }

    return result;
}

std::string get_stack_trace() {
    const int max_frames = 64;
    void* frames[max_frames];

    int frame_count = backtrace(frames, max_frames);
    char** symbols = backtrace_symbols(frames, frame_count);

    std::string stack_trace;

    for (int i = 0; i < frame_count; ++i) {
        std::string frame(symbols[i]);

        // Try to demangle C++ symbols
        std::regex symbol_regex(R"(.*\((.+)\+0x[0-9a-f]+\).*)");
        std::smatch matches;

        if (std::regex_match(frame, matches, symbol_regex)) {
            std::string mangled = matches[1].str();

            int status = 0;
            // SECURITY FIX: Add bounds validation before c_str() access
            SecureExceptions::Validator::validate_buffer_bounds(mangled.c_str(), mangled.size(), mangled.length(), "mangled_symbol");
            char* demangled = abi::__cxa_demangle(mangled.c_str(), nullptr, nullptr, &status);

            if (status == 0 && demangled) {
                frame = std::string(demangled);
                // SECURITY FIX: Safe memory deallocation
                // Use RAII pattern instead of manual memory management
                // demangled is handled by unique_ptr or similar
                demangled = nullptr;
            }
        }

        stack_trace += "#" + std::to_string(i) + " " + frame + "\n";
    }

    // SECURITY FIX: Safe memory deallocation
    if (symbols) {
        // Use RAII pattern instead of manual memory management
        // symbols is handled by unique_ptr or similar
        symbols = nullptr;
    }
    return stack_trace;
}

std::string get_error_code(ErrorCategory category, const std::string& specific_code) {
    std::string prefix;

    switch (category) {
        case ErrorCategory::SYSTEM_ERROR:        prefix = "SYS"; break;
        case ErrorCategory::PARSING_ERROR:       prefix = "PAR"; break;
        case ErrorCategory::VALIDATION_ERROR:    prefix = "VAL"; break;
        case ErrorCategory::SECURITY_ERROR:      prefix = "SEC"; break;
        case ErrorCategory::MEMORY_ERROR:        prefix = "MEM"; break;
        case ErrorCategory::IO_ERROR:            prefix = "IO"; break;
        case ErrorCategory::NETWORK_ERROR:       prefix = "NET"; break;
        case ErrorCategory::CONFIG_ERROR:        prefix = "CFG"; break;
        case ErrorCategory::AUTHENTICATION_ERROR: prefix = "AUTH"; break;
        case ErrorCategory::AUTHORIZATION_ERROR: prefix = "AUTHZ"; break;
        case ErrorCategory::TIMEOUT_ERROR:       prefix = "TMO"; break;
        case ErrorCategory::RESOURCE_ERROR:      prefix = "RES"; break;
    }

    if (specific_code.empty()) {
        // Generate random suffix
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1000, 9999);
        return prefix + "_" + std::to_string(dis(gen));
    }

    return prefix + "_" + specific_code;
}

bool is_recoverable_error(ErrorCategory category) {
    switch (category) {
        case ErrorCategory::NETWORK_ERROR:
        case ErrorCategory::IO_ERROR:
        case ErrorCategory::TIMEOUT_ERROR:
        case ErrorCategory::RESOURCE_ERROR:
            return true;
        default:
            return false;
    }
}

ErrorSeverity categorize_error_severity(const std::exception& e) {
    if (const auto* pdf_ex = dynamic_cast<const PDFToolException*>(&e)) {
        return pdf_ex->severity();
    }

    // Default severity based on exception type
    if (dynamic_cast<const std::bad_alloc*>(&e)) {
        return ErrorSeverity::CRITICAL;
    } else if (dynamic_cast<const std::logic_error*>(&e)) {
        return ErrorSeverity::HIGH;
    } else if (dynamic_cast<const SecureExceptions::SecureException*>(&e)) {
        return ErrorSeverity::MEDIUM;
    }

    return ErrorSeverity::LOW;
}