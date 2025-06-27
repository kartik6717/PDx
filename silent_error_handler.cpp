#include "silent_error_handler.hpp"
#include "stealth_macros.hpp"

// Static member initialization
std::vector<SilentErrorHandler::SilentError> SilentErrorHandler::error_history_;
std::mutex SilentErrorHandler::error_mutex_;

void SilentErrorHandler::handle_silent_error(const SilentError& error) {
    std::lock_guard<std::mutex> lock(error_mutex_);
    error_history_.push_back(error);
}

void SilentErrorHandler::log_internal_error(const std::string& error_code, 
                                           const std::string& message,
                                           ErrorSeverity severity) {
    SilentError error;
    error.severity = severity;
    error.error_code = error_code;
    error.internal_message = message;
    error.timestamp = std::chrono::system_clock::now();
    error.handled = false;
    
    handle_silent_error(error);
}

std::vector<SilentErrorHandler::SilentError> SilentErrorHandler::get_error_history() {
    std::lock_guard<std::mutex> lock(error_mutex_);
    return error_history_;
}

void SilentErrorHandler::clear_error_history() {
    std::lock_guard<std::mutex> lock(error_mutex_);
    error_history_.clear();
}
#include "silent_error_handler.hpp"

// Static member definitions
std::vector<SilentErrorHandler::SilentError> SilentErrorHandler::error_history_;
std::mutex SilentErrorHandler::error_mutex_;

void SilentErrorHandler::handle_silent_error(const SilentError& error) {
    std::lock_guard<std::mutex> lock(error_mutex_);
    error_history_.push_back(error);
    
    // Keep only last 100 errors to prevent memory bloat
    if (error_history_.size() > 100) {
        error_history_.erase(error_history_.begin());
    }
}

void SilentErrorHandler::log_internal_error(const std::string& error_code, 
                                          const std::string& message,
                                          ErrorSeverity severity) {
    SilentError error;
    error.error_code = error_code;
    error.internal_message = message;
    error.severity = severity;
    error.timestamp = std::chrono::system_clock::now();
    error.handled = false;
    
    handle_silent_error(error);
}

std::vector<SilentErrorHandler::SilentError> SilentErrorHandler::get_error_history() {
    std::lock_guard<std::mutex> lock(error_mutex_);
    return error_history_;
}

void SilentErrorHandler::clear_error_history() {
    std::lock_guard<std::mutex> lock(error_mutex_);
    error_history_.clear();
}
