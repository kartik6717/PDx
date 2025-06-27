#ifndef SILENT_ERROR_HANDLER_HPP
#define SILENT_ERROR_HANDLER_HPP

#include <string>
#include <vector>
#include <chrono>
#include <mutex>
#include "stealth_macros.hpp"

class SilentErrorHandler {
public:
    enum class ErrorSeverity {
        CRITICAL,
        WARNING,
        INFO
    };
    
    struct SilentError {
        ErrorSeverity severity;
        std::string error_code;
        std::string internal_message;
        std::chrono::system_clock::time_point timestamp;
        bool handled;
    };
    
    static void handle_silent_error(const SilentError& error);
    static void log_internal_error(const std::string& error_code, 
                                 const std::string& message,
                                 ErrorSeverity severity = ErrorSeverity::WARNING);
    static std::vector<SilentError> get_error_history();
    static void clear_error_history();
    static void set_error_suppression(bool suppress);
    static bool is_error_suppression_enabled();
    
private:
    static std::vector<SilentError> error_history_;
    static bool suppress_errors_;
    static std::mutex error_mutex_;
};

#endif // SILENT_ERROR_HANDLER_HPP