#include "secure_memory.hpp"
#include "secure_exceptions.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include "stealth_macros.hpp"

namespace SecureExceptions {

    // Static member definitions
    std::mutex ExceptionHandler::log_mutex_;
    std::vector<std::string> ExceptionHandler::error_log_;
    size_t ExceptionHandler::max_log_entries_ = 1000;

    std::string format_timestamp(const std::chrono::system_clock::time_point& tp) {
        auto time_t = std::chrono::system_clock::to_time_t(tp);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    void ExceptionHandler::log_error(const SecureException& e, const std::string& operation) {
        std::lock_guard<std::mutex> lock(log_mutex_);
        
        std::stringstream log_entry;
        log_entry << "[" << format_timestamp(e.get_timestamp()) << "] "
                  << "SECURE_EXCEPTION - Code: " << e.get_error_code() << " "
                  << "Operation: " << operation << " "
                  << "Message: " << e.what() << " "
                  << "Context: " << e.get_context();
        
        error_log_.push_back(log_entry.str());
        
        // Limit log size
        if (error_log_.size() > max_log_entries_) {
            error_log_.erase(error_log_.begin());
        }
        
        // Also output to stderr for immediate debugging
        SILENT_ERROR(log_entry.str() );
    }

    void ExceptionHandler::log_error(const std::exception& e, const std::string& operation) {
        std::lock_guard<std::mutex> lock(log_mutex_);
        
        std::stringstream log_entry;
        log_entry << "[" << format_timestamp(std::chrono::system_clock::now()) << "] "
                  << "STD_EXCEPTION - Operation: " << operation << " "
                  << "Message: " << e.what();
        
        error_log_.push_back(log_entry.str());
        
        if (error_log_.size() > max_log_entries_) {
            error_log_.erase(error_log_.begin());
        }
        
        SILENT_ERROR(log_entry.str() );
    }

    void ExceptionHandler::log_error(const std::string& message, const std::string& operation) {
        std::lock_guard<std::mutex> lock(log_mutex_);
        
        std::stringstream log_entry;
        log_entry << "[" << format_timestamp(std::chrono::system_clock::now()) << "] "
                  << "UNKNOWN_EXCEPTION - Operation: " << operation << " "
                  << "Message: " << message;
        
        error_log_.push_back(log_entry.str());
        
        if (error_log_.size() > max_log_entries_) {
            error_log_.erase(error_log_.begin());
        }
        
        SILENT_ERROR(log_entry.str() );
    }

    std::vector<std::string> ExceptionHandler::get_error_log() {
        std::lock_guard<std::mutex> lock(log_mutex_);
        return error_log_;
    }

    void ExceptionHandler::clear_error_log() {
        std::lock_guard<std::mutex> lock(log_mutex_);
        error_log_.clear();
    }
}
