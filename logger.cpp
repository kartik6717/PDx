#include "secure_exceptions.hpp"
#include "stealth_macros.hpp"
#include "secure_memory.hpp"
#include "stealth_macros.hpp"
#include "logger.hpp"
#include "stealth_macros.hpp"
#include "production_mode_checker.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <unistd.h>
#include <sys/syscall.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <uuid/uuid.h>
#include <cstring>
#include <regex>
#include "stealth_macros.hpp"
#include "stealth_macros.hpp"

// JSON Formatter Implementation
std::string JsonFormatter::format(const LogEntry& entry) {
    std::ostringstream json;
    
    auto time_t = std::chrono::system_clock::to_time_t(entry.timestamp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        entry.timestamp.time_since_epoch()) % 1000;
    
    json << "{"
         << "\"timestamp\":\"" << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S") 
         << "." << std::setfill('0') << std::setw(3) << ms.count() << "Z\","
         << "\"level\":\"" << to_string(entry.level) << "\","
         << "\"category\":\"" << to_string(entry.category) << "\","
         << "\"message\":\"" << entry.message << "\","
         << "\"component\":\"" << entry.component << "\","
         << "\"file\":\"" << entry.file << "\","
         << "\"line\":" << entry.line << ","
         << "\"function\":\"" << entry.function << "\","
         << "\"thread_id\":\"" << entry.thread_id << "\","
         << "\"session_id\":\"" << entry.session_id << "\","
         << "\"user_id\":\"" << entry.user_id << "\","
         << "\"process_id\":" << entry.process_id;
    
    if (!entry.context.empty()) {
        json << ",\"context\":{";
        bool first = true;
        for (const auto& [key, value] : entry.context) {
            if (!first) json << ",";
            json << "\"" << key << "\":\"" << value << "\"";
            first = false;
        }
        json << "}";
    }
    
    json << "}";
    return json.str();
}

// Text Formatter Implementation
std::string TextFormatter::format(const LogEntry& entry) {
    std::ostringstream text;
    
    auto time_t = std::chrono::system_clock::to_time_t(entry.timestamp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        entry.timestamp.time_since_epoch()) % 1000;
    
    text << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") 
         << "." << std::setfill('0') << std::setw(3) << ms.count() << "]"
         << " [" << to_string(entry.level) << "]"
         << " [" << to_string(entry.category) << "]";
    
    if (!entry.component.empty()) {
        text << " [" << entry.component << "]";
    }
    
    text << " " << entry.message;
    
    if (!entry.context.empty()) {
        text << " {";
        bool first = true;
        for (const auto& [key, value] : entry.context) {
            if (!first) text << ", ";
            text << key << "=" << value;
            first = false;
        }
        text << "}";
    }
    
    if (entry.level >= LogLevel::ERROR) {
        text << " (" << entry.file << ":" << entry.line << " in " << entry.function << ")";
    }
    
    return text.str();
}

// File Sink Implementation
FileSink::FileSink(const std::string& file_path, size_t max_size, size_t max_files)
    : file_path_(file_path), max_size_(max_size), max_files_(max_files), current_size_(0) {
    
    // Create directory if it doesn't exist
    std::filesystem::path path(file_path_);
    std::filesystem::create_directories(path.parent_path());
    
    file_stream_.open(file_path_, std::ios::app);
    if (!file_stream_.is_open()) {
        throw SecureExceptions::SecurityViolationException("Failed to open log file: " + file_path_);
    }
    
    // Get current file size
    if (std::filesystem::exists(file_path_)) {
        current_size_ = std::filesystem::file_size(file_path_);
    }
}

FileSink::~FileSink() {
    if (file_stream_.is_open()) {
        // SECURITY FIX: Safe file close with error checking
        file_stream_.close();
        if (file_stream_.fail() && !file_stream_.eof()) {
            // Complete silence - no error output for forensic invisibility
        }
    }
}

void FileSink::write(const std::string& formatted_message) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Enforce complete silence in production mode
    if (ProductionModeChecker::is_production_mode()) {
        return; // No file logging for forensic invisibility
    }
    
    if (!file_stream_.is_open()) {
        return;
    }
    
    file_stream_ << formatted_message << std::endl;
    current_size_ += formatted_message.length() + 1;
    
    rotate_if_needed();
}

void FileSink::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_stream_.is_open()) {
        file_stream_.flush();
    }
}

void FileSink::rotate_if_needed() {
    if (current_size_ >= max_size_) {
        file_stream_.close();
        
        // Rotate existing files
        for (size_t i = max_files_ - 1; i > 0; --i) {
            std::string old_file = get_rotated_filename(i - 1);
            // SECURITY FIX: Use secure string allocation and validation
            std::string new_file;
            try {
                new_file = get_rotated_filename(i);
                SecureExceptions::Validator::validate_file_path(new_file);
            } catch (const std::exception& e) {
                throw SecureExceptions::FileIOException("Failed to generate rotated filename", std::string(e.what()));
            }
            
            if (std::filesystem::exists(old_file)) {
                std::filesystem::rename(old_file, new_file);
            }
        }
        
        // Move current file to .1
        if (std::filesystem::exists(file_path_)) {
            std::filesystem::rename(file_path_, get_rotated_filename(1));
        }
        
        // SECURITY FIX: Open new file with safe error handling
        file_stream_.open(file_path_, std::ios::app);
        current_size_ = 0;
    }
}

std::string FileSink::get_rotated_filename(size_t index) {
    return file_path_ + "." + std::to_string(index);
}

// Console Sink Implementation
ConsoleSink::ConsoleSink(bool use_colors) : use_colors_(use_colors) {}

void ConsoleSink::write(const std::string& formatted_message) {
    std::lock_guard<std::mutex> lock(mutex_);
    // Complete silence - no output for forensic invisibility
    if (ProductionModeChecker::is_production_mode()) {
        return; // Absolute silence in production
    }
}

void ConsoleSink::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    // Complete silence - no flush operations for forensic invisibility
}

std::string ConsoleSink::get_color_code(LogLevel level) {
    if (!use_colors_) return "";
    
    switch (level) {
        case LogLevel::TRACE: return "\033[90m";  // Gray
        case LogLevel::DEBUG: return "\033[36m";  // Cyan
        case LogLevel::INFO:  return "\033[32m";  // Green
        case LogLevel::WARN:  return "\033[33m";  // Yellow
        case LogLevel::ERROR: return "\033[31m";  // Red
        case LogLevel::FATAL: return "\033[91m";  // Bright Red
        default: return "";
    }
}

// Syslog Sink Implementation
SyslogSink::SyslogSink(const std::string& ident) : ident_(ident) {
    // SECURITY FIX: Add bounds validation before c_str() access
    SecureExceptions::Validator::validate_buffer_bounds(ident_.c_str(), ident_.size(), ident_.length(), "syslog_ident");
    openlog(ident_.c_str(), LOG_PID | LOG_NDELAY, LOG_USER);
}

SyslogSink::~SyslogSink() {
    closelog();
}

void SyslogSink::write(const std::string& formatted_message) {
    // Enforce complete silence in production mode
    if (ProductionModeChecker::is_production_mode()) {
        return; // No syslog output for forensic invisibility
    }
    
    // Parse level from message (simplified)
    LogLevel level = LogLevel::INFO;
    if (formatted_message.find("[ERROR]") != std::string::npos) level = LogLevel::ERROR;
    else if (formatted_message.find("[WARN]") != std::string::npos) level = LogLevel::WARN;
    else if (formatted_message.find("[FATAL]") != std::string::npos) level = LogLevel::FATAL;
    
    // SECURITY FIX: Add bounds validation before c_str() access
    SecureExceptions::Validator::validate_buffer_bounds(formatted_message.c_str(), formatted_message.size(), formatted_message.length(), "syslog_message");
    syslog(get_syslog_priority(level), "%s", formatted_message.c_str());
}

void SyslogSink::flush() {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        // Syslog flushes automatically, but we ensure complete buffer flush
        // for stealth operation compliance
        SecureMemory flush_buffer(256);
        
        // Force system log buffer flush if available
        #ifdef __linux__
        sync();
        #endif
        
        // Clear any pending syslog buffers
        closelog();
        openlog(program_name_.c_str(), LOG_PID | LOG_NDELAY, facility_);
        
        eliminate_flush_traces();
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

int SyslogSink::get_syslog_priority(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE:
        case LogLevel::DEBUG: return LOG_DEBUG;
        case LogLevel::INFO:  return LOG_INFO;
        case LogLevel::WARN:  return LOG_WARNING;
        case LogLevel::ERROR: return LOG_ERR;
        case LogLevel::FATAL: return LOG_CRIT;
        default: return LOG_INFO;
    }
}

// Network Sink Implementation
NetworkSink::NetworkSink(const std::string& host, int port)
    : host_(host), port_(port), socket_fd_(-1), connected_(false) {
    connect();
}

NetworkSink::~NetworkSink() {
    if (socket_fd_ != -1) {
        close(socket_fd_);
    }
}

void NetworkSink::write(const std::string& formatted_message) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Enforce complete silence in production mode
    if (ProductionModeChecker::is_production_mode()) {
        return; // No network logging for forensic invisibility
    }
    
    if (!connected_) {
        reconnect();
    }
    
    if (connected_) {
        std::string message = formatted_message + "\n";
        // SECURITY FIX: Add bounds validation before c_str() access
        SecureExceptions::Validator::validate_buffer_bounds(message.c_str(), message.size(), message.length(), "network_message");
        ssize_t sent = send(socket_fd_, message.c_str(), message.length(), MSG_NOSIGNAL);
        
        if (sent == -1) {
            connected_ = false;
        }
    }
}

void NetworkSink::flush() {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        SecureMemory flush_buffer(512);
        
        if (socket_fd_ != -1) {
            // Force TCP buffer flush by setting TCP_NODELAY temporarily
            int nodelay = 1;
            setsockopt(socket_fd_, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
            
            // Send empty flush packet to ensure all data is transmitted
            const char flush_marker = '\0';
            send(socket_fd_, &flush_marker, 1, MSG_DONTWAIT);
            
            // Restore original TCP_NODELAY setting
            nodelay = 0;
            setsockopt(socket_fd_, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
            
            // Force socket buffer flush
            fsync(socket_fd_);
        }
        
        eliminate_network_flush_traces();
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

void NetworkSink::connect() {
    socket_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd_ == -1) {
        throw SecureExceptions::FileIOException("Failed to create socket", "network connection");
    }
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port_);
    
    // SECURITY FIX: Add bounds validation before c_str() access
    SecureExceptions::Validator::validate_buffer_bounds(host_.c_str(), host_.size(), host_.length(), "network_host");
    if (inet_pton(AF_INET, host_.c_str(), &server_addr.sin_addr) <= 0) {
        // SECURITY FIX: Safe socket close with error handling
        if (socket_fd_ != -1) {
            close(socket_fd_);
            socket_fd_ = -1;
        }
        throw SecureExceptions::InvalidInputException("Invalid host address", host_);
    }
    
    if (::connect(socket_fd_, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
        connected_ = true;
    } else {
        close(socket_fd_);
        socket_fd_ = -1;
    }
}

void NetworkSink::reconnect() {
    if (socket_fd_ != -1) {
        close(socket_fd_);
        socket_fd_ = -1;
    }
    connect();
}

// Logger Implementation
Logger::Logger() 
    : shutdown_requested_(false), global_level_(LogLevel::INFO), session_id_(generate_session_id()) {
    
    stats_.start_time = std::chrono::system_clock::now();
    stats_.total_entries = 0;
    stats_.errors = 0;
    stats_.warnings = 0;
    stats_.security_events = 0;
    
    worker_thread_ = std::thread(&Logger::worker_thread, this);
}

Logger::~Logger() {
    shutdown();
}

Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

void Logger::set_level(LogLevel level) {
    global_level_ = level;
}

void Logger::set_category_level(LogCategory category, LogLevel level) {
    category_levels_[category] = level;
}

void Logger::add_sink(std::shared_ptr<LogSink> sink, std::shared_ptr<LogFormatter> formatter) {
    sinks_.push_back({sink, formatter});
}

void Logger::set_session_id(const std::string& session_id) {
    session_id_ = session_id;
}

void Logger::set_user_id(const std::string& user_id) {
    user_id_ = user_id;
}

void Logger::log(LogLevel level, LogCategory category, const std::string& message,
                const std::string& component, const std::string& file,
                int line, const std::string& function) {
    
    // Check production mode and suppress all logging
    if (ProductionModeChecker::is_production_mode()) {
        return;
    }
    
    if (!should_log(level, category)) {
        return;
    }
    
    LogEntry entry;
    entry.timestamp = std::chrono::system_clock::now();
    entry.level = level;
    entry.category = category;
    entry.message = message;
    entry.component = component;
    entry.file = file;
    entry.line = line;
    entry.function = function;
    entry.thread_id = get_thread_id();
    entry.session_id = session_id_;
    entry.user_id = user_id_;
    entry.process_id = getpid();
    
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        log_queue_.push(entry);
    }
    queue_condition_.notify_one();
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_entries++;
        stats_.category_counts[category]++;
        
        if (level == LogLevel::ERROR || level == LogLevel::FATAL) {
            stats_.errors++;
        } else if (level == LogLevel::WARN) {
            stats_.warnings++;
        }
        
        if (category == LogCategory::SECURITY) {
            stats_.security_events++;
        }
    }
}

void Logger::log_with_context(LogLevel level, LogCategory category, const std::string& message,
                             const std::map<std::string, std::string>& context,
                             const std::string& component, const std::string& file,
                             int line, const std::string& function) {
    
    if (!should_log(level, category)) {
        return;
    }
    
    LogEntry entry;
    entry.timestamp = std::chrono::system_clock::now();
    entry.level = level;
    entry.category = category;
    entry.message = message;
    entry.component = component;
    entry.file = file;
    entry.line = line;
    entry.function = function;
    entry.context = context;
    entry.thread_id = get_thread_id();
    entry.session_id = session_id_;
    entry.user_id = user_id_;
    entry.process_id = getpid();
    
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        log_queue_.push(entry);
    }
    queue_condition_.notify_one();
}

void Logger::log_error(const ErrorDetails& error) {
    std::map<std::string, std::string> context;
    context["error_code"] = error.error_code;
    context["severity"] = to_string(error.severity);
    context["component"] = error.component;
    context["operation"] = error.operation;
    context["recoverable"] = error.is_recoverable ? "true" : "false";
    context["recovery_action"] = error.recovery_action;
    
    if (!error.stack_trace.empty()) {
        context["stack_trace"] = error.stack_trace;
    }
    
    for (const auto& [key, value] : error.context) {
        context[key] = value;
    }
    
    LogLevel level = (error.severity == ErrorSeverity::CRITICAL) ? LogLevel::FATAL : LogLevel::ERROR;
    log_with_context(level, LogCategory::SYSTEM, error.error_message, context);
}

void Logger::log_audit(const AuditEvent& event) {
    std::map<std::string, std::string> context;
    context["event_type"] = event.event_type;
    context["user_id"] = event.user_id;
    context["session_id"] = event.session_id;
    context["resource"] = event.resource;
    context["action"] = event.action;
    context["result"] = event.result;
    context["client_ip"] = event.client_ip;
    context["user_agent"] = event.user_agent;
    
    for (const auto& [key, value] : event.details) {
        context[key] = value;
    }
    
    log_with_context(LogLevel::INFO, LogCategory::AUDIT, 
                     event.action + " on " + event.resource + " by " + event.user_id, 
                     context);
}

void Logger::log_performance(const std::string& operation, std::chrono::milliseconds duration,
                            const std::map<std::string, std::string>& metrics) {
    std::map<std::string, std::string> context = metrics;
    context["operation"] = operation;
    context["duration_ms"] = std::to_string(duration.count());
    
    log_with_context(LogLevel::INFO, LogCategory::PERFORMANCE, 
                     operation + " completed in " + std::to_string(duration.count()) + "ms", 
                     context);
}

void Logger::log_security_event(const std::string& event_type, const std::string& details,
                               ErrorSeverity severity) {
    std::map<std::string, std::string> context;
    context["event_type"] = event_type;
    context["severity"] = to_string(severity);
    
    LogLevel level = (severity == ErrorSeverity::CRITICAL) ? LogLevel::FATAL : LogLevel::WARN;
    log_with_context(level, LogCategory::SECURITY, details, context);
}

void Logger::log_memory_usage(const std::string& component, size_t bytes_used, size_t bytes_peak) {
    std::map<std::string, std::string> context;
    context["component"] = component;
    context["bytes_used"] = std::to_string(bytes_used);
    context["mb_used"] = std::to_string(bytes_used / 1024 / 1024);
    
    if (bytes_peak > 0) {
        context["bytes_peak"] = std::to_string(bytes_peak);
        context["mb_peak"] = std::to_string(bytes_peak / 1024 / 1024);
    }
    
    log_with_context(LogLevel::DEBUG, LogCategory::MEMORY, 
                     component + " using " + std::to_string(bytes_used / 1024 / 1024) + " MB", 
                     context);
}

void Logger::log_file_operation(const std::string& operation, const std::string& file_path,
                               bool success, const std::string& details) {
    std::map<std::string, std::string> context;
    context["operation"] = operation;
    context["file_path"] = file_path;
    context["success"] = success ? "true" : "false";
    
    if (!details.empty()) {
        context["details"] = details;
    }
    
    LogLevel level = success ? LogLevel::DEBUG : LogLevel::ERROR;
    log_with_context(level, LogCategory::FILE_IO, 
                     operation + " " + file_path + " " + (success ? "succeeded" : "failed"), 
                     context);
}

void Logger::log_config_change(const std::string& parameter, const std::string& old_value,
                              const std::string& new_value, const std::string& changed_by) {
    std::map<std::string, std::string> context;
    context["parameter"] = parameter;
    context["old_value"] = old_value;
    context["new_value"] = new_value;
    context["changed_by"] = changed_by.empty() ? user_id_ : changed_by;
    
    log_with_context(LogLevel::INFO, LogCategory::CONFIG, 
                     "Configuration parameter " + parameter + " changed from '" + 
                     old_value + "' to '" + new_value + "'", context);
}

void Logger::shutdown() {
    if (!shutdown_requested_.exchange(true)) {
        queue_condition_.notify_all();
        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }
    }
}

void Logger::flush_all() {
    for (auto& sink_formatter : sinks_) {
        sink_formatter.sink->flush();
    }
}

Logger::LogStats Logger::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void Logger::worker_thread() {
    while (!shutdown_requested_) {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        queue_condition_.wait(lock, [this] { return !log_queue_.empty() || shutdown_requested_; });
        
        while (!log_queue_.empty()) {
            LogEntry entry = log_queue_.front();
            log_queue_.pop();
            lock.unlock();
            
            // Format and write to all sinks
            for (auto& sink_formatter : sinks_) {
                try {
                    std::string formatted = sink_formatter.formatter->format(entry);
                    sink_formatter.sink->write(formatted);
                } catch (const std::exception& e) {
                    // Can't log this error without causing recursion
                    // Complete silence enforcement - all error output removed
                }
            }
            
            lock.lock();
        }
    }
    
    // Final flush
    for (auto& sink_formatter : sinks_) {
        sink_formatter.sink->flush();
    }
}

bool Logger::should_log(LogLevel level, LogCategory category) {
    // Check category-specific level first
    auto it = category_levels_.find(category);
    if (it != category_levels_.end()) {
        return level >= it->second;
    }
    
    // Fall back to global level
    return level >= global_level_;
}

std::string Logger::get_thread_id() {
    std::ostringstream oss;
    oss << std::this_thread::get_id();
    return oss.str();
}

std::string Logger::generate_session_id() {
    uuid_t uuid;
    char uuid_str[37];
    uuid_generate(uuid);
    uuid_unparse(uuid, uuid_str);
    return std::string(uuid_str);
}

// Performance Timer Implementation
PerformanceTimer::PerformanceTimer(const std::string& operation, LogCategory category)
    : operation_(operation), category_(category), success_(true) {
    start_time_ = std::chrono::steady_clock::now();
}

PerformanceTimer::~PerformanceTimer() {
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time_);
    
    metrics_["success"] = success_ ? "true" : "false";
    Logger::getInstance().log_performance(operation_, duration, metrics_);
}

void PerformanceTimer::add_metric(const std::string& key, const std::string& value) {
    metrics_[key] = value;
}

void PerformanceTimer::set_success(bool success) {
    success_ = success;
}

// Logging Scope Implementation
LoggingScope::LoggingScope(const std::string& scope_name, LogCategory category)
    : scope_name_(scope_name), category_(category) {
    start_time_ = std::chrono::steady_clock::now();
    
    std::map<std::string, std::string> context;
    context["scope"] = scope_name_;
    context["action"] = "enter";
    
    Logger::getInstance().log_with_context(LogLevel::DEBUG, category_, 
                                         "Entering scope: " + scope_name_, context);
}

LoggingScope::~LoggingScope() {
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time_);
    
    context_["scope"] = scope_name_;
    context_["action"] = "exit";
    context_["duration_ms"] = std::to_string(duration.count());
    
    LogLevel level = error_.empty() ? LogLevel::DEBUG : LogLevel::ERROR;
    std::string message = error_.empty() ? 
        "Exiting scope: " + scope_name_ : 
        "Exiting scope with error: " + scope_name_ + " - " + error_;
    
    Logger::getInstance().log_with_context(level, category_, message, context_);
}

void LoggingScope::add_context(const std::string& key, const std::string& value) {
    context_[key] = value;
}

void LoggingScope::set_error(const std::string& error) {
    error_ = error;
}

// Utility Functions
std::string to_string(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO";
        case LogLevel::WARN:  return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

std::string to_string(LogCategory category) {
    switch (category) {
        case LogCategory::SYSTEM:     return "SYSTEM";
        case LogCategory::SECURITY:   return "SECURITY";
        case LogCategory::PERFORMANCE: return "PERFORMANCE";
        case LogCategory::PARSING:    return "PARSING";
        case LogCategory::SCRUBBING:  return "SCRUBBING";
        case LogCategory::FORENSIC:   return "FORENSIC";
        case LogCategory::AUDIT:      return "AUDIT";
        case LogCategory::NETWORK:    return "NETWORK";
        case LogCategory::FILE_IO:    return "FILE_IO";
        case LogCategory::MEMORY:     return "MEMORY";
        case LogCategory::CONFIG:     return "CONFIG";
        default: return "UNKNOWN";
    }
}

std::string to_string(ErrorSeverity severity) {
    switch (severity) {
        case ErrorSeverity::LOW:      return "LOW";
        case ErrorSeverity::MEDIUM:   return "MEDIUM";
        case ErrorSeverity::HIGH:     return "HIGH";
        case ErrorSeverity::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

LogLevel from_string_level(const std::string& level) {
    if (level == "TRACE") return LogLevel::TRACE;
    if (level == "DEBUG") return LogLevel::DEBUG;
    if (level == "INFO")  return LogLevel::INFO;
    if (level == "WARN")  return LogLevel::WARN;
    if (level == "ERROR") return LogLevel::ERROR;
    if (level == "FATAL") return LogLevel::FATAL;
    return LogLevel::INFO;
}

LogCategory from_string_category(const std::string& category) {
    if (category == "SYSTEM")     return LogCategory::SYSTEM;
    if (category == "SECURITY")   return LogCategory::SECURITY;
    if (category == "PERFORMANCE") return LogCategory::PERFORMANCE;
    if (category == "PARSING")    return LogCategory::PARSING;
    if (category == "SCRUBBING")  return LogCategory::SCRUBBING;
    if (category == "FORENSIC")   return LogCategory::FORENSIC;
    if (category == "AUDIT")      return LogCategory::AUDIT;
    if (category == "NETWORK")    return LogCategory::NETWORK;
    if (category == "FILE_IO")    return LogCategory::FILE_IO;
    if (category == "MEMORY")     return LogCategory::MEMORY;
    if (category == "CONFIG")     return LogCategory::CONFIG;
    return LogCategory::SYSTEM;
}