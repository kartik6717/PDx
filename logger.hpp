#pragma once

#include <string>
#include <memory>
#include <mutex>
#include <fstream>
#include <queue>
#include <thread>
#include <atomic>
#include <chrono>
#include <sstream>
#include <map>
#include <vector>

// Log levels
enum class LogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    FATAL = 5
};

// Log categories for structured logging
enum class LogCategory {
    SYSTEM,
    SECURITY,
    PERFORMANCE,
    PARSING,
    SCRUBBING,
    FORENSIC,
    AUDIT,
    NETWORK,
    FILE_IO,
    MEMORY,
    CONFIG
};

// Error severity levels
enum class ErrorSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

// Structured log entry
struct LogEntry {
    std::chrono::system_clock::time_point timestamp;
    LogLevel level;
    LogCategory category;
    std::string message;
    std::string component;
    std::string file;
    int line;
    std::string function;
    std::map<std::string, std::string> context;
    std::string thread_id;
    std::string session_id;
    std::string user_id;
    size_t process_id;
};

// Error details structure
struct ErrorDetails {
    std::string error_code;
    std::string error_message;
    ErrorSeverity severity;
    std::string component;
    std::string operation;
    std::map<std::string, std::string> context;
    std::chrono::system_clock::time_point timestamp;
    std::string stack_trace;
    std::string recovery_action;
    bool is_recoverable;
};

// Audit event structure
struct AuditEvent {
    std::string event_type;
    std::string user_id;
    std::string session_id;
    std::string resource;
    std::string action;
    std::string result;
    std::map<std::string, std::string> details;
    std::chrono::system_clock::time_point timestamp;
    std::string client_ip;
    std::string user_agent;
};

// Log formatter interface
class LogFormatter {
public:
    virtual ~LogFormatter() = default;
    virtual std::string format(const LogEntry& entry) = 0;
};

// JSON formatter for structured logging
class JsonFormatter : public LogFormatter {
public:
    std::string format(const LogEntry& entry) override;
};

// Plain text formatter for human readability
class TextFormatter : public LogFormatter {
public:
    std::string format(const LogEntry& entry) override;
};

// Log sink interface
class LogSink {
public:
    virtual ~LogSink() = default;
    virtual void write(const std::string& formatted_message) = 0;
    virtual void flush() = 0;
};

// File sink with rotation
class FileSink : public LogSink {
public:
    FileSink(const std::string& file_path, size_t max_size = 100 * 1024 * 1024, size_t max_files = 10);
    ~FileSink();
    
    void write(const std::string& formatted_message) override;
    void flush() override;

private:
    void rotate_if_needed();
    std::string get_rotated_filename(size_t index);
    
    std::string file_path_;
    size_t max_size_;
    size_t max_files_;
    std::ofstream file_stream_;
    size_t current_size_;
    std::mutex mutex_;
};

// Console sink
class ConsoleSink : public LogSink {
public:
    ConsoleSink(bool use_colors = true);
    
    void write(const std::string& formatted_message) override;
    void flush() override;

private:
    std::string get_color_code(LogLevel level);
    bool use_colors_;
    std::mutex mutex_;
};

// Syslog sink for system integration
class SyslogSink : public LogSink {
public:
    SyslogSink(const std::string& ident);
    ~SyslogSink();
    
    void write(const std::string& formatted_message) override;
    void flush() override;

private:
    int get_syslog_priority(LogLevel level);
    std::string ident_;
};

// Network sink for centralized logging
class NetworkSink : public LogSink {
public:
    NetworkSink(const std::string& host, int port);
    ~NetworkSink();
    
    void write(const std::string& formatted_message) override;
    void flush() override;

private:
    void connect();
    void reconnect();
    
    std::string host_;
    int port_;
    int socket_fd_;
    std::mutex mutex_;
    std::atomic<bool> connected_;
};

// Main logger class
class Logger {
public:
    static Logger& getInstance();
    
    // Configuration
    void set_level(LogLevel level);
    void set_category_level(LogCategory category, LogLevel level);
    void add_sink(std::shared_ptr<LogSink> sink, std::shared_ptr<LogFormatter> formatter);
    void set_session_id(const std::string& session_id);
    void set_user_id(const std::string& user_id);
    
    // Core logging methods
    void log(LogLevel level, LogCategory category, const std::string& message,
             const std::string& component = "", const std::string& file = "",
             int line = 0, const std::string& function = "");
    
    void log_with_context(LogLevel level, LogCategory category, const std::string& message,
                         const std::map<std::string, std::string>& context,
                         const std::string& component = "", const std::string& file = "",
                         int line = 0, const std::string& function = "");
    
    // Convenience methods
    void trace(const std::string& message, LogCategory category = LogCategory::SYSTEM);
    void debug(const std::string& message, LogCategory category = LogCategory::SYSTEM);
    void info(const std::string& message, LogCategory category = LogCategory::SYSTEM);
    void warn(const std::string& message, LogCategory category = LogCategory::SYSTEM);
    void error(const std::string& message, LogCategory category = LogCategory::SYSTEM);
    void fatal(const std::string& message, LogCategory category = LogCategory::SYSTEM);
    
    // Structured error logging
    void log_error(const ErrorDetails& error);
    
    // Audit logging
    void log_audit(const AuditEvent& event);
    
    // Performance logging
    void log_performance(const std::string& operation, std::chrono::milliseconds duration,
                        const std::map<std::string, std::string>& metrics = {});
    
    // Security logging
    void log_security_event(const std::string& event_type, const std::string& details,
                           ErrorSeverity severity = ErrorSeverity::HIGH);
    
    // Memory usage logging
    void log_memory_usage(const std::string& component, size_t bytes_used, size_t bytes_peak = 0);
    
    // File operation logging
    void log_file_operation(const std::string& operation, const std::string& file_path,
                           bool success, const std::string& details = "");
    
    // Configuration change logging
    void log_config_change(const std::string& parameter, const std::string& old_value,
                          const std::string& new_value, const std::string& changed_by = "");
    
    // Thread-safe shutdown
    void shutdown();
    void flush_all();
    
    // Statistics
    struct LogStats {
        size_t total_entries;
        size_t errors;
        size_t warnings;
        size_t security_events;
        std::chrono::system_clock::time_point start_time;
        std::map<LogCategory, size_t> category_counts;
    };
    
    LogStats get_statistics() const;

private:
    Logger();
    ~Logger();
    
    // Disable copy/move
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    void worker_thread();
    bool should_log(LogLevel level, LogCategory category);
    std::string get_thread_id();
    std::string generate_session_id();
    
    struct SinkFormatter {
        std::shared_ptr<LogSink> sink;
        std::shared_ptr<LogFormatter> formatter;
    };
    
    std::vector<SinkFormatter> sinks_;
    std::queue<LogEntry> log_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_condition_;
    std::thread worker_thread_;
    std::atomic<bool> shutdown_requested_;
    
    LogLevel global_level_;
    std::map<LogCategory, LogLevel> category_levels_;
    std::string session_id_;
    std::string user_id_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    LogStats stats_;
};

// RAII performance timer
class PerformanceTimer {
public:
    PerformanceTimer(const std::string& operation, LogCategory category = LogCategory::PERFORMANCE);
    ~PerformanceTimer();
    
    void add_metric(const std::string& key, const std::string& value);
    void set_success(bool success);

private:
    std::string operation_;
    LogCategory category_;
    std::chrono::steady_clock::time_point start_time_;
    std::map<std::string, std::string> metrics_;
    bool success_;
};

// Exception-safe logging scope
class LoggingScope {
public:
    LoggingScope(const std::string& scope_name, LogCategory category = LogCategory::SYSTEM);
    ~LoggingScope();
    
    void add_context(const std::string& key, const std::string& value);
    void set_error(const std::string& error);

private:
    std::string scope_name_;
    LogCategory category_;
    std::map<std::string, std::string> context_;
    std::string error_;
    std::chrono::steady_clock::time_point start_time_;
};

// Macros for convenient logging with source location
#define LOG_TRACE(message) Logger::getInstance().log(LogLevel::TRACE, LogCategory::SYSTEM, message, "", __FILE__, __LINE__, __FUNCTION__)
#define LOG_DEBUG(message) Logger::getInstance().log(LogLevel::DEBUG, LogCategory::SYSTEM, message, "", __FILE__, __LINE__, __FUNCTION__)
#include "stealth_macros.hpp"
#define LOG_INFO(message) Logger::getInstance().log(LogLevel::INFO, LogCategory::SYSTEM, message, "", __FILE__, __LINE__, __FUNCTION__)
#define LOG_WARN(message) Logger::getInstance().log(LogLevel::WARN, LogCategory::SYSTEM, message, "", __FILE__, __LINE__, __FUNCTION__)
#include "stealth_macros.hpp"
#define LOG_ERROR(message) Logger::getInstance().log(LogLevel::ERROR, LogCategory::SYSTEM, message, "", __FILE__, __LINE__, __FUNCTION__)
#define LOG_FATAL(message) Logger::getInstance().log(LogLevel::FATAL, LogCategory::SYSTEM, message, "", __FILE__, __LINE__, __FUNCTION__)
#include "stealth_macros.hpp"

// Category-specific macros
#define LOG_SECURITY(message) Logger::getInstance().log(LogLevel::WARN, LogCategory::SECURITY, message, "", __FILE__, __LINE__, __FUNCTION__)
#define LOG_AUDIT(message) Logger::getInstance().log(LogLevel::INFO, LogCategory::AUDIT, message, "", __FILE__, __LINE__, __FUNCTION__)
#include "stealth_macros.hpp"
#define LOG_PERFORMANCE(message) Logger::getInstance().log(LogLevel::INFO, LogCategory::PERFORMANCE, message, "", __FILE__, __LINE__, __FUNCTION__)

// Context logging macros
#define LOG_WITH_CONTEXT(level, category, message, context) \
    Logger::getInstance().log_with_context(level, category, message, context, "", __FILE__, __LINE__, __FUNCTION__)

// Performance measurement macro
#define MEASURE_PERFORMANCE(operation) PerformanceTimer _perf_timer(operation)
#define MEASURE_PERFORMANCE_CAT(operation, category) PerformanceTimer _perf_timer(operation, category)
#include "stealth_macros.hpp"

// Logging scope macro
#define LOG_SCOPE(name) LoggingScope _log_scope(name)
#define LOG_SCOPE_CAT(name, category) LoggingScope _log_scope(name, category)
#include "stealth_macros.hpp"

// String conversion utilities
std::string to_string(LogLevel level);
std::string to_string(LogCategory category);
std::string to_string(ErrorSeverity severity);
LogLevel from_string_level(const std::string& level);
LogCategory from_string_category(const std::string& category);
