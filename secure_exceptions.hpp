#ifndef SECURE_EXCEPTIONS_HPP
#define SECURE_EXCEPTIONS_HPP
#include "stealth_macros.hpp"

#include <exception>
#include <string>
#include <memory>
#include <vector>
#include <chrono>
#include <mutex>

namespace SecureExceptions {

    // Base secure exception class with context information
    class SecureException : public std::exception {
    protected:
        std::string message_;
        std::string context_;
        std::chrono::system_clock::time_point timestamp_;
        int error_code_;

    public:
        SecureException(const std::string& message, const std::string& context = "", int code = 0)
            : message_(message), context_(context), timestamp_(std::chrono::system_clock::now()), error_code_(code) {}

        const char* what() const noexcept override {
            return message_.c_str();
        }

        const std::string& get_context() const { return context_; }
        int get_error_code() const { return error_code_; }
        std::chrono::system_clock::time_point get_timestamp() const { return timestamp_; }
    };

    // Memory-related exceptions
    class MemoryException : public SecureException {
    public:
        MemoryException(const std::string& message, const std::string& context = "")
            : SecureException("Memory Error: " + message, context, 1001) {}
    };

    class BufferOverflowException : public MemoryException {
    public:
        BufferOverflowException(const std::string& context = "")
            : MemoryException("Buffer overflow detected", context) {}
    };

    class AllocationFailedException : public MemoryException {
    public:
        AllocationFailedException(size_t requested_size, const std::string& context = "")
            : MemoryException("Memory allocation failed for " + std::to_string(requested_size) + " bytes", context) {}
    };

    // File I/O related exceptions
    class FileIOException : public SecureException {
    public:
        FileIOException(const std::string& message, const std::string& context = "")
            : SecureException("File I/O Error: " + message, context, 2001) {}
    };

    class FileAccessException : public FileIOException {
    public:
        FileAccessException(const std::string& filename, const std::string& operation = "")
            : FileIOException("Cannot access file: " + filename, "Operation: " + operation) {}
    };

    class PathTraversalException : public FileIOException {
    public:
        PathTraversalException(const std::string& path)
            : FileIOException("Path traversal attempt detected", "Path: " + path) {}
    };

    // Concurrency related exceptions
    class ConcurrencyException : public SecureException {
    public:
        ConcurrencyException(const std::string& message, const std::string& context = "")
            : SecureException("Concurrency Error: " + message, context, 3001) {}
    };

    class DeadlockException : public ConcurrencyException {
    public:
        DeadlockException(const std::string& context = "")
            : ConcurrencyException("Potential deadlock detected", context) {}
    };

    class RaceConditionException : public ConcurrencyException {
    public:
        RaceConditionException(const std::string& context = "")
            : ConcurrencyException("Race condition detected", context) {}
    };

    // Validation related exceptions
    class ValidationException : public SecureException {
    public:
        ValidationException(const std::string& message, const std::string& context = "")
            : SecureException("Validation Error: " + message, context, 4001) {}
    };

    class InvalidInputException : public ValidationException {
    public:
        InvalidInputException(const std::string& input_name, const std::string& reason = "")
            : ValidationException("Invalid input: " + input_name, reason) {}
    };

    class SecurityViolationException : public ValidationException {
    public:
        SecurityViolationException(const std::string& violation, const std::string& context = "")
            : ValidationException("Security violation: " + violation, context) {}
    };

    class CryptoException : public SecureException {
    public:
        CryptoException(const std::string& message, const std::string& context = "")
            : SecureException("Cryptographic error: " + message, context) {}
    };

    // Exception handler with logging and recovery
    class ExceptionHandler {
    private:
        static std::mutex log_mutex_;
        static std::vector<std::string> error_log_;
        static size_t max_log_entries_;

    public:
        // Handle exception with logging and potential recovery
        template<typename Func>
        static auto safe_execute(Func&& func, const std::string& operation_name = "") 
            -> decltype(func()) {
            try {
                return func();
            } catch (const SecureException& e) {
                log_error(e, operation_name);
                throw; // Re-throw for caller to handle
            } catch (const std::exception& e) {
                log_error(e, operation_name);
                throw SecureException("Unhandled exception: " + std::string(e.what()), operation_name);
            } catch (...) {
                log_error("Unknown exception occurred", operation_name);
                throw SecureException("Unknown exception occurred", operation_name);
            }
        }

        // Execute with default value on exception
        template<typename Func, typename Default>
        static auto safe_execute_with_default(Func&& func, Default&& default_value, 
                                            const std::string& operation_name = "") 
            -> decltype(func()) {
            try {
                return func();
            } catch (const std::exception& e) {
                log_error(e, operation_name);
                return std::forward<Default>(default_value);
            } catch (...) {
                log_error("Unknown exception occurred", operation_name);
                return std::forward<Default>(default_value);
            }
        }

        // Log error information
        static void log_error(const SecureException& e, const std::string& operation = "");
        static void log_error(const std::exception& e, const std::string& operation = "");
        static void log_error(const std::string& message, const std::string& operation = "");

        // Get error log
        static std::vector<std::string> get_error_log();
        static void clear_error_log();

        // Handle specific exception types
        template<typename ExceptionType>
        static void handle_exception(const ExceptionType& e) {
            log_error(e.what(), "Exception Handler");
            throw;
        }
    };

    // RAII-based resource management with exception safety
    template<typename Resource, typename Deleter>
    class SecureResource {
    private:
        std::unique_ptr<Resource, Deleter> resource_;
        std::string resource_name_;

    public:
        SecureResource(Resource* resource, Deleter deleter, const std::string& name = "")
            : resource_(resource, deleter), resource_name_(name) {
            if (!resource_) {
                throw AllocationFailedException(0, "Failed to create resource: " + name);
            }
        }

        Resource* get() { return resource_.get(); }
        const Resource* get() const { return resource_.get(); }
        Resource& operator*() { return *resource_; }
        const Resource& operator*() const { return *resource_; }
        Resource* operator->() { return resource_.get(); }
        const Resource* operator->() const { return resource_.get(); }

        // Release ownership
        Resource* release() { return resource_.release(); }

        // Check if valid
        bool is_valid() const { return resource_ != nullptr; }
    };

    // Error severity levels
    enum class ErrorSeverity {
        LOW,
        MEDIUM, 
        HIGH,
        CRITICAL
    };

    // Global error handling function
    inline void handle_error(const std::string& message, ErrorSeverity severity) {
        switch (severity) {
            case ErrorSeverity::CRITICAL:
                throw SecurityViolationException(message);
            case ErrorSeverity::HIGH:
                throw ValidationException(message);
            case ErrorSeverity::MEDIUM:
                ExceptionHandler::log_error(message, "Error Handler");
                break;
            case ErrorSeverity::LOW:
                // Log only
                ExceptionHandler::log_error(message, "Warning");
                break;
        }
    }

    // Validation utilities
    class Validator {
    public:
        // Validate buffer bounds
        static void validate_buffer_bounds(const void* buffer, size_t buffer_size, 
                                         size_t access_size, const std::string& context = "") {
            if (!buffer) {
                throw ValidationException("Null buffer", context);
            }
            if (access_size > buffer_size) {
                throw BufferOverflowException(context + " - Access size: " + std::to_string(access_size) + 
                                            ", Buffer size: " + std::to_string(buffer_size));
            }
        }

        // Validate file path for security
        static void validate_file_path(const std::string& path) {
            if (path.empty()) {
                throw ValidationException("Empty file path");
            }
            
            // Check for path traversal attempts
            if (path.find("..") != std::string::npos || 
                path.find("./") != std::string::npos ||
                path.find("\\..") != std::string::npos) {
                throw PathTraversalException(path);
            }
        }

        // Validate size limits
        static void validate_size_limit(size_t size, size_t max_size, const std::string& context = "") {
            if (size > max_size) {
                throw ValidationException("Size limit exceeded", 
                    context + " - Size: " + std::to_string(size) + 
                    ", Max: " + std::to_string(max_size));
            }
        }
    };
}

#endif // SECURE_EXCEPTIONS_HPP
