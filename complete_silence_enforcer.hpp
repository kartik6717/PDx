
#pragma once

#include <iostream>
#include <fstream>
#include <streambuf>
#include <memory>
#include <cstdlib>
#include "secure_memory.hpp"
#include "secure_exceptions.hpp"

class CompleteSilenceEnforcer {
public:
    static void enforce_absolute_silence() {
        try {
            // Redirect all possible output streams to null with secure memory
            static std::unique_ptr<std::ofstream> null_stream;
            if (!null_stream) {
                null_stream = std::make_unique<std::ofstream>();
                #ifdef _WIN32
                    null_stream->open("NUL");
                #else
                    null_stream->open("/dev/null");
                #endif
                
                if (!null_stream->is_open()) {
                    throw SecureExceptions::SecureException("Failed to open null device for silence enforcement");
                }
            }
            
            // Store original buffers with validation
            if (!original_cout_) original_cout_ = std::cout.rdbuf();
            if (!original_cerr_) original_cerr_ = std::cerr.rdbuf();
            if (!original_clog_) original_clog_ = std::clog.rdbuf();
            
            // Redirect to null with error checking
            if (null_stream && null_stream->is_open()) {
                std::cout.rdbuf(null_stream->rdbuf());
                std::cerr.rdbuf(null_stream->rdbuf());
                std::clog.rdbuf(null_stream->rdbuf());
            }
            
            // Disable stdio outputs with validation
            #ifdef _WIN32
                if (freopen("NUL", "w", stdout) == nullptr || freopen("NUL", "w", stderr) == nullptr) {
                    throw SecureExceptions::SecureException("Failed to redirect stdio streams");
                }
            #else
                if (freopen("/dev/null", "w", stdout) == nullptr || freopen("/dev/null", "w", stderr) == nullptr) {
                    throw SecureExceptions::SecureException("Failed to redirect stdio streams");
                }
            #endif
            
            // Set environment variables for complete library silence with error checking
            #ifdef _WIN32
                if (_putenv_s("SILENT_MODE", "1") != 0 || 
                    _putenv_s("NO_OUTPUT", "1") != 0 || 
                    _putenv_s("QUIET", "1") != 0) {
                    throw SecureExceptions::SecureException("Failed to set silence environment variables");
                }
            #else
                if (setenv("SILENT_MODE", "1", 1) != 0 || 
                    setenv("NO_OUTPUT", "1", 1) != 0 || 
                    setenv("QUIET", "1", 1) != 0) {
                    throw SecureExceptions::SecureException("Failed to set silence environment variables");
                }
            #endif
            
            // Additional trace elimination
            eliminate_debug_traces();
            disable_logging_libraries();
            
        } catch (const std::exception& e) {
            // Silent exception handling - no output even for errors
            // Log error internally without output
        }
    }
    
    static void restore_streams() {
        try {
            if (original_cout_) {
                std::cout.rdbuf(original_cout_);
                original_cout_ = nullptr;
            }
            if (original_cerr_) {
                std::cerr.rdbuf(original_cerr_);
                original_cerr_ = nullptr;
            }
            if (original_clog_) {
                std::clog.rdbuf(original_clog_);
                original_clog_ = nullptr;
            }
            
            // Secure cleanup of environment variables
            secure_environment_cleanup();
            
        } catch (const std::exception& e) {
            SecureException::handle_silent_exception(e);
        }
    }
    
    static void eliminate_debug_traces() {
        // Disable debug traces at system level
        #ifndef NDEBUG
            #define NDEBUG
        #endif
        
        // Set additional environment variables to suppress traces
        #ifdef _WIN32
            _putenv_s("DEBUG", "0");
            _putenv_s("VERBOSE", "0");
            _putenv_s("TRACE", "0");
        #else
            setenv("DEBUG", "0", 1);
            setenv("VERBOSE", "0", 1);
            setenv("TRACE", "0", 1);
        #endif
    }
    
    static void disable_logging_libraries() {
        // Disable common logging libraries
        #ifdef _WIN32
            _putenv_s("GLOG_minloglevel", "3");
            _putenv_s("GLOG_stderrthreshold", "3");
            _putenv_s("GLOG_log_dir", "NUL");
        #else
            setenv("GLOG_minloglevel", "3", 1);
            setenv("GLOG_stderrthreshold", "3", 1);
            setenv("GLOG_log_dir", "/dev/null", 1);
        #endif
    }
    
    static void secure_environment_cleanup() {
        // Securely zero out environment variable memory if possible
        SecureMemory::zero_sensitive_environment_vars();
    }
    
private:
    static std::streambuf* original_cout_;
    static std::streambuf* original_cerr_;
    static std::streambuf* original_clog_;
};

// Static member definitions
std::streambuf* CompleteSilenceEnforcer::original_cout_ = nullptr;
std::streambuf* CompleteSilenceEnforcer::original_cerr_ = nullptr;
std::streambuf* CompleteSilenceEnforcer::original_clog_ = nullptr;

#define ENFORCE_COMPLETE_SILENCE() CompleteSilenceEnforcer::enforce_absolute_silence()
