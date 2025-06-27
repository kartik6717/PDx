#ifndef LIGHTWEIGHT_TRACE_SUPPRESSOR_HPP
#define LIGHTWEIGHT_TRACE_SUPPRESSOR_HPP

#include <iostream>
#include <fstream>
#include <streambuf>
#include <memory>
#include <vector>
#include <cstdio>
#include <stdexcept>
#include "secure_memory.hpp"
#include "secure_exceptions.hpp"

class LightweightTraceSuppressor {
private:
    static std::streambuf* original_cout_;
    static std::streambuf* original_cerr_;
    static std::streambuf* original_clog_;
    static std::unique_ptr<std::ofstream> null_stream_;
    static bool suppression_active_;
    static std::vector<FILE*> suppressed_files_;
    
public:
    static void suppress_all_traces() {
        try {
            if (!suppression_active_) {
                // Save original stream buffers with validation
                original_cout_ = std::cout.rdbuf();
                original_cerr_ = std::cerr.rdbuf();
                original_clog_ = std::clog.rdbuf();
                
                if (!original_cout_ || !original_cerr_ || !original_clog_) {
                    throw SecureException("Failed to save original stream buffers for trace suppression");
                }
                
                // Create null stream with secure memory management
                #ifdef _WIN32
                    null_stream_ = std::make_unique<std::ofstream>("NUL");
                #else
                    null_stream_ = std::make_unique<std::ofstream>("/dev/null");
                #endif
                
                if (!null_stream_ || !null_stream_->is_open()) {
                    throw SecureException("Failed to create null stream for trace suppression");
                }
                
                // Redirect C++ streams with error checking
                std::cout.rdbuf(null_stream_->rdbuf());
                std::cerr.rdbuf(null_stream_->rdbuf());
                std::clog.rdbuf(null_stream_->rdbuf());
                
                // Redirect C stdio with validation
                #ifdef _WIN32
                    if (freopen("NUL", "w", stdout) == nullptr || freopen("NUL", "w", stderr) == nullptr) {
                        throw SecureException("Failed to redirect C stdio streams");
                    }
                #else
                    if (freopen("/dev/null", "w", stdout) == nullptr || freopen("/dev/null", "w", stderr) == nullptr) {
                        throw SecureException("Failed to redirect C stdio streams");
                    }
                #endif
                
                // Enhanced trace elimination
                eliminate_all_debug_traces();
                suppress_library_logging();
                
                suppression_active_ = true;
            }
        } catch (const std::exception& e) {
            // Silent exception handling - critical for trace suppression
            SecureException::handle_silent_exception(e);
        }
    }
    
    static void restore_traces() {
        try {
            if (suppression_active_) {
                // Restore C++ streams with secure cleanup
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
                
                // Securely close null stream
                if (null_stream_ && null_stream_->is_open()) {
                    null_stream_->close();
                }
                null_stream_.reset();
                
                // Secure memory cleanup
                perform_restoration_cleanup();
                
                suppression_active_ = false;
            }
        } catch (const std::exception& e) {
            SecureException::handle_silent_exception(e);
        }
    }
    
    static bool is_suppression_active() {
        return suppression_active_;
    }
    
    static void suppress_file_traces() {
        try {
            if (!suppression_active_) {
                return;
            }
            
            // Enhanced file suppression for libraries that might create files
            #ifdef _WIN32
                if (freopen("NUL", "w", stdout) == nullptr || freopen("NUL", "w", stderr) == nullptr) {
                    throw SecureException("Failed to suppress file traces");
                }
            #else
                if (freopen("/dev/null", "w", stdout) == nullptr || freopen("/dev/null", "w", stderr) == nullptr) {
                    throw SecureException("Failed to suppress file traces");
                }
            #endif
            
            // Additional trace suppression measures
            suppress_temporary_files();
            eliminate_log_files();
            
        } catch (const std::exception& e) {
            SecureException::handle_silent_exception(e);
        }
    }
    
    static void emergency_silence() {
        try {
            // Force immediate silence without checks - critical security feature
            #ifdef _WIN32
                if (freopen("NUL", "w", stdout) == nullptr || freopen("NUL", "w", stderr) == nullptr) {
                    // Continue despite failure - emergency mode
                }
            #else
                if (freopen("/dev/null", "w", stdout) == nullptr || freopen("/dev/null", "w", stderr) == nullptr) {
                    // Continue despite failure - emergency mode
                }
            #endif
            
            static std::unique_ptr<std::ofstream> emergency_null = std::make_unique<std::ofstream>();
            #ifdef _WIN32
                emergency_null->open("NUL");
            #else
                emergency_null->open("/dev/null");
            #endif
            
            if (emergency_null && emergency_null->is_open()) {
                std::cout.rdbuf(emergency_null->rdbuf());
                std::cerr.rdbuf(emergency_null->rdbuf());
                std::clog.rdbuf(emergency_null->rdbuf());
            }
            
            // Emergency trace elimination
            emergency_trace_elimination();
            
        } catch (...) {
            // Silent emergency failure - continue without output
        }
    }
    
    static void eliminate_all_debug_traces() {
        // Comprehensive debug trace elimination
        try {
            #ifdef _WIN32
                _putenv_s("DEBUG", "0");
                _putenv_s("VERBOSE", "0");
                _putenv_s("TRACE", "0");
                _putenv_s("LOG_LEVEL", "0");
            #else
                setenv("DEBUG", "0", 1);
                setenv("VERBOSE", "0", 1);
                setenv("TRACE", "0", 1);
                setenv("LOG_LEVEL", "0", 1);
            #endif
        } catch (...) {
            // Silent failure
        }
    }
    
    static void suppress_library_logging() {
        // Suppress common library logging systems
        try {
            #ifdef _WIN32
                _putenv_s("GLOG_minloglevel", "3");
                _putenv_s("GLOG_stderrthreshold", "3");
                _putenv_s("SPDLOG_LEVEL", "off");
            #else
                setenv("GLOG_minloglevel", "3", 1);
                setenv("GLOG_stderrthreshold", "3", 1);
                setenv("SPDLOG_LEVEL", "off", 1);
            #endif
        } catch (...) {
            // Silent failure
        }
    }
    
    static void suppress_temporary_files() {
        // Prevent creation of temporary trace files
        try {
            #ifdef _WIN32
                _putenv_s("TMP", "NUL");
                _putenv_s("TEMP", "NUL");
            #else
                setenv("TMPDIR", "/dev/null", 1);
            #endif
        } catch (...) {
            // Silent failure
        }
    }
    
    static void eliminate_log_files() {
        // Ensure no log files are created
        try {
            #ifdef _WIN32
                _putenv_s("LOGFILE", "NUL");
            #else
                setenv("LOGFILE", "/dev/null", 1);
            #endif
        } catch (...) {
            // Silent failure
        }
    }
    
    static void perform_restoration_cleanup() {
        // Secure cleanup during restoration
        try {
            SecureMemory::zero_memory(&original_cout_, sizeof(original_cout_));
            SecureMemory::zero_memory(&original_cerr_, sizeof(original_cerr_));
            SecureMemory::zero_memory(&original_clog_, sizeof(original_clog_));
        } catch (...) {
            // Silent cleanup failure
        }
    }
    
    static void emergency_trace_elimination() {
        // Emergency trace elimination for critical situations
        try {
            eliminate_all_debug_traces();
            suppress_library_logging();
            suppress_temporary_files();
            eliminate_log_files();
        } catch (...) {
            // Silent emergency failure
        }
    }
    
    // Enhanced RAII wrapper for automatic suppression with security
    class ScopedSuppression {
    public:
        ScopedSuppression() {
            try {
                LightweightTraceSuppressor::suppress_all_traces();
            } catch (...) {
                // Silent initialization failure
            }
        }
        
        ~ScopedSuppression() {
            try {
                // Intentionally don't restore in destructor for security
                // Traces should remain suppressed
                // Perform secure cleanup instead
                LightweightTraceSuppressor::perform_restoration_cleanup();
            } catch (...) {
                // Silent cleanup failure
            }
        }
    };
};

// Static member definitions
std::streambuf* LightweightTraceSuppressor::original_cout_ = nullptr;
std::streambuf* LightweightTraceSuppressor::original_cerr_ = nullptr;
std::streambuf* LightweightTraceSuppressor::original_clog_ = nullptr;
std::unique_ptr<std::ofstream> LightweightTraceSuppressor::null_stream_ = nullptr;
bool LightweightTraceSuppressor::suppression_active_ = false;
std::vector<FILE*> LightweightTraceSuppressor::suppressed_files_;

// Convenience macros
#define SUPPRESS_ALL_TRACES() LightweightTraceSuppressor::suppress_all_traces()
#define SCOPED_TRACE_SUPPRESSION() LightweightTraceSuppressor::ScopedSuppression _suppressor_
#define EMERGENCY_SILENCE() LightweightTraceSuppressor::emergency_silence()

#endif // LIGHTWEIGHT_TRACE_SUPPRESSOR_HPP