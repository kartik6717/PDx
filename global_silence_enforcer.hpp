#ifndef GLOBAL_SILENCE_ENFORCER_HPP
#define GLOBAL_SILENCE_ENFORCER_HPP

#include <iostream>
#include <fstream>
#include <streambuf>
#include <memory>
#include <cstdio>
#include <stdexcept>
#include "production_mode_checker.hpp"
#include "secure_memory.hpp"
#include "secure_exceptions.hpp"

class GlobalSilenceEnforcer {
private:
    static std::streambuf* original_cout_buf_;
    static std::streambuf* original_cerr_buf_;
    static std::streambuf* original_clog_buf_;
    static std::ofstream null_stream_;
    static bool silence_activated_;
    
public:
    static void activate_complete_silence() {
        try {
            if (!silence_activated_) {
                // Save original stream buffers with validation
                original_cout_buf_ = std::cout.rdbuf();
                original_cerr_buf_ = std::cerr.rdbuf();
                original_clog_buf_ = std::clog.rdbuf();
                
                if (!original_cout_buf_ || !original_cerr_buf_ || !original_clog_buf_) {
                    throw SecureException("Failed to save original stream buffers");
                }
                
                // Open null device with error checking
                #ifdef _WIN32
                    null_stream_.open("NUL");
                #else
                    null_stream_.open("/dev/null");
                #endif
                
                if (!null_stream_.is_open()) {
                    throw SecureException("Failed to open null device for global silence");
                }
                
                // Redirect all C++ streams to null
                std::cout.rdbuf(null_stream_.rdbuf());
                std::cerr.rdbuf(null_stream_.rdbuf());
                std::clog.rdbuf(null_stream_.rdbuf());
                
                // Redirect C-style streams with validation
                #ifdef _WIN32
                    if (freopen("NUL", "w", stdout) == nullptr || freopen("NUL", "w", stderr) == nullptr) {
                        throw SecureException("Failed to redirect C-style streams");
                    }
                #else
                    if (freopen("/dev/null", "w", stdout) == nullptr || freopen("/dev/null", "w", stderr) == nullptr) {
                        throw SecureException("Failed to redirect C-style streams");
                    }
                #endif
                
                // Disable sync with C streams for better performance and silence
                std::ios_base::sync_with_stdio(false);
                
                // Additional trace elimination
                eliminate_system_traces();
                
                silence_activated_ = true;
            }
        } catch (const std::exception& e) {
            // Silent exception handling - critical for maintaining silence
            SecureException::handle_silent_exception(e);
        }
    }
    
    static void deactivate_silence() {
        try {
            if (silence_activated_ && ProductionModeChecker::is_debug_mode()) {
                // Restore original stream buffers with secure cleanup
                if (original_cout_buf_) {
                    std::cout.rdbuf(original_cout_buf_);
                    original_cout_buf_ = nullptr;
                }
                
                if (original_cerr_buf_) {
                    std::cerr.rdbuf(original_cerr_buf_);
                    original_cerr_buf_ = nullptr;
                }
                
                if (original_clog_buf_) {
                    std::clog.rdbuf(original_clog_buf_);
                    original_clog_buf_ = nullptr;
                }
                
                // Securely close null stream
                if (null_stream_.is_open()) {
                    null_stream_.close();
                }
                
                // Secure memory cleanup
                perform_secure_cleanup();
                
                silence_activated_ = false;
            }
        } catch (const std::exception& e) {
            SecureException::handle_silent_exception(e);
        }
    }
    
    static bool is_silence_active() {
        return silence_activated_;
    }
    
    static void eliminate_system_traces() {
        // Set environment variables to suppress all possible traces
        #ifdef _WIN32
            _putenv_s("SILENT_PDF_PROCESSING", "1");
            _putenv_s("NO_TRACE_OUTPUT", "1");
            _putenv_s("SUPPRESS_ALL_LOGS", "1");
        #else
            setenv("SILENT_PDF_PROCESSING", "1", 1);
            setenv("NO_TRACE_OUTPUT", "1", 1);
            setenv("SUPPRESS_ALL_LOGS", "1", 1);
        #endif
    }
    
    static void perform_secure_cleanup() {
        // Zero out sensitive memory areas
        SecureMemory::zero_memory(&original_cout_buf_, sizeof(original_cout_buf_));
        SecureMemory::zero_memory(&original_cerr_buf_, sizeof(original_cerr_buf_));
        SecureMemory::zero_memory(&original_clog_buf_, sizeof(original_clog_buf_));
    }
    
    // Automatic activation on program start with enhanced security
    class AutoActivator {
    public:
        AutoActivator() {
            try {
                GlobalSilenceEnforcer::activate_complete_silence();
            } catch (...) {
                // Silent failure - no output even for initialization errors
            }
        }
    };
    
private:
    static AutoActivator auto_activator_;
};

// Static member definitions
std::streambuf* GlobalSilenceEnforcer::original_cout_buf_ = nullptr;
std::streambuf* GlobalSilenceEnforcer::original_cerr_buf_ = nullptr;
std::streambuf* GlobalSilenceEnforcer::original_clog_buf_ = nullptr;
std::ofstream GlobalSilenceEnforcer::null_stream_;
bool GlobalSilenceEnforcer::silence_activated_ = false;
GlobalSilenceEnforcer::AutoActivator GlobalSilenceEnforcer::auto_activator_;

#endif // GLOBAL_SILENCE_ENFORCER_HPP