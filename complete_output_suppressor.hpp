#ifndef COMPLETE_OUTPUT_SUPPRESSOR_HPP
#define COMPLETE_OUTPUT_SUPPRESSOR_HPP

#include <iostream>
#include <fstream>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
#include <sstream>
#include <memory>
#include "secure_memory.hpp"
#include "secure_exceptions.hpp"

class CompleteOutputSuppressor {
private:
    static int saved_stdout_fd_;
    static int saved_stderr_fd_;
    static int null_fd_;
    static bool suppression_active_;
    static std::streambuf* saved_cout_buf_;
    static std::streambuf* saved_cerr_buf_;
    static std::streambuf* saved_clog_buf_;
    static std::unique_ptr<std::ofstream> null_stream_;
    
public:
    static void suppress_all_output() {
        try {
            if (!suppression_active_) {
                // Save original file descriptors with secure memory
                saved_stdout_fd_ = dup(STDOUT_FILENO);
                saved_stderr_fd_ = dup(STDERR_FILENO);
                
                if (saved_stdout_fd_ == -1 || saved_stderr_fd_ == -1) {
                    throw SecureException("Failed to save original file descriptors");
                }
                
                // Open null device
                #ifdef _WIN32
                    null_fd_ = open("NUL", O_WRONLY);
                #else
                    null_fd_ = open("/dev/null", O_WRONLY);
                #endif
                
                if (null_fd_ == -1) {
                    throw SecureException("Failed to open null device");
                }
                
                // Redirect file descriptors to null
                if (dup2(null_fd_, STDOUT_FILENO) == -1 || dup2(null_fd_, STDERR_FILENO) == -1) {
                    throw SecureException("Failed to redirect file descriptors");
                }
                
                // Save C++ stream buffers
                saved_cout_buf_ = std::cout.rdbuf();
                saved_cerr_buf_ = std::cerr.rdbuf();
                saved_clog_buf_ = std::clog.rdbuf();
                
                // Open null stream with secure memory management
                null_stream_ = std::make_unique<std::ofstream>();
                #ifdef _WIN32
                    null_stream_->open("NUL");
                #else
                    null_stream_->open("/dev/null");
                #endif
                
                if (!null_stream_->is_open()) {
                    throw SecureException("Failed to open null stream");
                }
                
                // Redirect C++ streams
                std::cout.rdbuf(null_stream_->rdbuf());
                std::cerr.rdbuf(null_stream_->rdbuf());
                std::clog.rdbuf(null_stream_->rdbuf());
                
                // Also redirect C stdio
                #ifdef _WIN32
                    if (freopen("NUL", "w", stdout) == nullptr || freopen("NUL", "w", stderr) == nullptr) {
                        throw SecureException("Failed to redirect C stdio");
                    }
                #else
                    if (freopen("/dev/null", "w", stdout) == nullptr || freopen("/dev/null", "w", stderr) == nullptr) {
                        throw SecureException("Failed to redirect C stdio");
                    }
                #endif
                
                suppression_active_ = true;
            }
        } catch (const std::exception& e) {
            // Secure exception handling without output
            SecureException::handle_silent_exception(e);
        }
    }
    
    static void restore_output() {
        try {
            if (suppression_active_) {
                // Restore file descriptors with error checking
                if (saved_stdout_fd_ != -1) {
                    dup2(saved_stdout_fd_, STDOUT_FILENO);
                    close(saved_stdout_fd_);
                    saved_stdout_fd_ = -1;
                }
                
                if (saved_stderr_fd_ != -1) {
                    dup2(saved_stderr_fd_, STDERR_FILENO);
                    close(saved_stderr_fd_);
                    saved_stderr_fd_ = -1;
                }
                
                if (null_fd_ != -1) {
                    close(null_fd_);
                    null_fd_ = -1;
                }
                
                // Restore C++ streams
                if (saved_cout_buf_) {
                    std::cout.rdbuf(saved_cout_buf_);
                    saved_cout_buf_ = nullptr;
                }
                
                if (saved_cerr_buf_) {
                    std::cerr.rdbuf(saved_cerr_buf_);
                    saved_cerr_buf_ = nullptr;
                }
                
                if (saved_clog_buf_) {
                    std::clog.rdbuf(saved_clog_buf_);
                    saved_clog_buf_ = nullptr;
                }
                
                // Securely close null stream
                if (null_stream_) {
                    null_stream_->close();
                    null_stream_.reset();
                }
                
                suppression_active_ = false;
            }
        } catch (const std::exception& e) {
            // Silent error handling for restoration
            SecureException::handle_silent_exception(e);
        }
    }
    
    static bool is_suppressed() {
        return suppression_active_;
    }
    
    static void enforce_silent_initialization() {
        // Ensure complete silence from the start
        suppress_all_output();
    }
    
    static void secure_cleanup() {
        // Perform secure cleanup with memory zeroing
        if (suppression_active_) {
            restore_output();
        }
        SecureMemory::zero_memory(&saved_stdout_fd_, sizeof(saved_stdout_fd_));
        SecureMemory::zero_memory(&saved_stderr_fd_, sizeof(saved_stderr_fd_));
        SecureMemory::zero_memory(&null_fd_, sizeof(null_fd_));
    }
};

// Static member definitions with secure initialization
int CompleteOutputSuppressor::saved_stdout_fd_ = -1;
int CompleteOutputSuppressor::saved_stderr_fd_ = -1;
int CompleteOutputSuppressor::null_fd_ = -1;
bool CompleteOutputSuppressor::suppression_active_ = false;
std::streambuf* CompleteOutputSuppressor::saved_cout_buf_ = nullptr;
std::streambuf* CompleteOutputSuppressor::saved_cerr_buf_ = nullptr;
std::streambuf* CompleteOutputSuppressor::saved_clog_buf_ = nullptr;
std::unique_ptr<std::ofstream> CompleteOutputSuppressor::null_stream_ = nullptr;

#endif // COMPLETE_OUTPUT_SUPPRESSOR_HPP