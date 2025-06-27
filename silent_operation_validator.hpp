#ifndef SILENT_OPERATION_VALIDATOR_HPP
#define SILENT_OPERATION_VALIDATOR_HPP

#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <chrono>
#include <fstream>

class SilentOperationValidator {
public:
    struct ValidationResult {
        bool is_completely_silent;
        size_t stdout_bytes_written;
        size_t stderr_bytes_written;
        std::vector<std::string> detected_violations;
        bool streams_properly_redirected;
        bool no_files_created;
        std::chrono::steady_clock::time_point validation_time;
    };
    
    static ValidationResult validate_silent_operation() {
        ValidationResult result;
        result.validation_time = std::chrono::steady_clock::now();
        result.is_completely_silent = true;
        result.stdout_bytes_written = 0;
        result.stderr_bytes_written = 0;
        result.streams_properly_redirected = false;
        result.no_files_created = true;
        
        // Check if streams are redirected to null
        std::ostringstream test_stream;
        auto cout_buf = std::cout.rdbuf();
        auto cerr_buf = std::cerr.rdbuf();
        
        // Test stdout redirection
        std::cout.rdbuf(test_stream.rdbuf());
        std::cout << "TEST";
        std::cout.rdbuf(cout_buf);
        
        if (test_stream.str().empty()) {
            result.streams_properly_redirected = true;
        } else {
            result.detected_violations.push_back("stdout not properly redirected");
            result.stdout_bytes_written = test_stream.str().length();
            result.is_completely_silent = false;
        }
        
        // Test stderr redirection
        test_stream.str("");
        std::cerr.rdbuf(test_stream.rdbuf());
        std::cerr << "TEST";
        std::cerr.rdbuf(cerr_buf);
        
        if (!test_stream.str().empty()) {
            result.detected_violations.push_back("stderr not properly redirected");
            result.stderr_bytes_written = test_stream.str().length();
            result.is_completely_silent = false;
        }
        
        // Check for file creation attempts
        std::ofstream test_file("test_silent_operation.tmp");
        if (test_file.is_open()) {
            test_file.close();
            std::remove("test_silent_operation.tmp");
            result.detected_violations.push_back("file creation not suppressed");
            result.no_files_created = false;
            result.is_completely_silent = false;
        }
        
        return result;
    }
    
    static void start_monitoring() {
        monitoring_active_ = true;
        cout_monitor_.str("");
        cerr_monitor_.str("");
        
        // Redirect streams to monitoring buffers
        original_cout_ = std::cout.rdbuf();
        original_cerr_ = std::cerr.rdbuf();
        
        std::cout.rdbuf(cout_monitor_.rdbuf());
        std::cerr.rdbuf(cerr_monitor_.rdbuf());
    }
    
    static void stop_monitoring() {
        if (monitoring_active_) {
            // Restore original streams
            std::cout.rdbuf(original_cout_);
            std::cerr.rdbuf(original_cerr_);
            
            monitoring_active_ = false;
        }
    }
    
    static bool verify_zero_output() {
        return cout_monitor_.str().empty() && cerr_monitor_.str().empty();
    }
    
    static std::string get_captured_output() {
        return "stdout: " + cout_monitor_.str() + "\nstderr: " + cerr_monitor_.str();
    }
    
private:
    static std::ostringstream cout_monitor_;
    static std::ostringstream cerr_monitor_;
    static std::streambuf* original_cout_;
    static std::streambuf* original_cerr_;
    static bool monitoring_active_;
};

// Static member definitions
std::ostringstream SilentOperationValidator::cout_monitor_;
std::ostringstream SilentOperationValidator::cerr_monitor_;
std::streambuf* SilentOperationValidator::original_cout_ = nullptr;
std::streambuf* SilentOperationValidator::original_cerr_ = nullptr;
bool SilentOperationValidator::monitoring_active_ = false;

#endif // SILENT_OPERATION_VALIDATOR_HPP