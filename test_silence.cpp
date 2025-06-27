#include "silence_enforcement_config.hpp"
#include "silent_operation_validator.hpp"
#include <iostream>
#include <fstream>

int main() {
    // Test that all output is suppressed
    std::cout << "This should not appear" << std::endl;
    std::cerr << "This error should not appear" << std::endl;
    
    // Try to write to a file
    std::ofstream test_file("test_output.txt");
    if (test_file.is_open()) {
        test_file << "This should not be written" << std::endl;
        test_file.close();
    }
    
    // Validate silence
    auto result = SilentOperationValidator::validate_silent_operation();
    
    // Return 0 if completely silent, 1 otherwise
    return result.is_completely_silent ? 0 : 1;
}