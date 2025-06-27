#include "silent_operation_validator.hpp"
#include <iostream>
#include <cstdlib>

int main() {
    // Run validation
    auto result = SilentOperationValidator::validate_silent_operation();
    
    // Exit with appropriate code
    if (result.is_completely_silent) {
        std::exit(0);
    } else {
        // Write violations to file since console is suppressed
        std::ofstream report("silence_violations.txt");
        if (report.is_open()) {
            report << "Silence Validation Failed\n";
            report << "========================\n";
            report << "stdout bytes: " << result.stdout_bytes_written << "\n";
            report << "stderr bytes: " << result.stderr_bytes_written << "\n";
            report << "Streams redirected: " << (result.streams_properly_redirected ? "yes" : "no") << "\n";
            report << "Files created: " << (!result.no_files_created ? "yes" : "no") << "\n";
            report << "\nViolations:\n";
            for (const auto& violation : result.detected_violations) {
                report << "- " << violation << "\n";
            }
            report.close();
        }
        std::exit(1);
    }
}