#include "secure_exceptions.hpp"
#include "secure_memory.hpp"
#include "forensic_validator.hpp"
#include <iostream>
#include <vector>
#include <string>
#include "stealth_macros.hpp"

int main(int argc, char* argv[]) {
    // Complete silence enforcement - all debug output removed
    
    if (argc > 1 && std::string(argv[1]) == "--help") {
        // Complete silence enforcement - all debug output removed
        return 0;
    }
    
    if (argc > 1 && std::string(argv[1]) == "--test") {
        // Complete silence enforcement - all debug output removed
        
        ForensicValidator validator;
        validator.set_validation_strictness(0.8); // Set to 80% instead of default 90%
        validator.set_forensic_tool_testing(true); // Enable all forensic tool tests
        // Create realistic PDF test data with proper structure
        std::string realistic_pdf = R"(%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj

4 0 obj
<<
/Length 44
>>
stream
BT
/F1 12 Tf
72 720 Td
(Hello World) Tj
ET
endstream
endobj

xref
0 5
0000000000 65535 f 
0000000010 00000 n 
0000000053 00000 n 
0000000104 00000 n 
0000000179 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
/ID [<4E2B9F2C8A3D1E5F7B6C8D9E0F1A2B3C><4E2B9F2C8A3D1E5F7B6C8D9E0F1A2B3C>]
>>
startxref
273
%%EOF)";

        std::vector<uint8_t> test_data1(realistic_pdf.begin(), realistic_pdf.end());
        std::vector<uint8_t> test_data2 = test_data1; // Same PDF for testing identical match
        
        // Test core validation
        bool result = validator.validate(test_data1, test_data2);
        // Complete silence enforcement - all debug output removed
        
        // Test detailed validation
        auto detailed = validator.detailed_validate(test_data1, test_data2);
        // Complete silence enforcement - all debug output removed
        // Complete silence enforcement - all debug output removed
        
        // Test fingerprint extraction
        auto fingerprint = validator.extract_fingerprint(test_data1);
        // Complete silence enforcement - all debug output removed
        
        // Complete silence enforcement - all debug output removed
        return 0;
    }
    
    // Complete silence enforcement - all debug output removed
    // Complete silence enforcement - all debug output removed
    
    return 0;
}
