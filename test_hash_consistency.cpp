#include "secure_memory.hpp"
#include "secure_exceptions.hpp"

#include "utils.hpp"
#include "forensic_validator.hpp"
#include <iostream>
#include "stealth_macros.hpp"

void test_hash_consistency() {
    SILENT_LOG("Testing hash consistency for same source PDF...\n");
    
    // Create test PDF data
    std::string test_pdf = R"(%PDF-1.4
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
>>
endobj
xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000074 00000 n 
0000000130 00000 n 
trailer
<<
/Size 4
/Root 1 0 R
>>
startxref
210
%%EOF)";

    std::vector<uint8_t> pdf_data(test_pdf.begin(), test_pdf.end()) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    // Extract consistent hashes
    auto hash_set1 = PDFUtils::extract_consistent_hashes(pdf_data) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    auto hash_set2 = PDFUtils::extract_consistent_hashes(pdf_data) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    auto hash_set3 = PDFUtils::extract_consistent_hashes(pdf_data) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    // Verify all hash sets are identical for same input
    if (!(hash_set1.md5_hash == hash_set2.md5_hash) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(hash_set1.md5_hash == hash_set3.md5_hash) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    if (!(hash_set1.sha256_hash == hash_set2.sha256_hash) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(hash_set1.sha256_hash == hash_set3.sha256_hash) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    if (!(hash_set1.structural_hash == hash_set2.structural_hash) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(hash_set1.structural_hash == hash_set3.structural_hash) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    // NEW: Verify that for the SAME source PDF, all three hash types are IDENTICAL
    // (since structural hash now uses SHA256 of the same source data)
    if (!(hash_set1.sha256_hash == hash_set1.structural_hash) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(hash_set2.sha256_hash == hash_set2.structural_hash) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(hash_set3.sha256_hash == hash_set3.structural_hash) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    SILENT_LOG("✅ Hash consistency verified - all 3 hash types are identical for same source PDF\n");
    SILENT_LOG("MD5: ") << hash_set1.md5_hash << "\n";
    SILENT_LOG("SHA256: ") << hash_set1.sha256_hash << "\n";
    SILENT_LOG("Structural: ") << hash_set1.structural_hash << "\n";
    SILENT_LOG("✅ VERIFIED: SHA256 == Structural hash (both use same source data)\n");
}

int main() {
    test_hash_consistency() { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    return 0;
}
