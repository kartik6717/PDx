#include "secure_memory.hpp"
#include "secure_exceptions.hpp"
#include <iostream>
#include <vector>
#include <string>
#include "secure_exceptions.hpp"
#include "anti_fingerprint_engine.hpp"
#include "stealth_macros.hpp"

void test_exact_source_fidelity() {
    SILENT_LOG("Testing Exact Source Fidelity - No Tampering Detection...\n");
    
    AntiFingerprintEngine engine;
    
    // Test 1: Source with authentic timestamps - should preserve exactly
    std::string test_pdf_with_timestamps = R"(
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
4 0 obj
<< 
/Producer (Authentic Original Producer)
/Creator (Original Creator Tool)
/ModDate (D:20230515141500+02'00')
/CreationDate (D:20230515140000+02'00')
/Title (Original Document Title)
/Author (Original Author Name)
>>
endobj
trailer
<< /Size 5 /Root 1 0 R /Info 4 0 R >>
)";
    
    std::vector<uint8_t> pdf_with_timestamps(test_pdf_with_timestamps.begin(), test_pdf_with_timestamps.end()) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    // Set authentic source metadata exactly as it was
    engine.set_source_metadata("Producer", "Authentic Original Producer") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    engine.set_source_metadata("Creator", "Original Creator Tool") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    engine.set_source_metadata("ModDate", "D:20230515141500+02'00'") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    engine.set_source_metadata("CreationDate", "D:20230515140000+02'00'") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    engine.set_source_metadata("Title", "Original Document Title") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    engine.set_source_metadata("Author", "Original Author Name") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    std::vector<uint8_t> result_with_timestamps = engine.process(pdf_with_timestamps) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    std::string result_str_timestamps(result_with_timestamps.begin(), result_with_timestamps.end()) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    // Verify EXACT preservation of source data
    if (!(result_str_timestamps.find("Authentic Original Producer") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_timestamps.find("Original Creator Tool") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_timestamps.find("D:20230515141500+02'00'") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_timestamps.find("D:20230515140000+02'00'") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_timestamps.find("Original Document Title") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_timestamps.find("Original Author Name") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    SILENT_LOG("✓ Test 1 PASSED: Exact source metadata preserved with timestamps\n");
    
    // Test 2: Source with blank fields - should remain blank (no unwrapping)
    std::string test_pdf_with_blanks = R"(
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
4 0 obj
<< 
/Producer ()
/Creator ()
/ModDate ()
/CreationDate ()
/Title (Actual Title Exists)
/Author ()
>>
endobj
trailer
<< /Size 5 /Root 1 0 R /Info 4 0 R >>
)";
    
    std::vector<uint8_t> pdf_with_blanks(test_pdf_with_blanks.begin(), test_pdf_with_blanks.end()) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    // Clear and set source metadata to match source (some blank, some with values)
    engine.clear_source_metadata() { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    engine.set_source_metadata("Producer", "") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }  // Source was blank
    engine.set_source_metadata("Creator", "") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }   // Source was blank
    engine.set_source_metadata("ModDate", "") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }   // Source was blank
    engine.set_source_metadata("CreationDate", "") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } } // Source was blank
    engine.set_source_metadata("Title", "Actual Title Exists") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } } // Source had value
    engine.set_source_metadata("Author", "") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }    // Source was blank
    
    std::vector<uint8_t> result_with_blanks = engine.process(pdf_with_blanks) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    std::string result_str_blanks(result_with_blanks.begin(), result_with_blanks.end()) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    // Verify blank fields remain blank (field structure preserved)
    if (!(result_str_blanks.find("/Producer ()") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_blanks.find("/Creator ()") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_blanks.find("/ModDate ()") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_blanks.find("/CreationDate ()") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_blanks.find("/Author ()") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    // Verify field with actual value is preserved
    if (!(result_str_blanks.find("Actual Title Exists") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    // Verify NO unwrapping occurred
    if (!(result_str_blanks.find("unknown") == std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_blanks.find("blank") == std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_blanks.find("empty") == std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_blanks.find("default") == std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_blanks.find("N/A") == std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    SILENT_LOG("✓ Test 2 PASSED: Blank fields remain blank with no unwrapping\n");
    
    // Test 3: Processing tool contamination removal while preserving structure
    std::string test_pdf_contaminated = R"(
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
4 0 obj
<< 
/Producer (GPL Ghostscript 9.50 - with original data from: Authentic Source)
/Creator (PDFtk Server 3.0.9 - created from: Original Creator)
/ModDate (D:20240625120000+00'00')
/CreationDate (D:20240625110000+00'00')
/Title (Generated by qpdf - Original: Real Document Title)
>>
endobj
trailer
<< /Size 5 /Root 1 0 R /Info 4 0 R >>
)";
    
    std::vector<uint8_t> pdf_contaminated(test_pdf_contaminated.begin(), test_pdf_contaminated.end()) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    // Set authentic source data (what should be preserved)
    engine.clear_source_metadata() { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    engine.set_source_metadata("Producer", "Authentic Source") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    engine.set_source_metadata("Creator", "Original Creator") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    engine.set_source_metadata("ModDate", "D:20230301100000+01'00'") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } } // Original timestamp
    engine.set_source_metadata("CreationDate", "D:20230301095500+01'00'") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } } // Original timestamp
    engine.set_source_metadata("Title", "Real Document Title") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    std::vector<uint8_t> result_decontaminated = engine.process(pdf_contaminated) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    std::string result_str_decontaminated(result_decontaminated.begin(), result_decontaminated.end()) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    // Verify tool signatures removed but authentic source data preserved
    if (!(result_str_decontaminated.find("GPL Ghostscript") == std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_decontaminated.find("PDFtk") == std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_decontaminated.find("qpdf") == std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    // Verify authentic source data is preserved
    if (!(result_str_decontaminated.find("Authentic Source") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_decontaminated.find("Original Creator") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_decontaminated.find("D:20230301100000+01'00'") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_decontaminated.find("D:20230301095500+01'00'") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_decontaminated.find("Real Document Title") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    // Verify field structure is intact (no deletion)
    if (!(result_str_decontaminated.find("/Producer (") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_decontaminated.find("/Creator (") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_decontaminated.find("/ModDate (") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_decontaminated.find("/CreationDate (") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_decontaminated.find("/Title (") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    SILENT_LOG("✓ Test 3 PASSED: Tool contamination removed, authentic data preserved, structure intact\n");
    
    // Test 4: Mixed scenario - some fields blank in source, some with values
    std::string test_pdf_mixed = R"(
%PDF-1.4
4 0 obj
<< 
/Producer (Tool Generated Producer)
/Creator ()
/ModDate (D:20240625120000+00'00')
/CreationDate ()
/Title (Some Generated Title)
/Author (Tool Generated Author)
/Subject ()
>>
endobj
)";
    
    std::vector<uint8_t> pdf_mixed(test_pdf_mixed.begin(), test_pdf_mixed.end()) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    // Set source metadata - mix of values and blanks exactly as source had
    engine.clear_source_metadata() { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    engine.set_source_metadata("Producer", "Real Producer Name") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }  // Source had value
    engine.set_source_metadata("Creator", "") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }                     // Source was blank
    engine.set_source_metadata("ModDate", "D:20221215083000+00'00'") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } } // Source had value
    engine.set_source_metadata("CreationDate", "") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }               // Source was blank
    engine.set_source_metadata("Title", "") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }                      // Source was blank
    engine.set_source_metadata("Author", "Real Author") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }          // Source had value
    engine.set_source_metadata("Subject", "") { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }                    // Source was blank
    
    std::vector<uint8_t> result_mixed = engine.process(pdf_mixed) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    std::string result_str_mixed(result_mixed.begin(), result_mixed.end()) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    // Fields with source values should have those values
    if (!(result_str_mixed.find("Real Producer Name") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_mixed.find("D:20221215083000+00'00'") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_mixed.find("Real Author") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    // Fields that were blank in source should remain blank
    if (!(result_str_mixed.find("/Creator ()") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_mixed.find("/CreationDate ()") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_mixed.find("/Title ()") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_mixed.find("/Subject ()") != std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    // No tool signatures should remain
    if (!(result_str_mixed.find("Tool Generated") == std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    if (!(result_str_mixed.find("Generated Title") == std::string::npos) { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
    
    SILENT_LOG("✓ Test 4 PASSED: Mixed scenario - exact source fidelity maintained\n");
    
    SILENT_LOG("\n===========================================\n");
    SILENT_LOG("EXACT SOURCE FIDELITY VALIDATION COMPLETE\n");
    SILENT_LOG("===========================================\n");
    SILENT_LOG("✓ Field structure preserved (no deletion)\n");
    SILENT_LOG("✓ Blank fields remain blank (no unwrapping)\n");
    SILENT_LOG("✓ Source timestamps preserved exactly\n");
    SILENT_LOG("✓ No tampering indicators introduced\n");
    SILENT_LOG("✓ Tool signatures removed completely\n");
    SILENT_LOG("✓ Authentic source data preserved exactly\n");
}

int main() {
    try {
        test_exact_source_fidelity() { throw SecureExceptions::ValidationException("Assertion failed", __FILE__ ":" + std::to_string(__LINE__)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); } }
        SILENT_LOG("\nAll tests PASSED! Anti-fingerprinting preserves exact source fidelity.\n");
        return 0;
    } catch (const std::exception& e) {
        SILENT_ERROR("Test FAILED: ") << e.what() << std::endl;
        return 1;
    }
}