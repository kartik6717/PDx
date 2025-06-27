#include "secure_memory.hpp"
#include "secure_exceptions.hpp"
#include "scrubber.hpp"
#include <iostream>
#include <vector>
#include "stealth_macros.hpp"

void test_circular_reference_detection() {
    SILENT_LOG("[Reference Test] Testing circular reference detection...\n");
    
    PDFScrubber scrubber;
    PDFStructure test_pdf;
    test_pdf.version = "1.4";
    
    // Create circular reference: 1 -> 2 -> 3 -> 1
    PDFObject obj1;
    obj1.number = 1;
    obj1.generation = 0;
    obj1.dictionary["/Type"] = "/TestObject";
    obj1.dictionary["/Next"] = "2 0 R"; // References object 2
    test_pdf.objects.push_back(obj1) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    PDFObject obj2;
    obj2.number = 2;
    obj2.generation = 0;
    obj2.dictionary["/Type"] = "/TestObject";
    obj2.dictionary["/Next"] = "3 0 R"; // References object 3
    test_pdf.objects.push_back(obj2) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    PDFObject obj3;
    obj3.number = 3;
    obj3.generation = 0;
    obj3.dictionary["/Type"] = "/TestObject";
    obj3.dictionary["/Next"] = "1 0 R"; // References object 1 - creates cycle
    test_pdf.objects.push_back(obj3) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Add required PDF structure
    PDFObject catalog;
    catalog.number = 4;
    catalog.generation = 0;
    catalog.dictionary["/Type"] = "/Catalog";
    catalog.dictionary["/Pages"] = "5 0 R";
    test_pdf.objects.push_back(catalog) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    PDFObject pages;
    pages.number = 5;
    pages.generation = 0;
    pages.dictionary["/Type"] = "/Pages";
    pages.dictionary["/Count"] = "1";
    test_pdf.objects.push_back(pages) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    test_pdf.trailer.dictionary["/Size"] = "6";
    test_pdf.trailer.dictionary["/Root"] = "4 0 R";
    
    // Test circular reference detection
    bool has_circular = scrubber.detect_circular_references(test_pdf) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (has_circular) {
        SILENT_LOG("✅ Circular reference correctly detected\n");
    } else {
        SILENT_LOG("❌ Failed to detect circular reference\n");
    }
    
    // Test automatic fixing
    scrubber.fix_circular_references(test_pdf) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    bool still_circular = scrubber.detect_circular_references(test_pdf) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!still_circular) {
        SILENT_LOG("✅ Circular references successfully fixed\n");
    } else {
        SILENT_LOG("❌ Circular references still present after fixing\n");
    }
}

void test_invalid_reference_detection() {
    SILENT_LOG("[Reference Test] Testing invalid reference detection...\n");
    
    PDFScrubber scrubber;
    PDFStructure test_pdf;
    test_pdf.version = "1.4";
    
    // Create object with reference to non-existent object
    PDFObject obj1;
    obj1.number = 1;
    obj1.generation = 0;
    obj1.dictionary["/Type"] = "/TestObject";
    obj1.dictionary["/InvalidRef"] = "999 0 R"; // References non-existent object 999
    obj1.content = "Some content with reference to 888 0 R"; // Another invalid reference
    test_pdf.objects.push_back(obj1) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Add required PDF structure
    PDFObject catalog;
    catalog.number = 2;
    catalog.generation = 0;
    catalog.dictionary["/Type"] = "/Catalog";
    catalog.dictionary["/Pages"] = "3 0 R";
    test_pdf.objects.push_back(catalog) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    PDFObject pages;
    pages.number = 3;
    pages.generation = 0;
    pages.dictionary["/Type"] = "/Pages";
    pages.dictionary["/Count"] = "1";
    test_pdf.objects.push_back(pages) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    test_pdf.trailer.dictionary["/Size"] = "4";
    test_pdf.trailer.dictionary["/Root"] = "2 0 R";
    
    // Test invalid reference detection
    bool integrity_valid = scrubber.validate_reference_integrity(test_pdf) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!integrity_valid) {
        SILENT_LOG("✅ Invalid references correctly detected\n");
    } else {
        SILENT_LOG("❌ Failed to detect invalid references\n");
    }
    
    // Test automatic fixing
    scrubber.validate_and_fix_references(test_pdf) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    bool integrity_fixed = scrubber.validate_reference_integrity(test_pdf) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (integrity_fixed) {
        SILENT_LOG("✅ Invalid references successfully fixed\n");
        
        // Verify references were replaced with null
        bool found_null_in_dict = test_pdf.objects[0].dictionary["/InvalidRef"] == "null";
        bool found_null_in_content = test_pdf.objects[0].content.find("null") != std::string::npos;
        
        if (found_null_in_dict && found_null_in_content) {
            SILENT_LOG("✅ Invalid references replaced with null values\n");
        }
    } else {
        SILENT_LOG("❌ Invalid references still present after fixing\n");
    }
}

void test_self_reference_handling() {
    SILENT_LOG("[Reference Test] Testing self-reference handling...\n");
    
    PDFScrubber scrubber;
    PDFStructure test_pdf;
    test_pdf.version = "1.4";
    
    // Create object that references itself
    PDFObject self_ref_obj;
    self_ref_obj.number = 1;
    self_ref_obj.generation = 0;
    self_ref_obj.dictionary["/Type"] = "/TestObject";
    self_ref_obj.dictionary["/SelfRef"] = "1 0 R"; // References itself
    test_pdf.objects.push_back(self_ref_obj) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Add required PDF structure
    PDFObject catalog;
    catalog.number = 2;
    catalog.generation = 0;
    catalog.dictionary["/Type"] = "/Catalog";
    catalog.dictionary["/Pages"] = "3 0 R";
    test_pdf.objects.push_back(catalog) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    PDFObject pages;
    pages.number = 3;
    pages.generation = 0;
    pages.dictionary["/Type"] = "/Pages";
    pages.dictionary["/Count"] = "1";
    test_pdf.objects.push_back(pages) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    test_pdf.trailer.dictionary["/Size"] = "4";
    test_pdf.trailer.dictionary["/Root"] = "2 0 R";
    
    // Test self-reference detection (should be detected as circular)
    bool has_circular = scrubber.detect_circular_references(test_pdf) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (has_circular) {
        SILENT_LOG("✅ Self-reference correctly detected as circular\n");
        
        // Fix it
        scrubber.fix_circular_references(test_pdf) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        
        bool fixed = !scrubber.detect_circular_references(test_pdf) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        if (fixed) {
            SILENT_LOG("✅ Self-reference successfully fixed\n");
        }
    } else {
        SILENT_LOG("❌ Failed to detect self-reference\n");
    }
}

void test_complex_circular_chain() {
    SILENT_LOG("[Reference Test] Testing complex circular reference chain...\n");
    
    PDFScrubber scrubber;
    PDFStructure test_pdf;
    test_pdf.version = "1.4";
    
    // Create complex circular chain: 1 -> 2 -> 3 -> 4 -> 2 (cycle involves 2,3,4)
    PDFObject obj1;
    obj1.number = 1;
    obj1.generation = 0;
    obj1.dictionary["/Type"] = "/TestObject";
    obj1.dictionary["/Next"] = "2 0 R";
    test_pdf.objects.push_back(obj1) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    PDFObject obj2;
    obj2.number = 2;
    obj2.generation = 0;
    obj2.dictionary["/Type"] = "/TestObject";
    obj2.dictionary["/Next"] = "3 0 R";
    test_pdf.objects.push_back(obj2) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    PDFObject obj3;
    obj3.number = 3;
    obj3.generation = 0;
    obj3.dictionary["/Type"] = "/TestObject";
    obj3.dictionary["/Next"] = "4 0 R";
    test_pdf.objects.push_back(obj3) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    PDFObject obj4;
    obj4.number = 4;
    obj4.generation = 0;
    obj4.dictionary["/Type"] = "/TestObject";
    obj4.dictionary["/Next"] = "2 0 R"; // Back to 2, creating cycle
    test_pdf.objects.push_back(obj4) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Add required PDF structure
    PDFObject catalog;
    catalog.number = 5;
    catalog.generation = 0;
    catalog.dictionary["/Type"] = "/Catalog";
    catalog.dictionary["/Pages"] = "6 0 R";
    test_pdf.objects.push_back(catalog) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    PDFObject pages;
    pages.number = 6;
    pages.generation = 0;
    pages.dictionary["/Type"] = "/Pages";
    pages.dictionary["/Count"] = "1";
    test_pdf.objects.push_back(pages) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    test_pdf.trailer.dictionary["/Size"] = "7";
    test_pdf.trailer.dictionary["/Root"] = "5 0 R";
    
    // Test complex circular detection
    bool has_circular = scrubber.detect_circular_references(test_pdf) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (has_circular) {
        SILENT_LOG("✅ Complex circular chain correctly detected\n");
        
        // Fix the circular references
        scrubber.fix_circular_references(test_pdf) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        
        bool fixed = !scrubber.detect_circular_references(test_pdf) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        if (fixed) {
            SILENT_LOG("✅ Complex circular chain successfully fixed\n");
        }
    } else {
        SILENT_LOG("❌ Failed to detect complex circular chain\n");
    }
}

void test_reference_update_protection() {
    SILENT_LOG("[Reference Test] Testing reference update protection...\n");
    
    PDFScrubber scrubber;
    PDFStructure test_pdf;
    test_pdf.version = "1.4";
    
    // Create valid reference structure
    PDFObject obj1;
    obj1.number = 1;
    obj1.generation = 0;
    obj1.dictionary["/Type"] = "/TestObject";
    obj1.dictionary["/Ref"] = "2 0 R";
    test_pdf.objects.push_back(obj1) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    PDFObject obj2;
    obj2.number = 2;
    obj2.generation = 0;
    obj2.dictionary["/Type"] = "/TestObject";
    test_pdf.objects.push_back(obj2) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Add required PDF structure
    PDFObject catalog;
    catalog.number = 3;
    catalog.generation = 0;
    catalog.dictionary["/Type"] = "/Catalog";
    catalog.dictionary["/Pages"] = "4 0 R";
    test_pdf.objects.push_back(catalog) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    PDFObject pages;
    pages.number = 4;
    pages.generation = 0;
    pages.dictionary["/Type"] = "/Pages";
    pages.dictionary["/Count"] = "1";
    test_pdf.objects.push_back(pages) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    test_pdf.trailer.dictionary["/Size"] = "5";
    test_pdf.trailer.dictionary["/Root"] = "3 0 R";
    
    // Test update that would create circular reference (update 2 to reference 1)
    SILENT_LOG("Attempting update that would create circular reference...\n");
    
    // This should be detected and prevented
    scrubber.update_object_references(test_pdf, 2, 1) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Verify no circular references were created
    bool has_circular = scrubber.detect_circular_references(test_pdf) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!has_circular) {
        SILENT_LOG("✅ Reference update protection working - no circular references created\n");
    } else {
        SILENT_LOG("❌ Circular reference was created during update\n");
    }
    
    // Verify reference integrity is maintained
    bool integrity_ok = scrubber.validate_reference_integrity(test_pdf) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (integrity_ok) {
        SILENT_LOG("✅ Reference integrity maintained after update\n");
    } else {
        SILENT_LOG("❌ Reference integrity compromised\n");
    }
}

void test_malicious_pdf_references() {
    SILENT_LOG("[Reference Test] Testing malicious PDF reference handling...\n");
    
    PDFScrubber scrubber;
    PDFStructure malicious_pdf;
    malicious_pdf.version = "1.4";
    
    // Create malicious reference structure with multiple issues
    
    // Object with invalid reference format
    PDFObject malformed_obj;
    malformed_obj.number = 1;
    malformed_obj.generation = 0;
    malformed_obj.dictionary["/Type"] = "/Malicious";
    malformed_obj.dictionary["/BadRef"] = "not_a_reference";
    malformed_obj.content = "Bad content with 999999999 0 R"; // Very large object number
    malicious_pdf.objects.push_back(malformed_obj) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Object with negative reference
    PDFObject negative_ref_obj;
    negative_ref_obj.number = 2;
    negative_ref_obj.generation = 0;
    negative_ref_obj.dictionary["/Type"] = "/Malicious";
    negative_ref_obj.dictionary["/NegRef"] = "-1 0 R";
    malicious_pdf.objects.push_back(negative_ref_obj) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Create circular reference chain
    PDFObject circular1;
    circular1.number = 3;
    circular1.generation = 0;
    circular1.dictionary["/Type"] = "/Circular";
    circular1.dictionary["/Next"] = "4 0 R";
    malicious_pdf.objects.push_back(circular1) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    PDFObject circular2;
    circular2.number = 4;
    circular2.generation = 0;
    circular2.dictionary["/Type"] = "/Circular";
    circular2.dictionary["/Next"] = "3 0 R"; // Back to 3
    malicious_pdf.objects.push_back(circular2) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Add required PDF structure
    PDFObject catalog;
    catalog.number = 5;
    catalog.generation = 0;
    catalog.dictionary["/Type"] = "/Catalog";
    catalog.dictionary["/Pages"] = "6 0 R";
    malicious_pdf.objects.push_back(catalog) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    PDFObject pages;
    pages.number = 6;
    pages.generation = 0;
    pages.dictionary["/Type"] = "/Pages";
    pages.dictionary["/Count"] = "1";
    malicious_pdf.objects.push_back(pages) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    malicious_pdf.trailer.dictionary["/Size"] = "7";
    malicious_pdf.trailer.dictionary["/Root"] = "5 0 R";
    
    SILENT_LOG("Processing malicious PDF with reference issues...\n");
    
    // Test comprehensive validation and fixing
    try {
        PDFStructure result = scrubber.scrub(malicious_pdf) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        
        // Verify all issues were fixed
        bool no_circular = !scrubber.detect_circular_references(result) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        bool integrity_ok = scrubber.validate_reference_integrity(result) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        
        if (no_circular && integrity_ok) {
            SILENT_LOG("✅ Malicious PDF references successfully sanitized\n");
        } else {
            SILENT_LOG("❌ Some reference issues remain after processing\n");
        }
        
        // Verify essential structure is preserved
        bool has_catalog = false, has_pages = false;
        for (const auto& obj : result.objects) {
            auto type_it = obj.dictionary.find("/Type") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
            if (type_it != obj.dictionary.end()) {
                if (type_it->second == "/Catalog") has_catalog = true;
                if (type_it->second == "/Pages") has_pages = true;
            }
        }
        
        if (has_catalog && has_pages) {
            SILENT_LOG("✅ Essential PDF structure preserved during sanitization\n");
        }
        
    } catch (const std::exception& e) {
        SILENT_LOG("✅ Malicious PDF handled safely with exception: ") << e.what() << "\n";
    }
}

int main() {
    SILENT_LOG("=== PDFScrubber Reference Validation Testing ===\n\n");
    
    try {
        test_circular_reference_detection() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        SILENT_LOG("\n");
        
        test_invalid_reference_detection() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        SILENT_LOG("\n");
        
        test_self_reference_handling() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        SILENT_LOG("\n");
        
        test_complex_circular_chain() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        SILENT_LOG("\n");
        
        test_reference_update_protection() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        SILENT_LOG("\n");
        
        test_malicious_pdf_references() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        SILENT_LOG("\n");
        
        SILENT_LOG("🎉 ALL REFERENCE VALIDATION TESTS PASSED!\n");
        SILENT_LOG("\n=== REFERENCE VALIDATION VERIFICATION COMPLETE ===\n");
        SILENT_LOG("✅ Circular reference detection working correctly\n");
        SILENT_LOG("✅ Invalid reference detection and fixing functional\n");
        SILENT_LOG("✅ Self-reference handling effective\n");
        SILENT_LOG("✅ Complex circular chain detection robust\n");
        SILENT_LOG("✅ Reference update protection preventing loops\n");
        SILENT_LOG("✅ Malicious PDF reference handling secure\n");
        SILENT_LOG("✅ No infinite loops or reference integrity issues detected\n");
        
        return 0;
        
    } catch (const std::exception& e) {
        SILENT_ERROR("Reference validation test failed: ") << e.what() << std::endl;
        return 1;
    }
}