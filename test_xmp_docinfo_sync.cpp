#include "secure_memory.hpp"
#include "secure_exceptions.hpp"
#include <iostream>
#include <vector>
#include <string>
#include "anti_fingerprint_engine.hpp"
#include "stealth_macros.hpp"

void test_xmp_docinfo_synchronization() {
    SILENT_LOG("Testing XMP-DocInfo Synchronization - Preventing Detection...\n");
    
    AntiFingerprintEngine engine;
    
    // Test 1: Mismatched XMP and DocInfo should be synchronized
    std::string test_pdf_mismatched = R"(
%PDF-1.4
4 0 obj
<< 
/Title (DocInfo Title Here)
/Author (DocInfo Author)
/Subject ()
/Creator (Original Creator Tool)
/Producer ()
/CreationDate (D:20220315100000+01'00')
/ModDate ()
>>
endobj
5 0 obj
<< /Type /Metadata /Subtype /XML /Length 800 >>
stream
<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="">
<dc:title><rdf:Alt><rdf:li xml:lang="x-default">Different XMP Title</rdf:li></rdf:Alt></dc:title>
<dc:creator><rdf:Seq><rdf:li>Different XMP Author</rdf:li></rdf:Seq></dc:creator>
<dc:description><rdf:Alt><rdf:li xml:lang="x-default">XMP Subject Text</rdf:li></rdf:Alt></dc:description>
<xmp:CreatorTool>Different XMP Creator</xmp:CreatorTool>
<pdf:Producer>XMP Producer Text</pdf:Producer>
<xmp:CreateDate>2023-01-01T12:00:00Z</xmp:CreateDate>
<xmp:ModifyDate>2023-06-15T14:30:00Z</xmp:ModifyDate>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>
endstream
endobj
)";
    
    std::vector<uint8_t> pdf_mismatched(test_pdf_mismatched.begin(), test_pdf_mismatched.end()) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Set authentic source metadata
    engine.clear_source_metadata() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("Title", "DocInfo Title Here") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("Author", "DocInfo Author") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("Subject", "") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("Creator", "Original Creator Tool") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("Producer", "") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("CreationDate", "D:20220315100000+01'00'") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("ModDate", "") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    std::vector<uint8_t> result_synced = engine.process(pdf_mismatched) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    std::string result_str_synced(result_synced.begin(), result_synced.end()) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Verify DocInfo values preserved
    if (!(result_str_synced.find("/Title (DocInfo Title Here)") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_synced.find("/Author (DocInfo Author)") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_synced.find("/Subject ()") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_synced.find("/Creator (Original Creator Tool)") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_synced.find("/Producer ()") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_synced.find("/CreationDate (D:20220315100000+01'00')") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_synced.find("/ModDate ()") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Verify XMP synchronized to match DocInfo
    if (!(result_str_synced.find("<dc:title><rdf:Alt><rdf:li xml:lang=\"x-default\">DocInfo Title Here</rdf:li></rdf:Alt></dc:title>") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_synced.find("<dc:creator><rdf:Seq><rdf:li>DocInfo Author</rdf:li></rdf:Seq></dc:creator>") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_synced.find("<dc:description><rdf:Alt><rdf:li xml:lang=\"x-default\"></rdf:li></rdf:Alt></dc:description>") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_synced.find("<xmp:CreatorTool>Original Creator Tool</xmp:CreatorTool>") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_synced.find("<pdf:Producer></pdf:Producer>") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_synced.find("<xmp:CreateDate>2022-03-15T10:00:00+01:00</xmp:CreateDate>") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_synced.find("<xmp:ModifyDate></xmp:ModifyDate>") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Verify mismatched values removed
    if (!(result_str_synced.find("Different XMP Title") == std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_synced.find("Different XMP Author") == std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_synced.find("XMP Subject Text") == std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_synced.find("Different XMP Creator") == std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_synced.find("XMP Producer Text") == std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_synced.find("2023-01-01T12:00:00Z") == std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_synced.find("2023-06-15T14:30:00Z") == std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    SILENT_LOG("✓ Test 1 PASSED: XMP synchronized to match DocInfo exactly\n");
    
    // Test 2: All blank fields should be synchronized as blank
    std::string test_pdf_all_blank = R"(
%PDF-1.4
4 0 obj
<< 
/Title ()
/Author ()
/Subject ()
/Creator ()
/Producer ()
/CreationDate ()
/ModDate ()
>>
endobj
5 0 obj
<< /Type /Metadata /Subtype /XML /Length 600 >>
stream
<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="">
<dc:title><rdf:Alt><rdf:li xml:lang="x-default">XMP Title Should Be Blank</rdf:li></rdf:Alt></dc:title>
<dc:creator><rdf:Seq><rdf:li>XMP Author Should Be Blank</rdf:li></rdf:Seq></dc:creator>
<xmp:CreatorTool>XMP Creator Should Be Blank</xmp:CreatorTool>
<pdf:Producer>XMP Producer Should Be Blank</pdf:Producer>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>
endstream
endobj
)";
    
    std::vector<uint8_t> pdf_all_blank(test_pdf_all_blank.begin(), test_pdf_all_blank.end()) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // All source fields are blank
    engine.clear_source_metadata() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("Title", "") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("Author", "") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("Subject", "") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("Creator", "") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("Producer", "") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("CreationDate", "") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("ModDate", "") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    std::vector<uint8_t> result_all_blank = engine.process(pdf_all_blank) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    std::string result_str_all_blank(result_all_blank.begin(), result_all_blank.end()) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Verify all DocInfo fields are blank
    if (!(result_str_all_blank.find("/Title ()") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_all_blank.find("/Author ()") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_all_blank.find("/Subject ()") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_all_blank.find("/Creator ()") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_all_blank.find("/Producer ()") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_all_blank.find("/CreationDate ()") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_all_blank.find("/ModDate ()") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Verify all XMP fields are blank too
    if (!(result_str_all_blank.find("<dc:title><rdf:Alt><rdf:li xml:lang=\"x-default\"></rdf:li></rdf:Alt></dc:title>") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_all_blank.find("<dc:creator><rdf:Seq><rdf:li></rdf:li></rdf:Seq></dc:creator>") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_all_blank.find("<xmp:CreatorTool></xmp:CreatorTool>") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_all_blank.find("<pdf:Producer></pdf:Producer>") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Verify no contaminated XMP values remain
    if (!(result_str_all_blank.find("XMP Title Should Be Blank") == std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_all_blank.find("XMP Author Should Be Blank") == std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_all_blank.find("XMP Creator Should Be Blank") == std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_all_blank.find("XMP Producer Should Be Blank") == std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    SILENT_LOG("✓ Test 2 PASSED: All blank fields synchronized consistently\n");
    
    // Test 3: Mixed blank and valued fields
    std::string test_pdf_mixed_sync = R"(
%PDF-1.4
4 0 obj
<< 
/Title (Authentic Document Title)
/Author ()
/Subject (Real Subject Matter)
/Creator ()
/Producer (Genuine Producer Name)
/CreationDate (D:20210910143000+02'00')
/ModDate ()
>>
endobj
5 0 obj
<< /Type /Metadata /Subtype /XML /Length 700 >>
stream
<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="">
<dc:title><rdf:Alt><rdf:li xml:lang="x-default">Wrong XMP Title</rdf:li></rdf:Alt></dc:title>
<dc:creator><rdf:Seq><rdf:li>Wrong XMP Author</rdf:li></rdf:Seq></dc:creator>
<dc:description><rdf:Alt><rdf:li xml:lang="x-default">Wrong XMP Subject</rdf:li></rdf:Alt></dc:description>
<xmp:CreatorTool>Wrong XMP Creator</xmp:CreatorTool>
<pdf:Producer>Wrong XMP Producer</pdf:Producer>
<xmp:CreateDate>2023-12-25T10:00:00Z</xmp:CreateDate>
<xmp:ModifyDate>2024-01-15T15:45:00Z</xmp:ModifyDate>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>
endstream
endobj
)";
    
    std::vector<uint8_t> pdf_mixed_sync(test_pdf_mixed_sync.begin(), test_pdf_mixed_sync.end()) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Set source metadata matching DocInfo
    engine.clear_source_metadata() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("Title", "Authentic Document Title") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("Author", "") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("Subject", "Real Subject Matter") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("Creator", "") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("Producer", "Genuine Producer Name") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("CreationDate", "D:20210910143000+02'00'") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("ModDate", "") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    std::vector<uint8_t> result_mixed_sync = engine.process(pdf_mixed_sync) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    std::string result_str_mixed_sync(result_mixed_sync.begin(), result_mixed_sync.end()) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Verify DocInfo preserved correctly
    if (!(result_str_mixed_sync.find("/Title (Authentic Document Title)") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_mixed_sync.find("/Author ()") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_mixed_sync.find("/Subject (Real Subject Matter)") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_mixed_sync.find("/Creator ()") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_mixed_sync.find("/Producer (Genuine Producer Name)") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_mixed_sync.find("/CreationDate (D:20210910143000+02'00')") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_mixed_sync.find("/ModDate ()") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Verify XMP matches DocInfo exactly
    if (!(result_str_mixed_sync.find("<dc:title><rdf:Alt><rdf:li xml:lang=\"x-default\">Authentic Document Title</rdf:li></rdf:Alt></dc:title>") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_mixed_sync.find("<dc:creator><rdf:Seq><rdf:li></rdf:li></rdf:Seq></dc:creator>") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_mixed_sync.find("<dc:description><rdf:Alt><rdf:li xml:lang=\"x-default\">Real Subject Matter</rdf:li></rdf:Alt></dc:description>") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_mixed_sync.find("<xmp:CreatorTool></xmp:CreatorTool>") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_mixed_sync.find("<pdf:Producer>Genuine Producer Name</pdf:Producer>") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_mixed_sync.find("<xmp:CreateDate>2021-09-10T14:30:00+02:00</xmp:CreateDate>") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_mixed_sync.find("<xmp:ModifyDate></xmp:ModifyDate>") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Verify wrong XMP values removed
    if (!(result_str_mixed_sync.find("Wrong XMP") == std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_mixed_sync.find("2023-12-25") == std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_mixed_sync.find("2024-01-15") == std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    SILENT_LOG("✓ Test 3 PASSED: Mixed fields synchronized perfectly\n");
    
    // Test 4: Date format conversion verification
    std::string test_pdf_date_conversion = R"(
%PDF-1.4
4 0 obj
<< 
/CreationDate (D:20200425123045+05'30')
/ModDate (D:20201201165500-08'00')
>>
endobj
5 0 obj
<< /Type /Metadata /Subtype /XML /Length 400 >>
stream
<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="">
<xmp:CreateDate>2019-01-01T00:00:00Z</xmp:CreateDate>
<xmp:ModifyDate>2019-12-31T23:59:59Z</xmp:ModifyDate>
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>
endstream
endobj
)";
    
    std::vector<uint8_t> pdf_date_conversion(test_pdf_date_conversion.begin(), test_pdf_date_conversion.end()) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Set source dates
    engine.clear_source_metadata() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("CreationDate", "D:20200425123045+05'30'") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    engine.set_source_metadata("ModDate", "D:20201201165500-08'00'") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    std::vector<uint8_t> result_date_conversion = engine.process(pdf_date_conversion) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    std::string result_str_date_conversion(result_date_conversion.begin(), result_date_conversion.end()) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Verify proper date format conversion
    if (!(result_str_date_conversion.find("<xmp:CreateDate>2020-04-25T12:30:45+05:30</xmp:CreateDate>") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_date_conversion.find("<xmp:ModifyDate>2020-12-01T16:55:00-08:00</xmp:ModifyDate>") != std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Verify old dates removed
    if (!(result_str_date_conversion.find("2019-01-01") == std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    if (!(result_str_date_conversion.find("2019-12-31") == std::string::npos) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    SILENT_LOG("✓ Test 4 PASSED: Date format conversion works correctly\n");
    
    SILENT_LOG("\n===========================================\n");
    SILENT_LOG("XMP-DOCINFO SYNCHRONIZATION VALIDATION COMPLETE\n");
    SILENT_LOG("===========================================\n");
    SILENT_LOG("✓ XMP metadata synchronized to match DocInfo exactly\n");
    SILENT_LOG("✓ Blank fields synchronized consistently\n");
    SILENT_LOG("✓ Mixed valued/blank fields handled correctly\n");
    SILENT_LOG("✓ Date format conversion accurate\n");
    SILENT_LOG("✓ No data inconsistencies remain\n");
    SILENT_LOG("✓ Tampering detection prevention achieved\n");
}

int main() {
    try {
        test_xmp_docinfo_synchronization() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        SILENT_LOG("\nAll tests PASSED! XMP-DocInfo synchronization prevents detection.\n");
        return 0;
    } catch (const std::exception& e) {
        SILENT_ERROR("Test FAILED: ") << e.what() << std::endl;
        return 1;
    }
}