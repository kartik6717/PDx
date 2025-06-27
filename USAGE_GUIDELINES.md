# PDF Scrubber Usage Guidelines

## Quick Start Guide

### Basic Document Sanitization
For general document cleaning with standard security measures:

```cpp
#include "scrubber.hpp"

// Create scrubber instance
PDFScrubber scrubber;

// Set standard intensity level
scrubber.set_intensity_level(PDFScrubber::IntensityLevel::STANDARD);

// Load and scrub PDF
PDFStructure cleaned_pdf = scrubber.scrub(original_pdf);
```

### High-Security Scenarios
For sensitive documents requiring maximum protection:

```cpp
PDFScrubber scrubber;

// Maximum security configuration
scrubber.set_intensity_level(PDFScrubber::IntensityLevel::MAXIMUM);
scrubber.set_scrubbing_profile(PDFScrubber::ScrubbingProfile::FORENSIC_EVASION);

// Enable all advanced features
scrubber.enable_parallel_processing_ = true;

// Scrub with maximum protection
PDFStructure secured_pdf = scrubber.scrub(sensitive_pdf);
```

## Scenario-Specific Guidelines

### 1. Legal Document Processing
**Use Case**: Law firms, legal departments, court filings

**Configuration**:
```cpp
PDFScrubber scrubber;
scrubber.set_scrubbing_profile(PDFScrubber::ScrubbingProfile::COMPLIANCE);

// Preserve case title but remove author information
scrubber.add_to_whitelist("/Title");
scrubber.add_to_whitelist("/Subject");
scrubber.add_to_blacklist("/Author");
scrubber.add_to_blacklist("/Producer");
```

**Rationale**:
- Maintains document identification for legal proceedings
- Removes personal information that could compromise attorney-client privilege
- Complies with court document anonymization requirements

### 2. Medical Records Sanitization
**Use Case**: HIPAA compliance, medical research, patient privacy

**Configuration**:
```cpp
PDFScrubber scrubber;
scrubber.set_intensity_level(PDFScrubber::IntensityLevel::AGGRESSIVE);
scrubber.set_scrubbing_profile(PDFScrubber::ScrubbingProfile::ANONYMIZER);

// Remove all identifying information
scrubber.add_to_blacklist("/Author");
scrubber.add_to_blacklist("/Creator");
scrubber.add_to_blacklist("/Producer");
scrubber.add_to_blacklist("/Keywords");

// Enable advanced anti-forensic features
scrubber.enable_parallel_processing_ = true;
```

**Rationale**:
- Ensures HIPAA compliance by removing all potentially identifying metadata
- Prevents reconstruction of document creation timeline
- Maintains document integrity for medical review

### 3. Financial Document Processing
**Use Case**: Banking, financial services, regulatory compliance

**Configuration**:
```cpp
PDFScrubber scrubber;
scrubber.set_scrubbing_profile(PDFScrubber::ScrubbingProfile::COMPLIANCE);

// Preserve document type but remove creation details
scrubber.add_to_whitelist("/Title");
scrubber.add_to_blacklist("/Author");
scrubber.add_to_blacklist("/CreationDate");
scrubber.add_to_blacklist("/ModDate");

// Ensure temporal artifacts are removed
scrubber.set_intensity_level(PDFScrubber::IntensityLevel::AGGRESSIVE);
```

**Rationale**:
- Maintains document classification for regulatory purposes
- Removes timing information that could reveal trading patterns
- Protects internal workflow information

### 4. Whistleblower Protection
**Use Case**: Anonymous document submission, investigative journalism

**Configuration**:
```cpp
PDFScrubber scrubber;
scrubber.set_intensity_level(PDFScrubber::IntensityLevel::MAXIMUM);
scrubber.set_scrubbing_profile(PDFScrubber::ScrubbingProfile::FORENSIC_EVASION);

// Remove ALL metadata
scrubber.clear_whitelist(); // Ensure nothing is preserved

// Enable maximum protection features
scrubber.enable_parallel_processing_ = true;
scrubber.enable_incremental_scrubbing_ = true;
```

**Rationale**:
- Maximum protection against forensic analysis
- Prevents source identification through document fingerprinting
- Eliminates all potential tracking information

### 5. Academic Research
**Use Case**: Research publications, peer review, data sharing

**Configuration**:
```cpp
PDFScrubber scrubber;
scrubber.set_scrubbing_profile(PDFScrubber::ScrubbingProfile::ANONYMIZER);

// Preserve research metadata but remove personal info
scrubber.add_to_whitelist("/Title");
scrubber.add_to_whitelist("/Subject");
scrubber.add_to_whitelist("/Keywords");
scrubber.add_to_blacklist("/Author");
scrubber.add_to_blacklist("/Creator");
```

**Rationale**:
- Maintains research classification and keywords for indexing
- Removes author identification for double-blind review
- Preserves academic integrity while ensuring anonymity

### 6. Corporate Document Sharing
**Use Case**: Business partnerships, vendor relationships, M&A

**Configuration**:
```cpp
PDFScrubber scrubber;
scrubber.set_intensity_level(PDFScrubber::IntensityLevel::STANDARD);

// Remove creation details but preserve document info
scrubber.add_to_whitelist("/Title");
scrubber.add_to_blacklist("/Author");
scrubber.add_to_blacklist("/Producer");
scrubber.add_to_blacklist("/CreationDate");
```

**Rationale**:
- Protects internal processes and employee information
- Maintains document identification for business purposes
- Prevents reverse-engineering of internal workflows

## Performance Optimization Guidelines

### Large Document Processing
For PDFs > 10MB or > 1000 objects:

```cpp
PDFScrubber scrubber;

// Enable performance optimizations
scrubber.enable_parallel_processing_ = true;
scrubber.enable_incremental_scrubbing_ = true;

// Use standard intensity to balance speed and security
scrubber.set_intensity_level(PDFScrubber::IntensityLevel::STANDARD);
```

### Batch Processing
For processing multiple documents:

```cpp
std::vector<PDFStructure> process_batch(const std::vector<PDFStructure>& pdfs) {
    PDFScrubber scrubber;
    scrubber.enable_parallel_processing_ = true;
    
    std::vector<PDFStructure> results;
    for (const auto& pdf : pdfs) {
        results.push_back(scrubber.scrub(pdf));
    }
    return results;
}
```

### Real-Time Processing
For streaming or real-time applications:

```cpp
PDFScrubber scrubber;
scrubber.set_intensity_level(PDFScrubber::IntensityLevel::BASIC);
scrubber.enable_incremental_scrubbing_ = true;

// Process documents as they arrive
PDFStructure process_realtime(const PDFStructure& pdf) {
    return scrubber.scrub(pdf);
}
```

## Security Best Practices

### 1. Validation Chain
Always implement comprehensive validation:

```cpp
PDFScrubber scrubber;

// Enable pre and post validation
if (!scrubber.pre_scrubbing_validation(input_pdf)) {
    throw std::runtime_error("Input PDF validation failed");
}

PDFStructure result = scrubber.scrub(input_pdf);

if (!scrubber.post_scrubbing_integrity_check(result)) {
    throw std::runtime_error("Output PDF integrity compromised");
}
```

### 2. Rollback Protection
Implement proper error handling:

```cpp
try {
    PDFStructure result = scrubber.scrub(input_pdf);
    return result;
} catch (const std::exception& e) {
    // Automatic rollback is handled internally
    std::cerr << "Scrubbing failed: " << e.what() << std::endl;
    return input_pdf; // Return original on failure
}
```

### 3. Configuration Validation
Verify scrubbing configuration before processing:

```cpp
void validate_configuration(const PDFScrubber& scrubber) {
    // Ensure appropriate intensity for use case
    if (high_security_required && 
        scrubber.intensity_level_ < PDFScrubber::IntensityLevel::AGGRESSIVE) {
        throw std::runtime_error("Insufficient security level");
    }
}
```

## Common Pitfalls and Solutions

### Problem: Visual Content Corruption
**Symptom**: Scrubbed PDFs have rendering issues
**Solution**: Enable visual content preservation
```cpp
scrubber.preserve_visual_content_ = true;
```

### Problem: Over-Aggressive Scrubbing
**Symptom**: Essential document information removed
**Solution**: Use whitelist to protect required metadata
```cpp
scrubber.add_to_whitelist("/Title");
scrubber.add_to_whitelist("/Subject");
```

### Problem: Performance Issues
**Symptom**: Slow processing of large documents
**Solution**: Enable performance optimizations
```cpp
scrubber.enable_parallel_processing_ = true;
scrubber.set_intensity_level(PDFScrubber::IntensityLevel::STANDARD);
```

### Problem: Incomplete Metadata Removal
**Symptom**: Sensitive information still present after scrubbing
**Solution**: Use maximum intensity with forensic evasion profile
```cpp
scrubber.set_intensity_level(PDFScrubber::IntensityLevel::MAXIMUM);
scrubber.set_scrubbing_profile(PDFScrubber::ScrubbingProfile::FORENSIC_EVASION);
```

## Compliance Guidelines

### GDPR Compliance (EU)
- Use ANONYMIZER profile for personal data removal
- Document processing decisions for audit trails
- Implement data subject access controls

### HIPAA Compliance (US Healthcare)
- Use MAXIMUM intensity for medical records
- Remove all temporal artifacts
- Implement secure deletion of original files

### SOX Compliance (US Financial)
- Use COMPLIANCE profile for financial documents
- Preserve audit-required metadata in whitelist
- Maintain processing logs for regulatory review

### Classification Handling (Government)
- Use FORENSIC_EVASION for classified materials
- Implement multi-pass scrubbing for high classifications
- Follow agency-specific guidelines for metadata retention

## Testing and Verification

### Automated Verification
```cpp
void verify_scrubbing_effectiveness(const PDFStructure& original, 
                                   const PDFStructure& scrubbed) {
    // Verify sensitive data removal
    assert(scrubbed.producer_info.empty());
    assert(scrubbed.javascript_actions.empty());
    
    // Verify structural integrity
    assert(!scrubbed.objects.empty());
    assert(!scrubbed.trailer.dictionary.empty());
}
```

### Manual Verification Steps
1. **Metadata Inspection**: Use PDF analysis tools to verify metadata removal
2. **Forensic Tool Testing**: Run against common forensic analysis software
3. **Visual Verification**: Ensure document rendering remains intact
4. **Compliance Check**: Verify adherence to relevant regulations

This comprehensive guide covers all major use cases and scenarios for the PDFScrubber module.