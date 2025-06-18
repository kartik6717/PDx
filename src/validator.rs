use crate::types::*;
use std::fs::File;
use memmap2::Mmap;
use regex::Regex;

/// Validate PDF file structure and forensic integrity
pub fn validate_pdf_file(pdf_path: &str) -> PdfResult<ValidationResult> {
    let start_time = std::time::Instant::now();

    let file = File::open(pdf_path).map_err(|e| PdfError::FileSystem {
        path: pdf_path.to_string(),
        operation: "open".to_string(),
        error_kind: match e.kind() {
            std::io::ErrorKind::NotFound => FileErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied => FileErrorKind::PermissionDenied,
            _ => FileErrorKind::ReadOnly,
        },
    })?;

    let mmap = unsafe { Mmap::map(&file) }.map_err(|e| PdfError::Memory {
        message: format!("Failed to memory map file: {}", e),
        requested_bytes: file.metadata().unwrap().len(),
        available_bytes: 0,
    })?;

    let mut result = ValidationResult {
        is_valid: true,
        errors: Vec::new(),
        warnings: Vec::new(),
        forensic_match: Some(ForensicMatch {
            matches: true,
            confidence: 0.95,
            matching_elements: vec!["Complete validation match".to_string()],
            non_matching_elements: vec![],
            details: ForensicMatchDetails {
                id_match: true,
                timestamp_match: true,
                metadata_match: true,
                structure_match: true,
                encryption_match: true,
                permission_match: true,
            },
        }),
        validation_stats: ValidationStatistics {
            objects_validated: 0,
            streams_validated: 0,
            references_validated: 0,
            validation_time_ms: 0,
        },
    };

    // Phase 1: Basic PDF structure validation
    validate_pdf_header(&mmap, &mut result)?;
    validate_pdf_trailer(&mmap, &mut result)?;
    validate_xref_structure(&mmap, &mut result)?;

    // Phase 2: Content structure validation
    validate_object_structure(&mmap, &mut result)?;
    validate_page_structure(&mmap, &mut result)?;

    // Phase 3: Security and integrity validation
    validate_encryption_integrity(&mmap, &mut result)?;
    validate_signature_integrity(&mmap, &mut result)?;

    // Phase 4: Forensic marker detection
    detect_forensic_markers(&mmap, &mut result)?;
    detect_third_party_modifications(&mmap, &mut result)?;

    // Determine overall validation status
    determine_validation_status(&mut result);

    let elapsed = start_time.elapsed();
    result.validation_stats.validation_time_ms = elapsed.as_millis() as u64;

    log::info!("PDF validation completed in {}ms with {} errors and {} warnings", 
               elapsed.as_millis(), result.errors.len(), result.warnings.len());

    Ok(result)
}

/// Validate PDF header structure
fn validate_pdf_header(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    if data.len() < 8 {
        result.errors.push(ValidationError {
            code: "HEADER_TOO_SHORT".to_string(),
            message: "File too small to contain valid PDF header".to_string(),
            severity: ErrorSeverity::Critical,
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            suggested_fix: Some("File may be corrupted or not a valid PDF".to_string()),
        });
        return validate_header_binary_content(data, result);
    }

    let header = &data[0..8];
    let header_str = match std::str::from_utf8(header) {
        Ok(s) => s,
        Err(_) => {
            result.errors.push(ValidationError {
                code: "HEADER_INVALID_UTF8".to_string(),
                message: "PDF header contains invalid UTF-8 characters".to_string(),
                severity: ErrorSeverity::Critical,
                location: Some(ErrorLocation::FileStructure { offset: 0 }),
                suggested_fix: Some("File may be corrupted".to_string()),
            });
            return validate_header_binary_content(data, result);
        }
    };

    if !header_str.starts_with("%PDF-") {
        result.errors.push(ValidationError {
            code: "HEADER_INVALID".to_string(),
            message: format!("Invalid PDF header: {}", header_str),
            severity: ErrorSeverity::Critical,
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            suggested_fix: Some("File is not a valid PDF document".to_string()),
        });
        return validate_header_recovery_attempt(data, result);
    }

    // Extract and validate PDF version
    if let Some(version_str) = header_str.strip_prefix("%PDF-") {
        if parse_pdf_version(version_str).is_err() {
            result.errors.push(ValidationError {
                code: "VERSION_INVALID".to_string(),
                message: format!("Invalid PDF version format: {}", version_str),
                severity: ErrorSeverity::Major,
                location: Some(ErrorLocation::FileStructure { offset: 5 }),
                suggested_fix: Some("Version should be in format X.Y".to_string()),
            });
        } else {
            // Version is valid, check for compatibility issues
            validate_version_compatibility(version_str, result)?;
        }
    }

    // Check for binary marker after header
    validate_binary_marker(data, result)?;

    log::debug!("PDF header validation completed successfully");
    Ok(())
}

/// Validate header binary content when UTF-8 fails
fn validate_header_binary_content(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    if data.len() >= 4 && data[0..4] == [0x25, 0x50, 0x44, 0x46] { // %PDF in hex
        result.warnings.push(ValidationWarning {
            code: "HEADER_BINARY_DETECTED".to_string(),
            message: "PDF header detected in binary format but not UTF-8 compliant".to_string(),
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            recommendation: Some("File may have encoding issues but appears to be PDF".to_string()),
        });
    }
    Ok(())
}

/// Attempt header recovery
fn validate_header_recovery_attempt(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    // Search for PDF header in first 1024 bytes
    let search_limit = std::cmp::min(1024, data.len());
    let search_area = &data[0..search_limit];

    if let Ok(content) = std::str::from_utf8(search_area) {
        if let Some(pdf_pos) = content.find("%PDF-") {
            result.warnings.push(ValidationWarning {
                code: "HEADER_OFFSET_FOUND".to_string(),
                message: format!("PDF header found at offset {} instead of 0", pdf_pos),
                location: Some(ErrorLocation::FileStructure { offset: pdf_pos as u64 }),
                recommendation: Some("File may have been modified or has leading content".to_string()),
            });
        }
    }
    Ok(())
}

/// Validate PDF version compatibility
fn validate_version_compatibility(version_str: &str, result: &mut ValidationResult) -> PdfResult<()> {
    let parts: Vec<&str> = version_str.trim().split('.').collect();
    if parts.len() == 2 {
        if let (Ok(major), Ok(minor)) = (parts[0].parse::<u8>(), parts[1].parse::<u8>()) {
            if major > 2 {
                result.warnings.push(ValidationWarning {
                    code: "VERSION_FUTURE".to_string(),
                    message: format!("PDF version {}.{} is newer than standard", major, minor),
                    location: Some(ErrorLocation::FileStructure { offset: 5 }),
                    recommendation: Some("Future PDF versions may not be fully supported".to_string()),
                });
            } else if major == 1 && minor < 2 {
                result.warnings.push(ValidationWarning {
                    code: "VERSION_DEPRECATED".to_string(),
                    message: format!("PDF version {}.{} is deprecated", major, minor),
                    location: Some(ErrorLocation::FileStructure { offset: 5 }),
                    recommendation: Some("Consider upgrading to newer PDF version".to_string()),
                });
            }
        }
    }
    Ok(())
}

/// Validate binary marker after header
fn validate_binary_marker(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    // Look for binary comment marker in first few lines
    let search_limit = std::cmp::min(256, data.len());

    if let Ok(content) = std::str::from_utf8(&data[0..search_limit]) {
        let lines: Vec<&str> = content.lines().take(4).collect();
        let mut found_binary_marker = false;

        for (i, line) in lines.iter().enumerate() {
            if i > 0 && line.starts_with('%') && line.len() > 4 {
                // Check if line contains high-bit characters indicating binary content
                if line.bytes().any(|b| b > 127) {
                    found_binary_marker = true;
                    break;
                }
            }
        }

        if !found_binary_marker && data.len() > 1024 {
            result.warnings.push(ValidationWarning {
                code: "BINARY_MARKER_MISSING".to_string(),
                message: "PDF lacks binary content marker - may indicate text-only PDF".to_string(),
                location: Some(ErrorLocation::FileStructure { offset: 0 }),
                recommendation: Some("Binary marker helps PDF readers handle mixed content".to_string()),
            });
        }
    }
    Ok(())
}

/// Validate PDF trailer structure
fn validate_pdf_trailer(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    let search_start = if data.len() > 1024 { data.len() - 1024 } else { 0 };
    let search_area = &data[search_start..];

    let content = match std::str::from_utf8(search_area) {
        Ok(s) => s,
        Err(_) => {
            result.errors.push(ValidationError {
                code: "TRAILER_INVALID_UTF8".to_string(),
                message: "Trailer area contains invalid UTF-8 characters".to_string(),
                severity: ErrorSeverity::Major,
                location: Some(ErrorLocation::FileStructure { offset: search_start as u64 }),
                suggested_fix: Some("File may be corrupted near end".to_string()),
            });
            return validate_trailer_binary_recovery(data, search_start, result);
        }
    };

    // Check for startxref
    if !content.contains("startxref") {
        result.errors.push(ValidationError {
            code: "STARTXREF_MISSING".to_string(),
            message: "startxref keyword not found".to_string(),
            severity: ErrorSeverity::Critical,
            location: Some(ErrorLocation::Trailer),
            suggested_fix: Some("PDF trailer is missing or corrupted".to_string()),
        });
        return validate_trailer_structure_recovery(data, result);
    }

    // Validate startxref value
    validate_startxref_value(content, result, search_start as u64)?;

    // Check for %%EOF
    if !content.contains("%%EOF") {
        result.warnings.push(ValidationWarning {
            code: "EOF_MISSING".to_string(),
            message: "%%EOF marker not found".to_string(),
            location: Some(ErrorLocation::Trailer),
            recommendation: Some("PDF end marker missing - file may be truncated".to_string()),
        });
    } else {
        validate_eof_position(content, result, search_start as u64)?;
    }

    // Validate trailer dictionary
    if let Some(trailer_pos) = content.find("trailer") {
        validate_trailer_dictionary(&content[trailer_pos..], result, search_start as u64 + trailer_pos as u64)?;
    } else {
        result.errors.push(ValidationError {
            code: "TRAILER_DICT_MISSING".to_string(),
            message: "trailer keyword not found".to_string(),
            severity: ErrorSeverity::Critical,
            location: Some(ErrorLocation::Trailer),
            suggested_fix: Some("PDF trailer dictionary is missing".to_string()),
        });
        return validate_implicit_trailer_search(content, result, search_start as u64);
    }

    log::debug!("PDF trailer validation completed");
    Ok(())
}

/// Validate trailer binary recovery
fn validate_trailer_binary_recovery(data: &[u8], search_start: usize, result: &mut ValidationResult) -> PdfResult<()> {
    // Search for %%EOF in binary data
    let eof_marker = b"%%EOF";
    if let Some(_) = data[search_start..].windows(eof_marker.len()).position(|window| window == eof_marker) {
        result.warnings.push(ValidationWarning {
            code: "EOF_BINARY_FOUND".to_string(),
            message: "EOF marker found in binary data despite UTF-8 issues".to_string(),
            location: Some(ErrorLocation::Trailer),
            recommendation: Some("File has encoding issues but structure may be intact".to_string()),
        });
    }
    Ok(())
}

/// Validate trailer structure recovery
fn validate_trailer_structure_recovery(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    // Search entire file for any xref references
    if let Ok(full_content) = std::str::from_utf8(data) {
        let xref_count = full_content.matches("xref").count();
        if xref_count > 0 {
            result.warnings.push(ValidationWarning {
                code: "XREF_FOUND_NO_STARTXREF".to_string(),
                message: format!("Found {} xref tables but no startxref pointer", xref_count),
                location: Some(ErrorLocation::Trailer),
                recommendation: Some("File may have structural damage but contains xref data".to_string()),
            });
        }
    }
    Ok(())
}

/// Validate startxref value
fn validate_startxref_value(content: &str, result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    if let Some(startxref_pos) = content.rfind("startxref") {
        let after_startxref = &content[startxref_pos + "startxref".len()..];
        if let Some(value_line) = after_startxref.lines().next() {
            let value = value_line.trim();
            if let Ok(xref_offset) = value.parse::<u64>() {
                if xref_offset == 0 {
                    result.warnings.push(ValidationWarning {
                        code: "STARTXREF_ZERO".to_string(),
                        message: "startxref points to offset 0".to_string(),
                        location: Some(ErrorLocation::Trailer),
                        recommendation: Some("Zero offset may indicate structural issues".to_string()),
                    });
                }
            } else {
                result.errors.push(ValidationError {
                    code: "STARTXREF_INVALID_VALUE".to_string(),
                    message: format!("startxref value is not numeric: {}", value),
                    severity: ErrorSeverity::Critical,
                    location: Some(ErrorLocation::FileStructure { offset }),
                    suggested_fix: Some("startxref must contain valid numeric offset".to_string()),
                });
            }
        }
    }
    Ok(())
}

/// Validate EOF position
fn validate_eof_position(content: &str, result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    if let Some(eof_pos) = content.rfind("%%EOF") {
        let after_eof = &content[eof_pos + 5..];
        if after_eof.trim().len() > 0 {
            result.warnings.push(ValidationWarning {
                code: "CONTENT_AFTER_EOF".to_string(),
                message: "Content found after %%EOF marker".to_string(),
                location: Some(ErrorLocation::FileStructure { offset: offset + eof_pos as u64 + 5 }),
                recommendation: Some("Content after EOF may indicate file append operations".to_string()),
            });
        }
    }
    Ok(())
}

/// Validate implicit trailer search
fn validate_implicit_trailer_search(content: &str, result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    // Search for dictionary patterns that might be trailers
    if content.contains("<<") && content.contains("/Size") && content.contains("/Root") {
        result.warnings.push(ValidationWarning {
            code: "IMPLICIT_TRAILER_FOUND".to_string(),
            message: "Found trailer-like dictionary without 'trailer' keyword".to_string(),
            location: Some(ErrorLocation::FileStructure { offset }),
            recommendation: Some("File may have non-standard trailer format".to_string()),
        });
    }
    Ok(())
}

/// Validate trailer dictionary structure
fn validate_trailer_dictionary(trailer_content: &str, result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    if let Some(dict_start) = trailer_content.find("<<") {
        if let Some(dict_end) = trailer_content[dict_start..].find(">>") {
            let dict_content = &trailer_content[dict_start+2..dict_start+dict_end];

            // Check required trailer fields
            validate_trailer_size_field(dict_content, result, offset)?;
            validate_trailer_root_field(dict_content, result, offset)?;
            validate_trailer_optional_fields(dict_content, result, offset)?;

        } else {
            result.errors.push(ValidationError {
                code: "TRAILER_DICT_UNCLOSED".to_string(),
                message: "Trailer dictionary not properly closed".to_string(),
                severity: ErrorSeverity::Critical,
                location: Some(ErrorLocation::FileStructure { offset }),
                suggested_fix: Some("Dictionary must end with >>".to_string()),
            });
        }
    } else {
        result.errors.push(ValidationError {
            code: "TRAILER_DICT_NOT_FOUND".to_string(),
            message: "Trailer dictionary not found".to_string(),
            severity: ErrorSeverity::Critical,
            location: Some(ErrorLocation::FileStructure { offset }),
            suggested_fix: Some("trailer keyword must be followed by dictionary".to_string()),
        });
    }

    Ok(())
}

/// Validate trailer size field
fn validate_trailer_size_field(dict_content: &str, result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    if !dict_content.contains("/Size") {
        result.errors.push(ValidationError {
            code: "TRAILER_SIZE_MISSING".to_string(),
            message: "Trailer missing required /Size field".to_string(),
            severity: ErrorSeverity::Critical,
            location: Some(ErrorLocation::FileStructure { offset }),
            suggested_fix: Some("Trailer dictionary must contain /Size".to_string()),
        });
    } else {
        // Extract and validate size value
        if let Some(size_pos) = dict_content.find("/Size") {
            let after_size = &dict_content[size_pos + 5..];
            if let Some(size_value) = extract_numeric_value(after_size) {
                if size_value == 0 {
                    result.errors.push(ValidationError {
                        code: "TRAILER_SIZE_ZERO".to_string(),
                        message: "Trailer /Size field is zero".to_string(),
                        severity: ErrorSeverity::Major,
                        location: Some(ErrorLocation::FileStructure { offset }),
                        suggested_fix: Some("Size must indicate number of objects in xref table".to_string()),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Validate trailer root field
fn validate_trailer_root_field(dict_content: &str, result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    if !dict_content.contains("/Root") {
        result.errors.push(ValidationError {
            code: "TRAILER_ROOT_MISSING".to_string(),
            message: "Trailer missing required /Root field".to_string(),
            severity: ErrorSeverity::Critical,
            location: Some(ErrorLocation::FileStructure { offset }),
            suggested_fix: Some("Trailer dictionary must contain /Root".to_string()),
        });
    } else {
        // Validate root reference format
        if let Some(root_pos) = dict_content.find("/Root") {
            let after_root = &dict_content[root_pos + 5..];
            if !after_root.trim_start().contains(" R") {
                result.warnings.push(ValidationWarning {
                    code: "ROOT_NOT_REFERENCE".to_string(),
                    message: "/Root field does not appear to be an object reference".to_string(),
                    location: Some(ErrorLocation::FileStructure { offset }),
                    recommendation: Some("/Root should reference the document catalog object".to_string()),
                });
            }
        }
    }
    Ok(())
}

/// Validate trailer optional fields
fn validate_trailer_optional_fields(dict_content: &str, result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    // Check for PDF ID array
    if dict_content.contains("/ID") {
        validate_pdf_id_array(dict_content, result, offset)?;
    } else {
        result.warnings.push(ValidationWarning {
            code: "PDF_ID_MISSING".to_string(),
            message: "PDF ID array not present in trailer".to_string(),
            location: Some(ErrorLocation::FileStructure { offset }),
            recommendation: Some("Consider adding PDF ID for better document tracking".to_string()),
        });
    }

    // Check for Info dictionary
    if dict_content.contains("/Info") {
        result.warnings.push(ValidationWarning {
            code: "INFO_DICT_FOUND".to_string(),
            message: "Document contains Info dictionary with metadata".to_string(),
            location: Some(ErrorLocation::Metadata { field: "info".to_string() }),
            recommendation: Some("Info dictionary may contain forensically relevant metadata".to_string()),
        });
    }

    // Check for encryption reference
    if dict_content.contains("/Encrypt") {
        result.warnings.push(ValidationWarning {
            code: "ENCRYPTION_REFERENCE_FOUND".to_string(),
            message: "Trailer references encryption dictionary".to_string(),
            location: Some(ErrorLocation::Security),
            recommendation: Some("Document encryption will affect validation completeness".to_string()),
        });
    }

    Ok(())
}

/// Extract numeric value from PDF content
fn extract_numeric_value(content: &str) -> Option<u64> {
    let trimmed = content.trim_start();
    let mut end_pos = 0;

    for ch in trimmed.chars() {
        if ch.is_ascii_digit() {
            end_pos += ch.len_utf8();
        } else {
            break;
        }
    }

    if end_pos > 0 {
        trimmed[..end_pos].parse().ok()
    } else {
        None
    }
}

/// Validate PDF ID array format
fn validate_pdf_id_array(dict_content: &str, result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    if let Some(id_pos) = dict_content.find("/ID") {
        let after_id = &dict_content[id_pos + 3..];
        if let Some(array_start) = after_id.find('[') {
            if let Some(array_end) = after_id[array_start..].find(']') {
                let array_content = &after_id[array_start+1..array_start+array_end];

                // Count hex strings in array
                let hex_string_count = array_content.matches('<').count();
                if hex_string_count != 2 {
                    result.errors.push(ValidationError {
                        code: "PDF_ID_INVALID_COUNT".to_string(),
                        message: format!("PDF ID array should contain 2 hex strings, found {}", hex_string_count),
                        severity: ErrorSeverity::Major,
                        location: Some(ErrorLocation::FileStructure { offset }),
                        suggested_fix: Some("PDF ID array must contain exactly 2 hex string elements".to_string()),
                    });
                } else {
                    validate_hex_string_elements(array_content, result, offset)?;
                }

            } else {
                result.errors.push(ValidationError {
                    code: "PDF_ID_ARRAY_UNCLOSED".to_string(),
                    message: "PDF ID array not properly closed".to_string(),
                    severity: ErrorSeverity::Major,
                    location: Some(ErrorLocation::FileStructure { offset }),
                    suggested_fix: Some("Array must end with ]".to_string()),
                });
            }
        } else {
            result.errors.push(ValidationError {
                code: "PDF_ID_NOT_ARRAY".to_string(),
                message: "PDF ID not followed by array".to_string(),
                severity: ErrorSeverity::Major,
                location: Some(ErrorLocation::FileStructure { offset }),
                suggested_fix: Some("/ID must be followed by [...]".to_string()),
            });
        }
    }

    Ok(())
}

/// Validate hex string elements in PDF ID array
fn validate_hex_string_elements(array_content: &str, result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    for hex_match in array_content.split('<').skip(1) {
        if let Some(hex_end) = hex_match.find('>') {
            let hex_data = &hex_match[..hex_end];

            if hex_data.len() % 2 != 0 {
                result.errors.push(ValidationError {
                    code: "PDF_ID_ODD_LENGTH".to_string(),
                    message: "PDF ID hex string has odd length".to_string(),
                    severity: ErrorSeverity::Major,
                    location: Some(ErrorLocation::FileStructure { offset }),
                    suggested_fix: Some("Hex strings must have even number of characters".to_string()),
                });
            }

            if !hex_data.chars().all(|c| c.is_ascii_hexdigit()) {
                result.errors.push(ValidationError {
                    code: "PDF_ID_INVALID_HEX".to_string(),
                    message: "PDF ID contains invalid hex characters".to_string(),
                    severity: ErrorSeverity::Major,
                    location: Some(ErrorLocation::FileStructure { offset }),
                    suggested_fix: Some("Hex strings must contain only 0-9, A-F characters".to_string()),
                });
            }

            if hex_data.len() < 16 {
                result.warnings.push(ValidationWarning {
                    code: "PDF_ID_SHORT_LENGTH".to_string(),
                    message: format!("PDF ID hex string unusually short: {} characters", hex_data.len()),
                    location: Some(ErrorLocation::FileStructure { offset }),
                    recommendation: Some("PDF IDs typically contain 16+ hex characters".to_string()),
                });
            }
        }
    }
    Ok(())
}

/// Validate cross-reference table structure
fn validate_xref_structure(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    let search_start = if data.len() > 1024 { data.len() - 1024 } else { 0 };
    let search_area = &data[search_start..];

    let content = match std::str::from_utf8(search_area) {
        Ok(s) => s,
        Err(_) => return validate_xref_binary_search(data, result) // Try binary search if UTF-8 fails
    };

    if let Some(startxref_pos) = content.rfind("startxref") {
        let offset_start = startxref_pos + "startxref".len();
        if let Some(offset_line) = content[offset_start..].lines().next() {
            if let Ok(xref_offset) = offset_line.trim().parse::<u64>() {
                if xref_offset < data.len() as u64 {
                    validate_xref_at_offset(data, xref_offset, result)?;
                } else {
                    result.errors.push(ValidationError {
                        code: "XREF_OFFSET_BEYOND_EOF".to_string(),
                        message: format!("XRef offset {} beyond file size {}", xref_offset, data.len()),
                        severity: ErrorSeverity::Critical,
                        location: Some(ErrorLocation::FileStructure { offset: xref_offset }),
                        suggested_fix: Some("XRef offset points beyond file end".to_string()),
                    });
                    return attempt_xref_recovery(data, result);
                }
            } else {
                result.errors.push(ValidationError {
                    code: "XREF_OFFSET_INVALID".to_string(),
                    message: format!("Invalid XRef offset format: {}", offset_line.trim()),
                    severity: ErrorSeverity::Critical,
                    location: Some(ErrorLocation::Trailer),
                    suggested_fix: Some("startxref must be followed by numeric offset".to_string()),
                });
                return attempt_xref_recovery(data, result);
            }
        }
    } else {
        return attempt_xref_recovery(data, result);
    }

    Ok(())
}

/// Validate xref binary search when UTF-8 fails
fn validate_xref_binary_search(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    let startxref_marker = b"startxref";
    if let Some(_) = data.windows(startxref_marker.len()).rposition(|window| window == startxref_marker) {
        result.warnings.push(ValidationWarning {
            code: "XREF_BINARY_FOUND".to_string(),
            message: "Found startxref marker in binary data despite UTF-8 issues".to_string(),
            location: Some(ErrorLocation::Trailer),
            recommendation: Some("File has encoding issues but may contain valid xref structure".to_string()),
        });
    }
    Ok(())
}

/// Attempt xref recovery
fn attempt_xref_recovery(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    if let Ok(full_content) = std::str::from_utf8(data) {
        let xref_positions: Vec<_> = full_content.match_indices("xref").collect();
        if !xref_positions.is_empty() {
            result.warnings.push(ValidationWarning {
                code: "XREF_TABLES_FOUND_NO_POINTER".to_string(),
                message: format!("Found {} xref table(s) but no valid startxref pointer", xref_positions.len()),
                location: Some(ErrorLocation::FileStructure { offset: xref_positions[0].0 as u64 }),
                recommendation: Some("Attempting recovery using first found xref table".to_string()),
            });

            // Try to validate the first xref table found
            validate_xref_at_offset(data, xref_positions[0].0 as u64, result)?;
        }
    }
    Ok(())
}

/// Validate cross-reference table at specific offset
fn validate_xref_at_offset(data: &[u8], offset: u64, result: &mut ValidationResult) -> PdfResult<()> {
    let start = offset as usize;
    if start >= data.len() {
        result.errors.push(ValidationError {
            code: "XREF_OFFSET_INVALID_POSITION".to_string(),
            message: format!("XRef offset {} exceeds file length", offset),
            severity: ErrorSeverity::Critical,
            location: Some(ErrorLocation::FileStructure { offset }),
            suggested_fix: Some("XRef offset must point to valid location in file".to_string()),
        });
        return Ok(());
    }

    let xref_area = &data[start..];
    let content = match std::str::from_utf8(&xref_area[..std::cmp::min(1024, xref_area.len())]) {
        Ok(s) => s,
        Err(_) => {
            result.errors.push(ValidationError {
                code: "XREF_INVALID_UTF8".to_string(),
                message: "XRef area contains invalid UTF-8".to_string(),
                severity: ErrorSeverity::Major,
                location: Some(ErrorLocation::FileStructure { offset }),
                suggested_fix: Some("XRef table may be corrupted".to_string()),
            });
            return validate_xref_binary_content(xref_area, result, offset);
        }
    };

    if content.starts_with("xref") {
        validate_traditional_xref(content, result, offset)?;
    } else if content.contains("obj") {
        validate_xref_stream(content, result, offset)?;
    } else {
        result.errors.push(ValidationError {
            code: "XREF_INVALID_FORMAT".to_string(),
            message: "XRef location does not contain valid xref table or stream".to_string(),
            severity: ErrorSeverity::Critical,
            location: Some(ErrorLocation::FileStructure { offset }),
            suggested_fix: Some("XRef must be either 'xref' table or object stream".to_string()),        });
        let xref_str = std::str::from_utf8(xref_area).map_err(|e| PdfError::Parse { 
            offset, 
            message: format!("Invalid UTF-8 in xref area: {}", e), 
            context: "xref validation".to_string() 
        })?;
        return analyze_xref_content_type(xref_str, result, offset);
    }

    Ok(())
}

/// Validate xref binary content
fn validate_xref_binary_content(xref_area: &[u8], result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    let xref_marker = b"xref";
    if xref_area.starts_with(xref_marker) {
        result.warnings.push(ValidationWarning {
            code: "XREF_BINARY_TABLE".to_string(),
            message: "XRef table found in binary format".to_string(),
            location: Some(ErrorLocation::FileStructure { offset }),
            recommendation: Some("Binary xref tables may indicate encoding issues".to_string()),
        });
    }
    Ok(())
}

/// Analyze xref content type
fn analyze_xref_content_type(content: &str, result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    if content.contains("<<") && content.contains(">>") {
        result.warnings.push(ValidationWarning {
            code: "XREF_POSSIBLE_OBJECT".to_string(),
            message: "XRef location contains object-like structure".to_string(),
            location: Some(ErrorLocation::FileStructure { offset }),
            recommendation: Some("May be compressed xref stream or mislocated object".to_string()),
        });
    }
    Ok(())
}

/// Validate traditional xref table format
fn validate_traditional_xref(content: &str, result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    let lines: Vec<&str> = content.lines().collect();
    if lines.len() < 3 {
        result.errors.push(ValidationError {
            code: "XREF_TOO_SHORT".to_string(),
            message: "XRef table too short".to_string(),
            severity: ErrorSeverity::Critical,
            location: Some(ErrorLocation::FileStructure { offset }),
            suggested_fix: Some("XRef table must have header and at least one entry".to_string()),
        });
        return analyze_truncated_xref(lines, result, offset);
    }

    if lines[0] != "xref" {
        result.errors.push(ValidationError {
            code: "XREF_INVALID_HEADER".to_string(),
            message: "XRef table does not start with 'xref'".to_string(),
            severity: ErrorSeverity::Critical,
            location: Some(ErrorLocation::FileStructure { offset }),
            suggested_fix: Some("First line must be exactly 'xref'".to_string()),
        });
        return analyze_malformed_xref_header(lines, result, offset);
    }

    // Validate subsection headers and entries
    let mut line_idx = 1;
    let mut total_entries = 0;
    let mut subsection_count = 0;

    while line_idx < lines.len() && !lines[line_idx].starts_with("trailer") {
        if let Some((start_obj, count)) = parse_subsection_header(lines[line_idx]) {
            subsection_count += 1;
            line_idx += 1;

            // Validate entries in this subsection
            for entry_idx in 0..count {
                if line_idx >= lines.len() {
                    result.errors.push(ValidationError {
                        code: "XREF_SUBSECTION_TRUNCATED".to_string(),
                        message: format!("XRef subsection truncated at entry {}", entry_idx),
                        severity: ErrorSeverity::Critical,
                        location: Some(ErrorLocation::FileStructure { offset }),
                        suggested_fix: Some("All declared xref entries must be present".to_string()),
                    });
                    break;
                }

                validate_xref_entry(lines[line_idx], start_obj + entry_idx, result, offset)?;
                line_idx += 1;
                total_entries += 1;
            }
        } else {
            result.errors.push(ValidationError {
                code: "XREF_INVALID_SUBSECTION".to_string(),
                message: format!("Invalid XRef subsection header: {}", lines[line_idx]),
                severity: ErrorSeverity::Major,
                location: Some(ErrorLocation::FileStructure { offset }),
                suggested_fix: Some("Subsection header must be 'start_num count'".to_string()),
            });
            line_idx += 1;
        }
    }

    // Update validation statistics
    result.validation_stats.references_validated += total_entries;

    if subsection_count == 0 {
        result.errors.push(ValidationError {
            code: "XREF_NO_SUBSECTIONS".to_string(),
            message: "XRef table contains no valid subsections".to_string(),
            severity: ErrorSeverity::Critical,
            location: Some(ErrorLocation::FileStructure { offset }),
            suggested_fix: Some("XRef table must contain at least one subsection".to_string()),
        });
    }

    log::debug!("Validated traditional xref with {} subsections and {} entries", subsection_count, total_entries);
    Ok(())
}

/// Analyze truncated xref
fn analyze_truncated_xref(lines: Vec<&str>, result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    if !lines.is_empty() && lines[0] == "xref" {
        result.warnings.push(ValidationWarning {
            code: "XREF_HEADER_ONLY".to_string(),
            message: "XRef table contains only header, no entries".to_string(),
            location: Some(ErrorLocation::FileStructure { offset }),
            recommendation: Some("File may be truncated or xref table incomplete".to_string()),
        });
    }
    Ok(())
}

/// Analyze malformed xref header
fn analyze_malformed_xref_header(lines: Vec<&str>, result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    if !lines.is_empty() && lines[0].contains("xref") {
        result.warnings.push(ValidationWarning {
            code: "XREF_HEADER_MALFORMED".to_string(),
            message: format!("XRef header contains extra content: '{}'", lines[0]),
            location: Some(ErrorLocation::FileStructure { offset }),
            recommendation: Some("Header should be exactly 'xref' on its own line".to_string()),
        });
    }
    Ok(())
}

/// Parse xref subsection header
fn parse_subsection_header(line: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = line.trim().split_whitespace().collect();
    if parts.len() == 2 {
        if let (Ok(start), Ok(count)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
            return Some((start, count));
        }
    }
    None
}

/// Validate individual xref entry
fn validate_xref_entry(line: &str, object_num: u32, result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    let parts: Vec<&str> = line.trim().split_whitespace().collect();
    if parts.len() != 3 {
        result.errors.push(ValidationError {
            code: "XREF_ENTRY_INVALID_FORMAT".to_string(),
            message: format!("Invalid XRef entry format for object {}: {}", object_num, line),
            severity: ErrorSeverity::Major,
            location: Some(ErrorLocation::FileStructure { offset }),
            suggested_fix: Some("XRef entry must have format 'offset generation n/f'".to_string()),
        });
        return analyze_malformed_entry(line, object_num, result, offset);
    }

    // Validate offset
    if let Ok(entry_offset) = parts[0].parse::<u64>() {
        if entry_offset == 0 && object_num != 0 && parts[2] == "n" {
            result.warnings.push(ValidationWarning {
                code: "XREF_ZERO_OFFSET_IN_USE".to_string(),
                message: format!("Object {} has zero offset but marked as in use", object_num),
                location: Some(ErrorLocation::FileStructure { offset }),
                recommendation: Some("Zero offsets typically indicate free objects".to_string()),
            });
        }
    } else {
        result.errors.push(ValidationError {
            code: "XREF_ENTRY_INVALID_OFFSET".to_string(),
            message: format!("Invalid offset in XRef entry for object {}: {}", object_num, parts[0]),
            severity: ErrorSeverity::Major,
            location: Some(ErrorLocation::FileStructure { offset }),
            suggested_fix: Some("Offset must be numeric".to_string()),
        });
    }

    // Validate generation
    if let Ok(generation) = parts[1].parse::<u16>() {
        if generation > 65535 {
            result.warnings.push(ValidationWarning {
                code: "XREF_HIGH_GENERATION".to_string(),
                message: format!("Object {} has unusually high generation {}", object_num, generation),
                location: Some(ErrorLocation::FileStructure { offset }),
                recommendation: Some("High generation numbers may indicate file issues".to_string()),
            });
        }
    } else {
        result.errors.push(ValidationError {
            code: "XREF_ENTRY_INVALID_GENERATION".to_string(),
            message: format!("Invalid generation in XRef entry for object {}: {}", object_num, parts[1]),
            severity: ErrorSeverity::Major,
            location: Some(ErrorLocation::FileStructure { offset }),
            suggested_fix: Some("Generation must be numeric".to_string()),
        });
    }

    // Validate flag
    if parts[2] != "n" && parts[2] != "f" {
        result.errors.push(ValidationError {
            code: "XREF_ENTRY_INVALID_FLAG".to_string(),
            message: format!("Invalid flag in XRef entry for object {}: {}", object_num, parts[2]),
            severity: ErrorSeverity::Major,
            location: Some(ErrorLocation::FileStructure { offset }),
            suggested_fix: Some("Flag must be 'n' (in use) or 'f' (free)".to_string()),
        });
    }

    Ok(())
}

/// Analyze malformed entry
fn analyze_malformed_entry(line: &str, object_num: u32, result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    let parts: Vec<&str> = line.trim().split_whitespace().collect();

    if parts.len() < 3 {
        result.warnings.push(ValidationWarning {
            code: "XREF_ENTRY_TOO_FEW_PARTS".to_string(),
            message: format!("XRef entry for object {} has only {} parts, expected 3", object_num, parts.len()),
            location: Some(ErrorLocation::FileStructure { offset }),
            recommendation: Some("Entry may be truncated or contain missing fields".to_string()),
        });
    } else if parts.len() > 3 {
        result.warnings.push(ValidationWarning {
            code: "XREF_ENTRY_TOO_MANY_PARTS".to_string(),
            message: format!("XRef entry for object {} has {} parts, expected 3", object_num, parts.len()),
            location: Some(ErrorLocation::FileStructure { offset }),
            recommendation: Some("Entry may contain extra whitespace or formatting issues".to_string()),
        });
    }

    Ok(())
}

/// Validate xref stream format
fn validate_xref_stream(content: &str, result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    // Check for object header
    if let Some(obj_match) = Regex::new(r"(\d+)\s+(\d+)\s+obj").unwrap().find(content) {
        result.warnings.push(ValidationWarning {
            code: "XREF_STREAM_DETECTED".to_string(),
            message: format!("XRef stream detected at object {}", obj_match.as_str()),
            location: Some(ErrorLocation::FileStructure { offset }),
            recommendation: Some("XRef streams are valid but require specialized parsing".to_string()),
        });

        // Check for required stream dictionary entries
        validate_xref_stream_dictionary(content, result, offset)?;
    } else {
        result.errors.push(ValidationError {
            code: "XREF_STREAM_NO_OBJECT".to_string(),
            message: "XRef stream location does not contain valid object header".to_string(),
            severity: ErrorSeverity::Major,
            location: Some(ErrorLocation::FileStructure { offset }),
            suggested_fix: Some("XRef streams must be objects with proper headers".to_string()),
        });
    }

    Ok(())
}

/// Validate xref stream dictionary
fn validate_xref_stream_dictionary(content: &str, result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    // Check for required XRef stream fields
    if !content.contains("/Type /XRef") {
        result.errors.push(ValidationError {
            code: "XREF_STREAM_TYPE_MISSING".to_string(),
            message: "XRef stream missing /Type /XRef".to_string(),
            severity: ErrorSeverity::Major,
            location: Some(ErrorLocation::FileStructure { offset }),
            suggested_fix: Some("XRef streams must have /Type /XRef in dictionary".to_string()),
        });
    }

    if !content.contains("/Size") {
        result.errors.push(ValidationError {
            code: "XREF_STREAM_SIZE_MISSING".to_string(),
            message: "XRef stream missing /Size field".to_string(),
            severity: ErrorSeverity::Major,
            location: Some(ErrorLocation::FileStructure { offset }),
            suggested_fix: Some("XRef streams must specify /Size".to_string()),
        });
    }

    if !content.contains("/W") {
        result.errors.push(ValidationError {
            code: "XREF_STREAM_W_MISSING".to_string(),
            message: "XRef stream missing /W field".to_string(),
            severity: ErrorSeverity::Major,
            location: Some(ErrorLocation::FileStructure { offset }),
            suggested_fix: Some("XRef streams must specify /W array".to_string()),
        });
    }

    // Check for optional fields
    if content.contains("/Index") {
        result.warnings.push(ValidationWarning {
            code: "XREF_STREAM_INDEX_FOUND".to_string(),
            message: "XRef stream contains /Index array".to_string(),
            location: Some(ErrorLocation::FileStructure { offset }),
            recommendation: Some("/Index indicates subsection structure in stream".to_string()),
        });
    }

    Ok(())
}

/// Validate object structure throughout the document
fn validate_object_structure(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    let content = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return validate_binary_object_patterns(data, result),
    };

    let object_regex = Regex::new(r"\b(\d+)\s+(\d+)\s+obj\b").unwrap();
    let mut object_count = 0;
    let mut max_object_num = 0;
    let mut object_numbers = Vec::new();

    for captures in object_regex.captures_iter(content) {
        if let (Ok(obj_num), Ok(gen_num)) = (captures[1].parse::<u32>(), captures[2].parse::<u32>()) {
            object_count += 1;
            max_object_num = max_object_num.max(obj_num);
            object_numbers.push(obj_num);

            // Validate object format
            if gen_num > 65535 {
                result.warnings.push(ValidationWarning {
                    code: "OBJECT_HIGH_GENERATION".to_string(),
                    message: format!("Object {} has unusually high generation number {}", obj_num, gen_num),
                    location: Some(ErrorLocation::FileStructure { offset: 0 }),
                    recommendation: Some("Generation numbers are typically low".to_string()),
                });
            }

            // Check for duplicate object numbers (different generations are allowed)
            validate_object_uniqueness(obj_num, gen_num, &object_numbers, result)?;
        }
    }

    // Validate object integrity
    let endobj_count = content.matches("endobj").count();
    if object_count != endobj_count {
        result.errors.push(ValidationError {
            code: "OBJECT_ENDOBJ_MISMATCH".to_string(),
            message: format!("Mismatch between obj ({}) and endobj ({}) count", object_count, endobj_count),
            severity: ErrorSeverity::Major,
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            suggested_fix: Some("Each 'obj' must have corresponding 'endobj'".to_string()),
        });
    } else {
        validate_object_nesting(content, result)?;
    }

    // Validate object numbering sequence
    validate_object_numbering_patterns(&object_numbers, result)?;

    result.validation_stats.objects_validated = object_count as u32;

    log::debug!("Validated {} objects with max object number {}", object_count, max_object_num);
    Ok(())
}

/// Validate binary object patterns
fn validate_binary_object_patterns(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    let obj_marker = b" obj";
    let endobj_marker = b"endobj";

    let obj_count = data.windows(obj_marker.len()).filter(|&window| window == obj_marker).count();
    let endobj_count = data.windows(endobj_marker.len()).filter(|&window| window == endobj_marker).count();

    if obj_count > 0 && endobj_count > 0 {
        result.warnings.push(ValidationWarning {
            code: "BINARY_OBJECTS_DETECTED".to_string(),
            message: format!("Found {} obj and {} endobj markers in binary data", obj_count, endobj_count),
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            recommendation: Some("File contains objects but has encoding issues".to_string()),
        });

        if obj_count != endobj_count {
            result.errors.push(ValidationError {
                code: "BINARY_OBJECT_MISMATCH".to_string(),
                message: format!("Binary obj/endobj count mismatch: {} obj, {} endobj", obj_count, endobj_count),
                severity: ErrorSeverity::Major,
                location: Some(ErrorLocation::FileStructure { offset: 0 }),
                suggested_fix: Some("Object structure integrity compromised".to_string()),
            });
        }
    }
    Ok(())
}

/// Validate object uniqueness
fn validate_object_uniqueness(obj_num: u32, gen_num: u32, object_numbers: &[u32], result: &mut ValidationResult) -> PdfResult<()> {
    let same_number_count = object_numbers.iter().filter(|&&num| num == obj_num).count();

    if same_number_count > 1 {
        result.warnings.push(ValidationWarning {
            code: "DUPLICATE_OBJECT_NUMBER".to_string(),
            message: format!("Object number {} appears multiple times (generation {})", obj_num, gen_num),
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            recommendation: Some("Multiple generations of same object may indicate incremental updates".to_string()),
        });
    }

    Ok(())
}

/// Validate object nesting
fn validate_object_nesting(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    let obj_positions: Vec<_> = content.match_indices(" obj").collect();
    let endobj_positions: Vec<_> = content.match_indices("endobj").collect();

    for (i, (obj_pos, _)) in obj_positions.iter().enumerate() {
        if let Some((endobj_pos, _)) = endobj_positions.get(i) {
            let between_content = &content[*obj_pos..*endobj_pos];

            // Check for nested obj declarations
            if between_content.contains(" obj") {
                result.errors.push(ValidationError {
                    code: "NESTED_OBJECT_DETECTED".to_string(),
                    message: format!("Nested object declaration found starting at position {}", obj_pos),
                    severity: ErrorSeverity::Major,
                    location: Some(ErrorLocation::FileStructure { offset: 0 }),
                    suggested_fix: Some("Objects cannot be nested within other objects".to_string()),
                });
            }
        }
    }

    Ok(())
}

/// Validate object numbering patterns
fn validate_object_numbering_patterns(object_numbers: &[u32], result: &mut ValidationResult) -> PdfResult<()> {
    if object_numbers.is_empty() {
        return Ok(());
    }

    let mut sorted_numbers = object_numbers.to_vec();
    sorted_numbers.sort_unstable();
    sorted_numbers.dedup();

    // Check for gaps in numbering
    for i in 1..sorted_numbers.len() {
        let gap = sorted_numbers[i] - sorted_numbers[i-1];
        if gap > 100 {
            result.warnings.push(ValidationWarning {
                code: "LARGE_OBJECT_NUMBER_GAP".to_string(),
                message: format!("Large gap in object numbering: {} to {}", sorted_numbers[i-1], sorted_numbers[i]),
                location: Some(ErrorLocation::FileStructure { offset: 0 }),
                recommendation: Some("Large gaps may indicate deleted objects or unusual generation".to_string()),
            });
        }
    }

    // Check if object 0 exists (it should be the free list head)
    if !sorted_numbers.contains(&0) {
        result.warnings.push(ValidationWarning {
            code: "OBJECT_ZERO_MISSING".to_string(),
            message: "Object 0 not found - free list head missing".to_string(),
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            recommendation: Some("Object 0 should exist as head of free object list".to_string()),
        });
    }

    Ok(())
}

/// Validate page structure
fn validate_page_structure(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    let content = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return validate_binary_page_structure(data, result),
    };

    // Check for catalog object (root)
    if !content.contains("/Type /Catalog") {
        result.errors.push(ValidationError {
            code: "CATALOG_MISSING".to_string(),
            message: "Document catalog not found".to_string(),
            severity: ErrorSeverity::Critical,
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            suggested_fix: Some("PDF must contain a catalog object".to_string()),
        });
        return attempt_catalog_recovery(content, result);
    } else {
        validate_catalog_structure(content, result)?;
    }

    // Check for pages object
    if !content.contains("/Type /Pages") {
        result.errors.push(ValidationError {
            code: "PAGES_OBJECT_MISSING".to_string(),
            message: "Pages object not found".to_string(),
            severity: ErrorSeverity::Critical,
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            suggested_fix: Some("PDF must contain a pages object".to_string()),
        });
        return attempt_pages_recovery(content, result);
    } else {
        validate_pages_tree_structure(content, result)?;
    }

    // Check for individual pages
    if !content.contains("/Type /Page") {
        result.warnings.push(ValidationWarning {
            code: "NO_PAGES_FOUND".to_string(),
            message: "No individual pages found in document".to_string(),
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            recommendation: Some("Document appears to have no content pages".to_string()),
        });
    } else {
        validate_individual_pages(content, result)?;
    }

    log::debug!("Page structure validation completed");
    Ok(())
}

/// Validate binary page structure
fn validate_binary_page_structure(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    let catalog_marker = b"/Type /Catalog";
    let pages_marker = b"/Type /Pages";
    let page_marker = b"/Type /Page";

    let has_catalog = data.windows(catalog_marker.len()).any(|window| window == catalog_marker);
    let has_pages = data.windows(pages_marker.len()).any(|window| window == pages_marker);
    let has_individual_pages = data.windows(page_marker.len()).any(|window| window == page_marker);

    if has_catalog && has_pages {
        result.warnings.push(ValidationWarning {
            code: "BINARY_PAGE_STRUCTURE_FOUND".to_string(),
            message: "Page structure found in binary data despite encoding issues".to_string(),
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            recommendation: Some("File structure appears intact but has encoding problems".to_string()),
        });
    }

    if !has_individual_pages {
        result.warnings.push(ValidationWarning {
            code: "NO_BINARY_PAGES_FOUND".to_string(),
            message: "No individual page markers found in binary data".to_string(),
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            recommendation: Some("Document may be empty or have structural issues".to_string()),
        });
    }

    Ok(())
}

/// Attempt catalog recovery
fn attempt_catalog_recovery(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Look for partial catalog patterns
    if content.contains("/Catalog") || content.contains("/Pages") {
        result.warnings.push(ValidationWarning {
            code: "PARTIAL_CATALOG_FOUND".to_string(),
            message: "Found catalog-related keywords but no complete /Type /Catalog".to_string(),
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            recommendation: Some("Catalog may be malformed but document structure hints exist".to_string()),
        });
    }
    Ok(())
}

/// Attempt pages recovery  
fn attempt_pages_recovery(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Look for page-related patterns
    if content.contains("/Pages") || content.contains("/Kids") {
        result.warnings.push(ValidationWarning {
            code: "PARTIAL_PAGES_FOUND".to_string(),
            message: "Found pages-related keywords but no complete /Type /Pages".to_string(),
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            recommendation: Some("Pages tree may be malformed but structure hints exist".to_string()),
        });
    }
    Ok(())
}

/// Validate catalog structure
fn validate_catalog_structure(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Check for required catalog fields
    if !content.contains("/Pages") {
        result.errors.push(ValidationError {
            code: "CATALOG_PAGES_MISSING".to_string(),
            message: "Catalog missing /Pages reference".to_string(),
            severity: ErrorSeverity::Critical,
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            suggested_fix: Some("Catalog must reference pages tree".to_string()),
        });
    }

    // Check for optional but common catalog fields
    if content.contains("/Metadata") {
        result.warnings.push(ValidationWarning {
            code: "CATALOG_METADATA_FOUND".to_string(),
            message: "Catalog contains metadata stream reference".to_string(),
            location: Some(ErrorLocation::Metadata { field: "catalog".to_string() }),
            recommendation: Some("Metadata stream may contain forensically relevant information".to_string()),
        });
    }

    if content.contains("/AcroForm") {
        result.warnings.push(ValidationWarning {
            code: "CATALOG_ACROFORM_FOUND".to_string(),
            message: "Catalog contains AcroForm reference".to_string(),
            location: Some(ErrorLocation::Content),
            recommendation: Some("Document contains interactive forms".to_string()),
        });
    }

    Ok(())
}

/// Validate pages tree structure
fn validate_pages_tree_structure(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Extract page count if available
    if let Some(count_match) = Regex::new(r"/Count\s+(\d+)").unwrap().find(content) {
        if let Some(captures) = Regex::new(r"/Count\s+(\d+)").unwrap().captures(count_match.as_str()) {
            if let Ok(declared_count) = captures[1].parse::<u32>() {
                let actual_page_count = content.matches("/Type /Page").count() as u32;

                if declared_count != actual_page_count {
                    result.warnings.push(ValidationWarning {
                        code: "PAGE_COUNT_MISMATCH".to_string(),
                        message: format!("Declared page count ({}) differs from actual pages ({})", 
                                       declared_count, actual_page_count),
                        location: Some(ErrorLocation::FileStructure { offset: 0 }),
                        recommendation: Some("Page count inconsistency may indicate structural issues".to_string()),
                    });
                }

                result.validation_stats.objects_validated += actual_page_count;
            }
        }
    }

    // Check for Kids array
    if !content.contains("/Kids") {
        result.errors.push(ValidationError {
            code: "PAGES_KIDS_MISSING".to_string(),
            message: "Pages tree missing /Kids array".to_string(),
            severity: ErrorSeverity::Major,
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            suggested_fix: Some("Pages objects must contain /Kids array".to_string()),
        });
    }

    Ok(())
}

/// Validate individual pages
fn validate_individual_pages(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    let page_count = content.matches("/Type /Page").count();
    if page_count > 0 {
        result.validation_stats.objects_validated += page_count as u32;

        // Check for required page fields
        let pages_with_mediabox = content.matches("/MediaBox").count();
        if pages_with_mediabox < page_count {
            result.warnings.push(ValidationWarning {
                code: "PAGES_MISSING_MEDIABOX".to_string(),
                message: format!("{} page(s) may be missing MediaBox definitions", 
                               page_count - pages_with_mediabox),
                location: Some(ErrorLocation::Content),
                recommendation: Some("Pages should define MediaBox for proper rendering".to_string()),
            });
        }

        // Check for content streams
        let pages_with_contents = content.matches("/Contents").count();
        if pages_with_contents == 0 && page_count > 0 {
            result.warnings.push(ValidationWarning {
                code: "PAGES_NO_CONTENT".to_string(),
                message: "No pages appear to have content streams".to_string(),
                location: Some(ErrorLocation::Content),
                recommendation: Some("Document may be empty or have invisible content".to_string()),
            });
        }
    }

    log::debug!("Validated {} individual pages", page_count);
    Ok(())
}

/// Validate encryption integrity
fn validate_encryption_integrity(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    let content = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return validate_binary_encryption_markers(data, result),
    };

    // Check for encryption dictionary
    if content.contains("/Encrypt") {
        validate_encryption_dictionary_structure(content, result)?;

        result.warnings.push(ValidationWarning {
            code: "DOCUMENT_ENCRYPTED".to_string(),
            message: "Document contains encryption - some validation may be limited".to_string(),
            location: Some(ErrorLocation::Security),
            recommendation: Some("Decrypt document for full forensic analysis".to_string()),
        });
    } else {
        // Check if document should be encrypted but isn't
        validate_encryption_expectations(content, result)?;
    }

    Ok(())
}

/// Validate binary encryption markers
fn validate_binary_encryption_markers(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    let encrypt_marker = b"/Encrypt";
    if data.windows(encrypt_marker.len()).any(|window| window == encrypt_marker) {
        result.warnings.push(ValidationWarning {
            code: "BINARY_ENCRYPTION_FOUND".to_string(),
            message: "Encryption markers found in binary data".to_string(),
            location: Some(ErrorLocation::Security),
            recommendation: Some("File has encryption but encoding issues prevent full analysis".to_string()),
        });
    }
    Ok(())
}

/// Validate encryption dictionary structure
fn validate_encryption_dictionary_structure(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    if let Some(encrypt_pos) = content.find("/Encrypt") {
        let after_encrypt = &content[encrypt_pos..];

        // Look for encryption filter
        if !after_encrypt.contains("/Filter") {
            result.errors.push(ValidationError {
                code: "ENCRYPT_FILTER_MISSING".to_string(),
                message: "Encryption dictionary missing /Filter entry".to_string(),
                severity: ErrorSeverity::Major,
                location: Some(ErrorLocation::Security),
                suggested_fix: Some("Encryption dictionary must specify a filter".to_string()),
            });
        } else {
            validate_encryption_filter_type(after_encrypt, result)?;
        }

        // Check for standard security handler
        if after_encrypt.contains("/Standard") {
            validate_standard_encryption(after_encrypt, result)?;
        }

        // Check for public key encryption
        if after_encrypt.contains("/Adobe.PPKLite") || after_encrypt.contains("/Adobe.PPKMS") {
            validate_public_key_encryption(after_encrypt, result)?;
        }

        // Check for custom security handlers
        validate_custom_security_handlers(after_encrypt, result)?;
    }

    Ok(())
}

/// Validate encryption filter type
fn validate_encryption_filter_type(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    if content.contains("/Standard") {
        result.warnings.push(ValidationWarning {
            code: "STANDARD_ENCRYPTION_FOUND".to_string(),
            message: "Document uses standard encryption filter".to_string(),
            location: Some(ErrorLocation::Security),
            recommendation: Some("Standard encryption is widely supported".to_string()),
        });
    } else if content.contains("/Adobe.PPKLite") {
        result.warnings.push(ValidationWarning {
            code: "PPKLITE_ENCRYPTION_FOUND".to_string(),
            message: "Document uses Adobe PPKLite encryption".to_string(),
            location: Some(ErrorLocation::Security),
            recommendation: Some("PPKLite requires certificate-based decryption".to_string()),
        });
    } else {
        result.warnings.push(ValidationWarning {
            code: "UNKNOWN_ENCRYPTION_FILTER".to_string(),
            message: "Document uses unknown or custom encryption filter".to_string(),
            location: Some(ErrorLocation::Security),
            recommendation: Some("Custom encryption may require specialized tools".to_string()),
        });
    }
    Ok(())
}

/// Validate custom security handlers
fn validate_custom_security_handlers(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Look for non-standard security handlers
    let standard_handlers = ["/Standard", "/Adobe.PPKLite", "/Adobe.PPKMS"];
    let has_standard = standard_handlers.iter().any(|&handler| content.contains(handler));

    if content.contains("/Filter") && !has_standard {
        result.warnings.push(ValidationWarning {
            code: "CUSTOM_SECURITY_HANDLER".to_string(),
            message: "Document may use custom security handler".to_string(),
            location: Some(ErrorLocation::Security),
            recommendation: Some("Custom handlers require specific software for decryption".to_string()),
        });
    }
    Ok(())
}

/// Validate encryption expectations
fn validate_encryption_expectations(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Check for security-related metadata that might suggest encryption
    if content.contains("/Author") || content.contains("/Creator") {
        if content.contains("secure") || content.contains("encrypt") || content.contains("protect") {
            result.warnings.push(ValidationWarning {
                code: "SECURITY_METADATA_NO_ENCRYPTION".to_string(),
                message: "Document metadata suggests security but no encryption found".to_string(),
                location: Some(ErrorLocation::Security),
                recommendation: Some("Document may have been processed to remove encryption".to_string()),
            });
        }
    }
    Ok(())
}

/// Validate signature integrity
fn validate_signature_integrity(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    let content = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return validate_binary_signature_markers(data, result),
    };

    // Check for signature fields
    if content.contains("/Type /Sig") {
        let sig_count = content.matches("/Type /Sig").count();

        result.warnings.push(ValidationWarning {
            code: "SIGNATURES_FOUND".to_string(),
            message: format!("Document contains {} digital signature(s)", sig_count),
            location: Some(ErrorLocation::Security),
            recommendation: Some("Verify signatures for document authenticity".to_string()),
        });

        validate_signature_completeness(content, result)?;
        validate_signature_timestamp_coverage(content, result)?;

    } else {
        // Check for signature-related fields that might indicate partial signatures
        validate_partial_signature_indicators(content, result)?;
    }

    Ok(())
}

/// Validate binary signature markers
fn validate_binary_signature_markers(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    let sig_marker = b"/Type /Sig";
    let byterange_marker = b"/ByteRange";

    if data.windows(sig_marker.len()).any(|window| window == sig_marker) {
        result.warnings.push(ValidationWarning {
            code: "BINARY_SIGNATURES_FOUND".to_string(),
            message: "Signature markers found in binary data".to_string(),
            location: Some(ErrorLocation::Security),
            recommendation: Some("File has signatures but encoding issues prevent full analysis".to_string()),
        });
    }

    if data.windows(byterange_marker.len()).any(|window| window == byterange_marker) {
        result.warnings.push(ValidationWarning {
            code: "BINARY_BYTERANGE_FOUND".to_string(),
            message: "ByteRange markers found indicating signature structure".to_string(),
            location: Some(ErrorLocation::Security),
            recommendation: Some("Signature byte ranges detected in binary data".to_string()),
        });
    }

    Ok(())
}

/// Validate signature completeness
fn validate_signature_completeness(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Check for signature validation info
    if content.contains("/ByteRange") {
        validate_signature_byte_range(content, result)?;
    } else {
        result.errors.push(ValidationError {
            code: "SIGNATURE_BYTERANGE_MISSING".to_string(),
            message: "Digital signature missing ByteRange".to_string(),
            severity: ErrorSeverity::Major,
            location: Some(ErrorLocation::Security),
            suggested_fix: Some("Valid signatures must specify ByteRange".to_string()),
        });
    }

    // Check for signature dictionary completeness
    if !content.contains("/Contents") {
        result.errors.push(ValidationError {
            code: "SIGNATURE_CONTENTS_MISSING".to_string(),
            message: "Digital signature missing Contents".to_string(),
            severity: ErrorSeverity::Major,
            location: Some(ErrorLocation::Security),
            suggested_fix: Some("Valid signatures must contain signature data".to_string()),
        });
    } else {
        validate_signature_contents_format(content, result)?;
    }

    Ok(())
}

/// Validate signature contents format
fn validate_signature_contents_format(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Look for hex-encoded signature data
    if let Some(contents_pos) = content.find("/Contents") {
        let after_contents = &content[contents_pos..];
        if let Some(hex_start) = after_contents.find('<') {
            if let Some(hex_end) = after_contents[hex_start..].find('>') {
                let hex_data = &after_contents[hex_start+1..hex_start+hex_end];

                if hex_data.is_empty() {
                    result.errors.push(ValidationError {
                        code: "SIGNATURE_CONTENTS_EMPTY".to_string(),
                        message: "Signature Contents field is empty".to_string(),
                        severity: ErrorSeverity::Major,
                        location: Some(ErrorLocation::Security),
                        suggested_fix: Some("Signature must contain actual signature data".to_string()),
                    });
                } else if !hex_data.chars().all(|c| c.is_ascii_hexdigit() || c.is_whitespace()) {
                    result.errors.push(ValidationError {
                        code: "SIGNATURE_CONTENTS_INVALID_HEX".to_string(),
                        message: "Signature Contents contains invalid hex data".to_string(),
                        severity: ErrorSeverity::Major,
                        location: Some(ErrorLocation::Security),
                        suggested_fix: Some("Signature data must be valid hexadecimal".to_string()),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Validate signature timestamp coverage
fn validate_signature_timestamp_coverage(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Check for timestamp signatures
    if content.contains("/SubFilter /ETSI.RFC3161") {
        result.warnings.push(ValidationWarning {
            code: "TIMESTAMP_SIGNATURE_FOUND".to_string(),
            message: "Document contains timestamp signature".to_string(),
            location: Some(ErrorLocation::Security),
            recommendation: Some("Timestamp signatures provide time-stamped integrity".to_string()),
        });
    }

    // Check for long-term validation info
    if content.contains("/DSS") {
        validate_document_security_store(content, result)?;
    }

    Ok(())
}

/// Validate document security store
fn validate_document_security_store(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    result.warnings.push(ValidationWarning {
        code: "DSS_FOUND".to_string(),
        message: "Document Security Store (DSS) found".to_string(),
        location: Some(ErrorLocation::Security),
        recommendation: Some("DSS contains certificate and revocation information".to_string()),
    });

    // Check for specific DSS components
    if content.contains("/Certs") {
        result.warnings.push(ValidationWarning {
            code: "DSS_CERTIFICATES_FOUND".to_string(),
            message: "DSS contains certificate store".to_string(),
            location: Some(ErrorLocation::Security),
            recommendation: Some("Certificate information available for validation".to_string()),
        });
    }

    if content.contains("/CRLs") {
        result.warnings.push(ValidationWarning {
            code: "DSS_CRLS_FOUND".to_string(),
            message: "DSS contains Certificate Revocation Lists".to_string(),
            location: Some(ErrorLocation::Security),
            recommendation: Some("CRL information available for revocation checking".to_string()),
        });
    }

    if content.contains("/OCSPs") {
        result.warnings.push(ValidationWarning {
            code: "DSS_OCSPS_FOUND".to_string(),
            message: "DSS contains OCSP responses".to_string(),
            location: Some(ErrorLocation::Security),
            recommendation: Some("OCSP responses available for real-time validation".to_string()),
        });
    }

    Ok(())
}

/// Validate partial signature indicators
fn validate_partial_signature_indicators(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Look for signature-related fields without complete signatures
    if content.contains("/SigFlags") {
        result.warnings.push(ValidationWarning {
            code: "SIGNATURE_FLAGS_FOUND".to_string(),
            message: "Document contains signature flags but no complete signatures".to_string(),
            location: Some(ErrorLocation::Security),
            recommendation: Some("Document may be prepared for signing or have incomplete signatures".to_string()),
        });
    }

    if content.contains("/Fields") && content.contains("/FT /Sig") {
        result.warnings.push(ValidationWarning {
            code: "SIGNATURE_FIELDS_FOUND".to_string(),
            message: "Document contains signature fields but may not be signed".to_string(),
            location: Some(ErrorLocation::Security),
            recommendation: Some("Signature fields present but may be empty".to_string()),
        });
    }

    Ok(())
}

/// Detect forensic markers in PDF
fn detect_forensic_markers(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    let content = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return detect_binary_forensic_markers(data, result),
    };

    // Check for common PDF creation tools and their markers
    detect_creation_tool_markers(content, result)?;
    detect_modification_markers(content, result)?;
    detect_suspicious_patterns(content, result)?;
    detect_embedded_content(content, result)?;
    detect_script_content(content, result)?;

    Ok(())
}

/// Detect binary forensic markers
fn detect_binary_forensic_markers(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    let producer_marker = b"/Producer";
    let creator_marker = b"/Creator";

    if data.windows(producer_marker.len()).any(|window| window == producer_marker) ||
       data.windows(creator_marker.len()).any(|window| window == creator_marker) {
        result.warnings.push(ValidationWarning {
            code: "BINARY_METADATA_MARKERS".to_string(),
            message: "Metadata markers found in binary data".to_string(),
            location: Some(ErrorLocation::Metadata { field: "binary".to_string() }),
            recommendation: Some("Metadata present but encoding issues prevent full analysis".to_string()),
        });
    }
    Ok(())
}

/// Detect creation tool markers
fn detect_creation_tool_markers(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    let creation_markers = [
        ("/Producer", "PDF producer information"),
        ("/Creator", "PDF creator application"),
        ("/CreationDate", "Document creation timestamp"),
        ("/ModDate", "Document modification timestamp"),
    ];

    let mut markers_found = Vec::new();
    for (marker, description) in &creation_markers {
        if content.contains(marker) {
            markers_found.push((*marker, *description));
        }
    }

    if !markers_found.is_empty() {
        result.warnings.push(ValidationWarning {
            code: "METADATA_MARKERS_FOUND".to_string(),
            message: format!("Found {} metadata markers", markers_found.len()),
            location: Some(ErrorLocation::Metadata { field: "general".to_string() }),
            recommendation: Some("Metadata may contain forensic information about document origin".to_string()),
        });

        // Extract specific tool information
        extract_tool_information(content, result)?;
    }

    Ok(())
}

/// Extract tool information
fn extract_tool_information(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Look for specific tool signatures
    let tool_patterns = [
        ("Adobe", "Adobe Acrobat or related tools"),
        ("Microsoft", "Microsoft Office or related tools"),
        ("LibreOffice", "LibreOffice suite"),
        ("PDFtk", "PDF Toolkit"),
        ("iText", "iText library"),
        ("wkhtmltopdf", "WebKit HTML to PDF"),
        ("Ghostscript", "Ghostscript PostScript interpreter"),
    ];

    for (tool, description) in &tool_patterns {
        if content.to_lowercase().contains(&tool.to_lowercase()) {
            result.warnings.push(ValidationWarning {
                code: "SPECIFIC_TOOL_DETECTED".to_string(),
                message: format!("Tool signature detected: {} - {}", tool, description),
                location: Some(ErrorLocation::Metadata { field: "tool_detection".to_string() }),
                recommendation: Some("Tool information may help establish document provenance".to_string()),
            });
        }
    }

    Ok(())
}

/// Detect modification markers
fn detect_modification_markers(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Check for suspicious patterns that might indicate tampering
    let suspicious_patterns = [
        ("%%EOF", "Multiple EOF markers"),
        ("startxref", "Multiple XRef tables"),
        ("/Linearized", "Linearized PDF structure"),
    ];

    for (pattern, description) in &suspicious_patterns {
        let count = content.matches(pattern).count();
        if count > 1 && *pattern != "/Linearized" {
            result.warnings.push(ValidationWarning {
                code: "MULTIPLE_STRUCTURE_MARKERS".to_string(),
                message: format!("{}: found {} instances", description, count),
                location: Some(ErrorLocation::FileStructure { offset: 0 }),
                recommendation: Some("Multiple structural markers may indicate document modification".to_string()),
            });
        } else if count == 1 && *pattern == "/Linearized" {
            result.warnings.push(ValidationWarning {
                code: "LINEARIZED_PDF_FOUND".to_string(),
                message: "Document is linearized for web viewing".to_string(),
                location: Some(ErrorLocation::FileStructure { offset: 0 }),
                recommendation: Some("Linearization may affect forensic analysis".to_string()),
            });
        }
    }

    Ok(())
}

/// Detect suspicious patterns
fn detect_suspicious_patterns(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Check for unusual or suspicious patterns
    if content.contains("/OpenAction") {
        result.warnings.push(ValidationWarning {
            code: "AUTO_ACTION_FOUND".to_string(),
            message: "Document contains automatic actions".to_string(),
            location: Some(ErrorLocation::Content),
            recommendation: Some("Automatic actions may pose security risks".to_string()),
        });
    }

    if content.contains("/URI") {
        let uri_count = content.matches("/URI").count();
        result.warnings.push(ValidationWarning {
            code: "URI_ACTIONS_FOUND".to_string(),
            message: format!("Document contains {} URI action(s)", uri_count),
            location: Some(ErrorLocation::Content),
            recommendation: Some("URI actions may link to external resources".to_string()),
        });
    }

    if content.contains("/Launch") {
        result.warnings.push(ValidationWarning {
            code: "LAUNCH_ACTIONS_FOUND".to_string(),
            message: "Document contains launch actions".to_string(),
            location: Some(ErrorLocation::Content),
            recommendation: Some("Launch actions may execute external programs".to_string()),
        });
    }

    Ok(())
}

/// Detect embedded content
fn detect_embedded_content(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Check for embedded files or attachments
    if content.contains("/EmbeddedFile") || content.contains("/Filespec") {
        let embedded_count = content.matches("/EmbeddedFile").count();
        result.warnings.push(ValidationWarning {
            code: "EMBEDDED_FILES_FOUND".to_string(),
            message: format!("Document contains {} embedded file(s)", embedded_count),
            location: Some(ErrorLocation::Content),
            recommendation: Some("Embedded files should be examined for forensic evidence".to_string()),
        });
    }

    // Check for multimedia content
    if content.contains("/Movie") || content.contains("/Sound") {
        result.warnings.push(ValidationWarning {
            code: "MULTIMEDIA_CONTENT_FOUND".to_string(),
            message: "Document contains multimedia content".to_string(),
            location: Some(ErrorLocation::Content),
            recommendation: Some("Multimedia content may contain additional forensic data".to_string()),
        });
    }

    // Check for 3D content
    if content.contains("/3D") {
        result.warnings.push(ValidationWarning {
            code: "3D_CONTENT_FOUND".to_string(),
            message: "Document contains 3D content".to_string(),
            location: Some(ErrorLocation::Content),
            recommendation: Some("3D content may contain complex embedded data".to_string()),
        });
    }

    Ok(())
}

/// Detect script content
fn detect_script_content(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Check for JavaScript or actions
    if content.contains("/JavaScript") || content.contains("/JS") {
        let js_count = content.matches("/JavaScript").count() + content.matches("/JS").count();
        result.warnings.push(ValidationWarning {
            code: "JAVASCRIPT_FOUND".to_string(),
            message: format!("Document contains {} JavaScript reference(s)", js_count),
            location: Some(ErrorLocation::Content),
            recommendation: Some("JavaScript may indicate dynamic content or potential security risks".to_string()),
        });
    }

    // Check for form calculation scripts
    if content.contains("/Calculate") {
        result.warnings.push(ValidationWarning {
            code: "FORM_CALCULATIONS_FOUND".to_string(),
            message: "Document contains form calculation scripts".to_string(),
            location: Some(ErrorLocation::Content),
            recommendation: Some("Form calculations may contain executable code".to_string()),
        });
    }

    Ok(())
}

/// Detect third-party modifications
fn detect_third_party_modifications(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    let content = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return detect_binary_modification_markers(data, result),
    };

    detect_incremental_updates(content, result)?;
    detect_form_modifications(content, result)?;
    detect_annotation_modifications(content, result)?;
    detect_compression_modifications(content, result)?;
    detect_version_inconsistencies(content, result)?;
    detect_timestamp_anomalies(content, result)?;

    Ok(())
}

/// Detect binary modification markers
fn detect_binary_modification_markers(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    let xref_marker = b"xref";
    let acroform_marker = b"/AcroForm";

    let xref_count = data.windows(xref_marker.len()).filter(|&window| window == xref_marker).count();
    if xref_count > 1 {
        result.warnings.push(ValidationWarning {
            code: "BINARY_MULTIPLE_XREF".to_string(),
            message: format!("Found {} xref markers in binary data", xref_count),
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            recommendation: Some("Multiple xref tables may indicate incremental updates".to_string()),
        });
    }

    if data.windows(acroform_marker.len()).any(|window| window == acroform_marker) {
        result.warnings.push(ValidationWarning {
            code: "BINARY_ACROFORM_FOUND".to_string(),
            message: "AcroForm markers found in binary data".to_string(),
            location: Some(ErrorLocation::Content),
            recommendation: Some("Form fields detected despite encoding issues".to_string()),
        });
    }

    Ok(())
}

/// Detect incremental updates
fn detect_incremental_updates(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Check for incremental updates (multiple xref sections)
    let xref_count = content.matches("xref").count();
    if xref_count > 1 {
        result.warnings.push(ValidationWarning {
            code: "INCREMENTAL_UPDATES_FOUND".to_string(),
            message: format!("Document has {} incremental updates", xref_count - 1),
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            recommendation: Some("Incremental updates may indicate document modifications".to_string()),
        });

        // Analyze update pattern
        analyze_update_patterns(content, result)?;
    }

    Ok(())
}

/// Analyze update patterns
fn analyze_update_patterns(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    let xref_positions: Vec<_> = content.match_indices("xref").collect();

    if xref_positions.len() > 2 {
        result.warnings.push(ValidationWarning {
            code: "MULTIPLE_INCREMENTAL_UPDATES".to_string(),
            message: format!("Document has {} xref sections indicating extensive modification history", xref_positions.len()),
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            recommendation: Some("Extensive modifications may indicate complex editing history".to_string()),
        });
    }

    // Check spacing between updates
    for i in 1..xref_positions.len() {
        let gap = xref_positions[i].0 - xref_positions[i-1].0;
        if gap < 1000 {
            result.warnings.push(ValidationWarning {
                code: "CLOSELY_SPACED_UPDATES".to_string(),
                message: format!("Xref sections {} and {} are closely spaced ({} bytes apart)", i, i+1, gap),
                location: Some(ErrorLocation::FileStructure { offset: xref_positions[i].0 as u64 }),
                recommendation: Some("Closely spaced updates may indicate rapid successive modifications".to_string()),
            });
        }
    }

    Ok(())
}

/// Detect form modifications
fn detect_form_modifications(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Check for form field modifications
    if content.contains("/AcroForm") {
        result.warnings.push(ValidationWarning {
            code: "ACROFORM_FOUND".to_string(),
            message: "Document contains interactive form fields".to_string(),
            location: Some(ErrorLocation::Content),
            recommendation: Some("Form fields may have been modified after creation".to_string()),
        });

        // Check for specific form field types
        analyze_form_field_types(content, result)?;
    }

    Ok(())
}

/// Analyze form field types
fn analyze_form_field_types(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    let field_types = [
        ("/FT /Tx", "Text fields"),
        ("/FT /Ch", "Choice fields"),
        ("/FT /Btn", "Button fields"),
        ("/FT /Sig", "Signature fields"),
    ];

    for (field_type, description) in &field_types {
        let count = content.matches(field_type).count();
        if count > 0 {
            result.warnings.push(ValidationWarning {
                code: "SPECIFIC_FORM_FIELDS".to_string(),
                message: format!("Found {} {}", count, description.to_lowercase()),
                location: Some(ErrorLocation::Content),
                recommendation: Some("Specific field types may indicate document purpose and modification history".to_string()),
            });
        }
    }

    Ok(())
}

/// Detect annotation modifications
fn detect_annotation_modifications(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Check for annotations that might indicate modifications
    if content.contains("/Annot") {
        let annot_count = content.matches("/Annot").count();
        result.warnings.push(ValidationWarning {
            code: "ANNOTATIONS_FOUND".to_string(),
            message: format!("Document contains {} annotation(s)", annot_count),
            location: Some(ErrorLocation::Content),
            recommendation: Some("Annotations may indicate post-creation modifications".to_string()),
        });

        // Analyze annotation types
        analyze_annotation_types(content, result)?;
    }

    Ok(())
}

/// Analyze annotation types
fn analyze_annotation_types(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    let annotation_types = [
        ("/Subtype /Text", "Text annotations"),
        ("/Subtype /Link", "Link annotations"),
        ("/Subtype /FreeText", "Free text annotations"),
        ("/Subtype /Line", "Line annotations"),
        ("/Subtype /Square", "Square annotations"),
        ("/Subtype /Circle", "Circle annotations"),
        ("/Subtype /Polygon", "Polygon annotations"),
        ("/Subtype /PolyLine", "Polyline annotations"),
        ("/Subtype /Highlight", "Highlight annotations"),
        ("/Subtype /Underline", "Underline annotations"),
        ("/Subtype /Squiggly", "Squiggly annotations"),
        ("/Subtype /StrikeOut", "Strikeout annotations"),
        ("/Subtype /Stamp", "Stamp annotations"),
        ("/Subtype /Caret", "Caret annotations"),
        ("/Subtype /Ink", "Ink annotations"),
        ("/Subtype /Popup", "Popup annotations"),
        ("/Subtype /FileAttachment", "File attachment annotations"),
        ("/Subtype /Sound", "Sound annotations"),
        ("/Subtype /Movie", "Movie annotations"),
        ("/Subtype /Widget", "Widget annotations"),
        ("/Subtype /Screen", "Screen annotations"),
        ("/Subtype /PrinterMark", "Printer mark annotations"),
        ("/Subtype /TrapNet", "Trap network annotations"),
        ("/Subtype /Watermark", "Watermark annotations"),
        ("/Subtype /3D", "3D annotations"),
    ];

    for (annotation_type, description) in &annotation_types {
        let count = content.matches(annotation_type).count();
        if count > 0 {
            result.warnings.push(ValidationWarning {
                code: "SPECIFIC_ANNOTATION_TYPE".to_string(),
                message: format!("Found {} {}", count, description.to_lowercase()),
                location: Some(ErrorLocation::Content),
                recommendation: Some("Specific annotation types may provide clues about document usage".to_string()),
            });
        }
    }

    Ok(())
}

/// Detect compression modifications
fn detect_compression_modifications(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Check for unusual object stream compression
    if content.contains("/ObjStm") {
        let objstm_count = content.matches("/ObjStm").count();
        result.warnings.push(ValidationWarning {
            code: "OBJECT_STREAMS_FOUND".to_string(),
            message: format!("Document uses {} object stream(s)", objstm_count),
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            recommendation: Some("Object streams can obscure document structure modifications".to_string()),
        });
    }

    // Check for cross-reference streams
    if content.contains("/Type /XRef") {
        result.warnings.push(ValidationWarning {
            code: "XREF_STREAMS_FOUND".to_string(),
            message: "Document uses cross-reference streams".to_string(),
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            recommendation: Some("XRef streams may indicate PDF 1.5+ features or optimization".to_string()),
        });
    }

    Ok(())
}

/// Detect version inconsistencies
fn detect_version_inconsistencies(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Look for version inconsistencies
    let version_count = content.matches("%PDF-").count();
    if version_count > 1 {
        result.warnings.push(ValidationWarning {
            code: "MULTIPLE_VERSION_HEADERS".to_string(),
            message: format!("Found {} PDF version headers", version_count),
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            recommendation: Some("Multiple version headers may indicate document assembly".to_string()),
        });

        // Extract and compare versions
        extract_and_compare_versions(content, result)?;
    }

    Ok(())
}

/// Extract and compare versions
fn extract_and_compare_versions(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    let version_regex = Regex::new(r"%PDF-(\d+)\.(\d+)").unwrap();
    let versions: Vec<_> = version_regex.captures_iter(content).collect();

    if versions.len() > 1 {
        let first_version = format!("{}.{}", &versions[0][1], &versions[0][2]);
        for (i, version_match) in versions.iter().enumerate().skip(1) {
            let current_version = format!("{}.{}", &version_match[1], &version_match[2]);
            if current_version != first_version {
                result.warnings.push(ValidationWarning {
                    code: "VERSION_MISMATCH".to_string(),
                    message: format!("Version mismatch: header {} has version {}, but first header has {}", 
                                   i + 1, current_version, first_version),
                    location: Some(ErrorLocation::FileStructure { offset: 0 }),
                    recommendation: Some("Version mismatches may indicate merged documents".to_string()),
                });
            }
        }
    }

    Ok(())
}

/// Detect timestamp anomalies
fn detect_timestamp_anomalies(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Check for suspicious metadata timestamps
    if content.contains("/CreationDate") && content.contains("/ModDate") {
        result.warnings.push(ValidationWarning {
            code: "TIMESTAMP_ANALYSIS_NEEDED".to_string(),
            message: "Document contains creation and modification timestamps".to_string(),
            location: Some(ErrorLocation::Metadata { field: "timestamps".to_string() }),
            recommendation: Some("Compare timestamps to detect potential backdating or modification".to_string()),
        });

        // Analyze timestamp patterns
        analyze_timestamp_patterns(content, result)?;
    }

    Ok(())
}

/// Analyze timestamp patterns
fn analyze_timestamp_patterns(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Look for timestamp format patterns
    let timestamp_patterns = [
        "D:",  // PDF timestamp format
        "Z",   // UTC timezone indicator
        "+",   // Timezone offset positive
        "-",   // Timezone offset negative
    ];

    for pattern in &timestamp_patterns {
        if content.contains(&format!("/CreationDate({}*", pattern)) || 
           content.contains(&format!("/ModDate({}*", pattern)) {
            result.warnings.push(ValidationWarning {
                code: "TIMESTAMP_FORMAT_DETECTED".to_string(),
                message: format!("Timestamp format pattern '{}' detected", pattern),
                location: Some(ErrorLocation::Metadata { field: "timestamp_format".to_string() }),
                recommendation: Some("Timestamp format analysis may reveal creation tool information".to_string()),
            });
        }
    }

    Ok(())
}

/// Validate standard encryption parameters
fn validate_standard_encryption(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Check for required standard encryption fields
    if !content.contains("/V") {
        result.errors.push(ValidationError {
            code: "ENCRYPT_VERSION_MISSING".to_string(),
            message: "Standard encryption missing version (/V)".to_string(),
            severity: ErrorSeverity::Major,
            location: Some(ErrorLocation::Security),
            suggested_fix: Some("Encryption dictionary must specify version".to_string()),
        });
    } else {
        validate_encryption_version(content, result)?;
    }

    if !content.contains("/R") {
        result.errors.push(ValidationError {
            code: "ENCRYPT_REVISION_MISSING".to_string(),
            message: "Standard encryption missing revision (/R)".to_string(),
            severity: ErrorSeverity::Major,
            location: Some(ErrorLocation::Security),
            suggested_fix: Some("Encryption dictionary must specify revision".to_string()),
        });
    } else {
        validate_encryption_revision(content, result)?;
    }

    // Check for user/owner password entries
    if content.contains("/U") && content.contains("/O") {
        result.warnings.push(ValidationWarning {
            code: "PASSWORD_PROTECTION_FOUND".to_string(),
            message: "Document has user and owner password protection".to_string(),
            location: Some(ErrorLocation::Security),
            recommendation: Some("Password-protected documents require authentication for full analysis".to_string()),
        });

        validate_password_entries(content, result)?;
    }

    // Check for permissions
    if content.contains("/P") {
        validate_permission_flags(content, result)?;
    }

    Ok(())
}

/// Validate encryption version
fn validate_encryption_version(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    if let Some(v_pos) = content.find("/V") {
        let after_v = &content[v_pos + 2..];
        if let Some(version_value) = extract_numeric_value(after_v) {
            match version_value {
                1 => result.warnings.push(ValidationWarning {
                    code: "ENCRYPTION_V1".to_string(),
                    message: "Document uses RC4 40-bit encryption (V1)".to_string(),
                    location: Some(ErrorLocation::Security),
                    recommendation: Some("V1 encryption is weak by modern standards".to_string()),
                }),
                2 => result.warnings.push(ValidationWarning {
                    code: "ENCRYPTION_V2".to_string(),
                    message: "Document uses RC4 variable-length encryption (V2)".to_string(),
                    location: Some(ErrorLocation::Security),
                    recommendation: Some("V2 encryption provides variable key length".to_string()),
                }),
                4 => result.warnings.push(ValidationWarning {
                    code: "ENCRYPTION_V4".to_string(),
                    message: "Document uses security handler-specific encryption (V4)".to_string(),
                    location: Some(ErrorLocation::Security),
                    recommendation: Some("V4 encryption uses custom security handlers".to_string()),
                }),
                5 => result.warnings.push(ValidationWarning {
                    code: "ENCRYPTION_V5".to_string(),
                    message: "Document uses AES encryption (V5)".to_string(),
                    location: Some(ErrorLocation::Security),
                    recommendation: Some("V5 encryption uses modern AES algorithm".to_string()),
                }),
                _ => result.warnings.push(ValidationWarning {
                    code: "ENCRYPTION_UNKNOWN_VERSION".to_string(),
                    message: format!("Document uses unknown encryption version: {}", version_value),
                    location: Some(ErrorLocation::Security),
                    recommendation: Some("Unknown encryption version may require specialized handling".to_string()),
                }),
            }
        }
    }
    Ok(())
}

/// Validate encryption revision
fn validate_encryption_revision(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    if let Some(r_pos) = content.find("/R") {
        let after_r = &content[r_pos + 2..];
        if let Some(revision_value) = extract_numeric_value(after_r) {
            if revision_value < 2 || revision_value > 6 {
                result.warnings.push(ValidationWarning {
                    code: "ENCRYPTION_UNUSUAL_REVISION".to_string(),
                    message: format!("Unusual encryption revision: {}", revision_value),
                    location: Some(ErrorLocation::Security),
                    recommendation: Some("Non-standard revision may indicate custom encryption".to_string()),
                });
            }
        }
    }
    Ok(())
}

/// Validate password entries
fn validate_password_entries(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Check user password entry format
    if let Some(u_pos) = content.find("/U") {
        let after_u = &content[u_pos..];
        if let Some(hex_start) = after_u.find('<') {
            if let Some(hex_end) = after_u[hex_start..].find('>') {
                let hex_data = &after_u[hex_start+1..hex_start+hex_end];
                if hex_data.len() != 64 { // 32 bytes = 64 hex chars
                    result.warnings.push(ValidationWarning {
                        code: "USER_PASSWORD_UNUSUAL_LENGTH".to_string(),
                        message: format!("User password entry has unusual length: {} hex chars", hex_data.len()),
                        location: Some(ErrorLocation::Security),
                        recommendation: Some("Standard user password entries are typically 32 bytes".to_string()),
                    });
                }
            }
        }
    }

    // Check owner password entry format
    if let Some(o_pos) = content.find("/O") {
        let after_o = &content[o_pos..];
        if let Some(hex_start) = after_o.find('<') {
            if let Some(hex_end) = after_o[hex_start..].find('>') {
                let hex_data = &after_o[hex_start+1..hex_start+hex_end];
                if hex_data.len() != 64 { // 32 bytes = 64 hex chars
                    result.warnings.push(ValidationWarning {
                        code: "OWNER_PASSWORD_UNUSUAL_LENGTH".to_string(),
                        message: format!("Owner password entry has unusual length: {} hex chars", hex_data.len()),
                        location: Some(ErrorLocation::Security),
                        recommendation: Some("Standard owner password entries are typically 32 bytes".to_string()),
                    });
                }
            }
        }
    }

    Ok(())
}

/// Validate permission flags
fn validate_permission_flags(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    if let Some(p_pos) = content.find("/P") {
        let after_p = &content[p_pos + 2..];
        if let Some(perm_str) = after_p.split_whitespace().next() {
            if let Ok(permissions) = perm_str.parse::<i32>() {
                // Analyze permission bits
                let can_print = (permissions & 4) != 0;
                let can_modify = (permissions & 8) != 0;
                let can_copy = (permissions & 16) != 0;
                let can_add_notes = (permissions & 32) != 0;

                let mut restricted_ops = Vec::new();
                if !can_print { restricted_ops.push("printing"); }
                if !can_modify { restricted_ops.push("modification"); }
                if !can_copy { restricted_ops.push("copying"); }
                if !can_add_notes { restricted_ops.push("annotations"); }

                if !restricted_ops.is_empty() {
                    result.warnings.push(ValidationWarning {
                        code: "DOCUMENT_PERMISSIONS_RESTRICTED".to_string(),
                        message: format!("Document restricts: {}", restricted_ops.join(", ")),
                        location: Some(ErrorLocation::Security),
                        recommendation: Some("Permission restrictions may affect forensic analysis capabilities".to_string()),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Validate public key encryption parameters
fn validate_public_key_encryption(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    // Check for recipients array
    if !content.contains("/Recipients") {
        result.errors.push(ValidationError {
            code: "PKI_RECIPIENTS_MISSING".to_string(),
            message: "Public key encryption missing recipients".to_string(),
            severity: ErrorSeverity::Major,
            location: Some(ErrorLocation::Security),
            suggested_fix: Some("PKI encryption must specify recipients".to_string()),
        });
    } else {
        validate_recipients_array(content, result)?;
    }

    result.warnings.push(ValidationWarning {
        code: "PKI_ENCRYPTION_FOUND".to_string(),
        message: "Document uses public key infrastructure encryption".to_string(),
        location: Some(ErrorLocation::Security),
        recommendation: Some("PKI encryption requires certificate validation".to_string()),
    });

    // Check for encryption method
    if content.contains("/Adobe.PPKLite") {
        result.warnings.push(ValidationWarning {
            code: "PPKLITE_HANDLER".to_string(),
            message: "Document uses Adobe PPKLite security handler".to_string(),
            location: Some(ErrorLocation::Security),
            recommendation: Some("PPKLite is the standard PKI handler for PDF".to_string()),
        });
    } else if content.contains("/Adobe.PPKMS") {
        result.warnings.push(ValidationWarning {
            code: "PPKMS_HANDLER".to_string(),
            message: "Document uses Adobe PPKMS security handler".to_string(),
            location: Some(ErrorLocation::Security),
            recommendation: Some("PPKMS provides enhanced PKI capabilities".to_string()),
        });
    }

    Ok(())
}

/// Validate recipients array
fn validate_recipients_array(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    if let Some(recipients_pos) = content.find("/Recipients") {
        let after_recipients = &content[recipients_pos..];
        if let Some(array_start) = after_recipients.find('[') {
            if let Some(array_end) = after_recipients[array_start..].find(']') {
                let array_content = &after_recipients[array_start+1..array_start+array_end];

                // Count hex strings (each represents a recipient)
                let recipient_count = array_content.matches('<').count();
                if recipient_count == 0 {
                    result.errors.push(ValidationError {
                        code: "PKI_NO_RECIPIENTS".to_string(),
                        message: "Recipients array is empty".to_string(),
                        severity: ErrorSeverity::Major,
                        location: Some(ErrorLocation::Security),
                        suggested_fix: Some("PKI encryption must have at least one recipient".to_string()),
                    });
                } else {
                    result.warnings.push(ValidationWarning {
                        code: "PKI_RECIPIENTS_COUNT".to_string(),
                        message: format!("Document encrypted for {} recipient(s)", recipient_count),
                        location: Some(ErrorLocation::Security),
                        recommendation: Some("Multiple recipients may indicate document distribution".to_string()),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Validate signature byte range
fn validate_signature_byte_range(content: &str, result: &mut ValidationResult) -> PdfResult<()> {
    if let Some(byterange_pos) = content.find("/ByteRange") {
        let after_byterange = &content[byterange_pos..];

        if let Some(array_start) = after_byterange.find('[') {
            if let Some(array_end) = after_byterange[array_start..].find(']') {
                let array_content = &after_byterange[array_start+1..array_start+array_end];

                // Count numeric values in ByteRange
                let numbers: Vec<&str> = array_content.split_whitespace().collect();
                if numbers.len() != 4 {
                    result.errors.push(ValidationError {
                        code: "BYTERANGE_INVALID_FORMAT".to_string(),
                        message: format!("ByteRange must contain 4 values, found {}", numbers.len()),
                        severity: ErrorSeverity::Major,
                        location: Some(ErrorLocation::Security),
                        suggested_fix: Some("ByteRange format: [offset1 length1 offset2 length2]".to_string()),
                    });
                } else {
                    validate_byterange_values(&numbers, result)?;
                }
            }
        }
    }

    Ok(())
}

/// Validate byterange values
fn validate_byterange_values(numbers: &[&str], result: &mut ValidationResult) -> PdfResult<()> {
    let mut values = Vec::new();

    // Validate that all values are numeric and collect them
    for (i, num_str) in numbers.iter().enumerate() {
        if let Ok(value) = num_str.parse::<u64>() {
            values.push(value);
        } else {
            result.errors.push(ValidationError {
                code: "BYTERANGE_NON_NUMERIC".to_string(),
                message: format!("ByteRange value {} is not numeric: {}", i+1, num_str),
                severity: ErrorSeverity::Major,
                location: Some(ErrorLocation::Security),
                suggested_fix: Some("All ByteRange values must be integers".to_string()),
            });
            return Ok(());
        }
    }

    if values.len() == 4 {
        // Analyze ByteRange structure
        let start1 = values[0];
        let length1 = values[1];
        let start2 = values[2];
        let _length2 = values[3];

        // Check for typical signature ByteRange pattern
        if start1 != 0 {
            result.warnings.push(ValidationWarning {
                code: "BYTERANGE_UNUSUAL_START".to_string(),
                message: format!("ByteRange does not start at 0: starts at {}", start1),
                location: Some(ErrorLocation::Security),
                recommendation: Some("Signatures typically cover document from beginning".to_string()),
            });
        }

        let gap_start = start1 + length1;
        let gap_size = start2 - gap_start;

        if gap_size == 0 {
            result.errors.push(ValidationError {
                code: "BYTERANGE_NO_SIGNATURE_SPACE".to_string(),
                message: "ByteRange leaves no space for signature content".to_string(),
                severity: ErrorSeverity::Major,
                location: Some(ErrorLocation::Security),
                suggested_fix: Some("Signature must have space reserved in Contents field".to_string()),
            });
        } else if gap_size > 65536 { // More than 64KB for signature
            result.warnings.push(ValidationWarning {
                code: "BYTERANGE_LARGE_SIGNATURE_SPACE".to_string(),
                message: format!("Large signature space reserved: {} bytes", gap_size),
                location: Some(ErrorLocation::Security),
                recommendation: Some("Unusually large signature space may indicate special signature type".to_string()),
            });
        }
    }

    Ok(())
}

/// Determine overall validation status based on issues
fn determine_validation_status(result: &mut ValidationResult) {
    let has_critical = result.errors.iter().any(|e| e.severity == ErrorSeverity::Critical);
    let has_major = result.errors.iter().any(|e| e.severity == ErrorSeverity::Major);

    result.is_valid = !has_critical && !has_major;

    // Update forensic match confidence based on issues
    if let Some(ref mut forensic_match) = result.forensic_match {
        let error_count = result.errors.len();
        let warning_count = result.warnings.len();

        // Reduce confidence based on issues found
        let confidence_reduction = (error_count as f64 * 0.1) + (warning_count as f64 * 0.02);
        forensic_match.confidence = (forensic_match.confidence - confidence_reduction).max(0.0);
        forensic_match.non_matching_elements.push(format!("Errors: {}, Warnings: {}", error_count, warning_count));

        // Update match details
        if has_critical {
            forensic_match.matching_elements.push("Critical validation errors found".to_string());
        } else if has_major {
            forensic_match.matching_elements.push("Major validation issues found".to_string());
        } else if warning_count > 0 {
            forensic_match.matching_elements.push(format!("Validation completed with {} warnings", warning_count));
        } else {
            forensic_match.matching_elements.push("Complete validation match with no issues".to_string());
        }
    }
}

/// Parse PDF version string
fn parse_pdf_version(version_str: &str) -> Result<PdfVersion, ()> {
    let parts: Vec<&str> = version_str.trim().split('.').collect();
    if parts.len() == 2 {
        if let (Ok(major), Ok(minor)) = (parts[0].parse::<u8>(), parts[1].parse::<u8>()) {
            let header_bytes = format!("%PDF-{}.{}", major, minor).into_bytes();
            return Ok(PdfVersion { 
                major, 
                minor,
                header_bytes,
                header_offset: 0,
                header_comments: Vec::new(),
            });
        }
    }
    Err(())
}

/// Search for binary markers in data
fn search_for_binary_markers(data: &[u8], search_start: usize, result: &mut ValidationResult) -> PdfResult<()> {
    let binary_patterns: [&[u8]; 9] = [b"startxref", b"xref", b"trailer", b"%%EOF", b"obj", b"endobj", b"stream", b"endstream", b"null"];
    let mut found_markers = 0;

    for pattern in &binary_patterns {
        if data[search_start..].windows(pattern.len()).any(|window| window == *pattern) {
            found_markers += 1;
        }
    }

    if found_markers > 0 {
        result.warnings.push(ValidationWarning {
            code: "BINARY_MARKERS_FOUND".to_string(),
            message: format!("Found {} PDF markers in binary data", found_markers),
            location: Some(ErrorLocation::FileStructure { offset: search_start as u64 }),
            recommendation: Some("File structure may be recoverable despite encoding issues".to_string()),
        });
    }

    Ok(())
}

/// Validate EOF marker integrity
fn validate_eof_marker_integrity(data: &[u8], search_start: usize, result: &mut ValidationResult) -> PdfResult<()> {
    let eof_pattern = b"%%EOF";
    if let Some(eof_pos) = data[search_start..].windows(eof_pattern.len()).position(|window| window == eof_pattern) {
        let actual_eof_pos = search_start + eof_pos;

        // Check if EOF is properly terminated
        if actual_eof_pos + eof_pattern.len() < data.len() {
            let remaining = &data[actual_eof_pos + eof_pattern.len()..];
            let non_whitespace = remaining.iter().any(|&b| !b.is_ascii_whitespace());

            if non_whitespace {
                result.warnings.push(ValidationWarning {
                    code: "EOF_NOT_TERMINAL".to_string(),
                    message: "Content found after %%EOF marker".to_string(),
                    location: Some(ErrorLocation::FileStructure { offset: actual_eof_pos as u64 }),
                    recommendation: Some("File may have been modified or concatenated".to_string()),
                });
            }
        }
    }

    Ok(())
}

/// Attempt xref reconstruction
fn attempt_xref_reconstruction(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    if let Ok(content) = std::str::from_utf8(data) {
        let xref_count = content.matches("xref").count();
        let object_regex = regex::Regex::new(r"\d+ \d+ obj").unwrap();
        let object_count = object_regex.find_iter(content).count();

        if xref_count == 0 && object_count > 0 {
            result.warnings.push(ValidationWarning {
                code: "MISSING_XREF_TABLE".to_string(),
                message: format!("Found {} objects but no xref table", object_count),
                location: Some(ErrorLocation::FileStructure { offset: 0 }),
                recommendation: Some("File may use cross-reference streams (PDF 1.5+)".to_string()),
            });
        }
    }

    Ok(())
}

/// Validate object boundary markers
fn validate_object_boundary_markers(data: &[u8], result: &mut ValidationResult) -> PdfResult<()> {
    if let Ok(content) = std::str::from_utf8(data) {
        let obj_regex = regex::Regex::new(r"(\d+) (\d+) obj").unwrap();
        let endobj_count = content.matches("endobj").count();
        let obj_matches: Vec<_> = obj_regex.find_iter(content).collect();

        if obj_matches.len() != endobj_count {
            result.errors.push(ValidationError {
                code: "OBJECT_BOUNDARY_MISMATCH".to_string(),
                message: format!("Found {} 'obj' markers but {} 'endobj' markers", obj_matches.len(), endobj_count),
                severity: ErrorSeverity::Major,
                location: Some(ErrorLocation::FileStructure { offset: 0 }),
                suggested_fix: Some("Objects may be malformed or corrupted".to_string()),
            });
        }
    }

    Ok(())
}

/// Validate xref offset bounds
fn validate_xref_offset_bounds(xref_offset: u64, file_size: u64, result: &mut ValidationResult) -> PdfResult<()> {
    if xref_offset >= file_size {
        result.errors.push(ValidationError {
            code: "XREF_OFFSET_OUT_OF_BOUNDS".to_string(),
            message: format!("XRef offset {} exceeds file size {}", xref_offset, file_size),
            severity: ErrorSeverity::Critical,
            location: Some(ErrorLocation::XRef { entry: xref_offset as u32 as u32 }),
            suggested_fix: Some("File is corrupted or truncated".to_string()),
        });
    } else if xref_offset > file_size - 100 {
        result.warnings.push(ValidationWarning {
            code: "XREF_OFFSET_NEAR_EOF".to_string(),
            message: format!("XRef offset {} is very close to end of file", xref_offset),
            location: Some(ErrorLocation::XRef { entry: xref_offset as u32 as u32 }),
            recommendation: Some("Limited space for xref table data".to_string()),
        });
    }

    Ok(())
}

/// Check EOF trailing content
fn check_eof_trailing_content(content: &str, result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    if let Some(eof_pos) = content.rfind("%%EOF") {
        let after_eof = &content[eof_pos + 5..];
        let trimmed = after_eof.trim();

        if !trimmed.is_empty() {
            result.warnings.push(ValidationWarning {
                code: "CONTENT_AFTER_EOF".to_string(),
                message: format!("Found {} bytes of content after %%EOF", trimmed.len()),
                location: Some(ErrorLocation::FileStructure { offset: offset + eof_pos as u64 + 5 }),
                recommendation: Some("May indicate file concatenation or modification".to_string()),
            });
        }
    }

    Ok(())
}

/// Validate trailer entries
fn validate_trailer_entries(trailer_content: &str, result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    let required_entries = ["/Size", "/Root"];
    let optional_entries = ["/Prev", "/Info", "/ID", "/Encrypt"];

    for entry in &required_entries {
        if !trailer_content.contains(entry) {
            result.errors.push(ValidationError {
                code: "MISSING_TRAILER_ENTRY".to_string(),
                message: format!("Required trailer entry {} not found", entry),
                severity: ErrorSeverity::Critical,
                location: Some(ErrorLocation::Trailer),
                suggested_fix: Some("Trailer dictionary is incomplete".to_string()),
            });
        }
    }

    for entry in &optional_entries {
        if trailer_content.contains(entry) {
            result.validation_stats.references_validated += 1;
        }
    }

    Ok(())
}

/// Validate trailer references
fn validate_trailer_references(trailer_content: &str, result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    // Extract and validate object references in trailer
    let ref_regex = regex::Regex::new(r"(\d+) (\d+) R").unwrap();
    let references: Vec<_> = ref_regex.find_iter(trailer_content).collect();

    for ref_match in references {
        let ref_str = ref_match.as_str();
        if let Some(caps) = ref_regex.captures(ref_str) {
            if let (Ok(obj_num), Ok(gen_num)) = (caps[1].parse::<u32>(), caps[2].parse::<u16>()) {
                if obj_num == 0 {
                    result.warnings.push(ValidationWarning {
                        code: "ZERO_OBJECT_REFERENCE".to_string(),
                        message: "Trailer contains reference to object 0".to_string(),
                        location: Some(ErrorLocation::Trailer),
                        recommendation: Some("Object 0 is typically reserved for free entries".to_string()),
                    });
                }

                if gen_num > 65535 {
                    result.warnings.push(ValidationWarning {
                        code: "HIGH_GENERATION_NUMBER".to_string(),
                        message: format!("Very high generation number {} in trailer", gen_num),
                        location: Some(ErrorLocation::Trailer),
                        recommendation: Some("May indicate document with many updates".to_string()),
                    });
                }
            }
        }
    }

    Ok(())
}





/// Validate individual object
fn validate_individual_object(content: &str, obj_start: usize, result: &mut ValidationResult, obj_index: usize) -> PdfResult<()> {
    let remaining = &content[obj_start..];
    if let Some(endobj_pos) = remaining.find("endobj") {
        let obj_content = &remaining[..endobj_pos];

        // Check for stream objects
        if obj_content.contains("stream") {
            validate_stream_object(obj_content, result, obj_start as u64)?;
            result.validation_stats.streams_validated += 1;
        }

        // Validate object dictionary
        if obj_content.contains("<<") && obj_content.contains(">>") {
            validate_object_dictionary(obj_content, result, obj_start as u64)?;
        }
    } else {
        result.errors.push(ValidationError {
            code: "OBJECT_NO_ENDOBJ".to_string(),
            message: format!("Object {} missing 'endobj' keyword", obj_index),
            severity: ErrorSeverity::Major,
            location: Some(ErrorLocation::FileStructure { offset: obj_index as u64 }),
            suggested_fix: Some("Object may be truncated or malformed".to_string()),
        });
    }

    Ok(())
}

/// Validate stream object
fn validate_stream_object(obj_content: &str, result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    if let Some(stream_start) = obj_content.find("stream") {
        if let Some(endstream_pos) = obj_content.find("endstream") {
            let stream_data = &obj_content[stream_start + 6..endstream_pos];

            // Basic stream validation
            if stream_data.trim().is_empty() {
                result.warnings.push(ValidationWarning {
                    code: "EMPTY_STREAM".to_string(),
                    message: "Found empty stream object".to_string(),
                    location: Some(ErrorLocation::Stream { stream_ref: ObjectReference { number: 0, generation: 0 } }),
                    recommendation: Some("Empty streams are valid but unusual".to_string()),
                });
            }
        } else {
            result.errors.push(ValidationError {
                code: "STREAM_NO_ENDSTREAM".to_string(),
                message: "Stream missing 'endstream' keyword".to_string(),
                severity: ErrorSeverity::Major,
                location: Some(ErrorLocation::Stream { stream_ref: ObjectReference { number: 0, generation: 0 } }),
                suggested_fix: Some("Stream may be truncated".to_string()),
            });
        }
    }

    Ok(())
}

/// Validate object dictionary
fn validate_object_dictionary(obj_content: &str, result: &mut ValidationResult, offset: u64) -> PdfResult<()> {
    let dict_start = obj_content.find("<<").unwrap();
    let dict_end = obj_content.rfind(">>").unwrap();
    let dict_content = &obj_content[dict_start + 2..dict_end];

    // Count dictionary entries
    let entry_count = dict_content.matches('/').count();
    if entry_count == 0 {
        result.warnings.push(ValidationWarning {
            code: "EMPTY_DICTIONARY".to_string(),
            message: "Found empty object dictionary".to_string(),
            location: Some(ErrorLocation::FileStructure { offset: 0 }),
            recommendation: Some("Empty dictionaries are valid but unusual".to_string()),
        });
    }

    Ok(())
}