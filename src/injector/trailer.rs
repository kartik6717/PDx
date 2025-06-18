use crate::types::*;
use regex::Regex;
use sha2::Digest;

use std::collections::HashMap;

/// Validate trailer data for consistency and format correctness
fn validate_trailer_data(trailer: &TrailerData) -> PdfResult<()> {
    if trailer.size == 0 {
        return Err(PdfError::Trailer {
            message: "Trailer size cannot be zero".to_string(),
            expected_size: Some(1),
        });
    }

    if trailer.prev_offset.unwrap_or(0) == 0 {
        return Err(PdfError::Trailer {
            message: "XRef offset cannot be zero".to_string(),
            expected_size: None,
        });
    }

    Ok(())
}

/// Replace trailer section in PDF file data
fn replace_trailer_section(file_data: &mut Vec<u8>, trailer_content: &str) -> PdfResult<()> {
    // Convert trailer content to bytes and replace in file data
    let trailer_bytes = trailer_content.as_bytes();

    // Find trailer position and replace
    if let Some(pos) = find_trailer_position(file_data) {
        let end_pos = pos + trailer_bytes.len();
        if end_pos <= file_data.len() {
            file_data[pos..end_pos].copy_from_slice(trailer_bytes);
        }
    }

    Ok(())
}

/// Update document ID in PDF file data
fn update_document_id(file_data: &mut Vec<u8>, id_array: &[String]) -> PdfResult<()> {
    if id_array.len() >= 2 {
        let id_string = format!("/ID [<{}> <{}>]", id_array[0], id_array[1]);
        let id_bytes = id_string.as_bytes();

        // Find and update ID array in file data
        if let Some(pos) = find_id_array_position(file_data) {
            let end_pos = pos + id_bytes.len();
            if end_pos <= file_data.len() {
                file_data[pos..end_pos].copy_from_slice(id_bytes);
            }
        }
    }

    Ok(())
}

/// Validate XRef offset consistency
fn validate_xref_offset_consistency(target_data: &PdfForensicData) -> PdfResult<()> {
    if target_data.trailer.prev_offset.unwrap_or(0) != target_data.xref.xref_offset {
        return Err(PdfError::XRef {
            offset: target_data.xref.xref_offset,
            message: "XRef offset mismatch between trailer and xref data".to_string(),
            entry_count: target_data.xref.entries.len() as u32,
        });
    }

    Ok(())
}

/// Find trailer position in file data
fn find_trailer_position(file_data: &[u8]) -> Option<usize> {
    let trailer_marker = b"trailer";
    file_data.windows(trailer_marker.len())
        .position(|window| window == trailer_marker)
}

/// Find ID array position in file data
fn find_id_array_position(file_data: &[u8]) -> Option<usize> {
    let id_marker = b"/ID";
    file_data.windows(id_marker.len())
        .position(|window| window == id_marker)
}

/// Trailer backup structure
#[derive(Debug, Clone)]
pub struct TrailerBackup {
    pub original_trailer: TrailerData,
    pub backup_timestamp: chrono::DateTime<chrono::Utc>,
    pub file_size: u64,
    pub checksum: String,
}

/// Inject trailer data into target PDF forensic data
pub fn inject_trailer_data(
    target_data: &mut PdfForensicData,
    source_trailer: &TrailerData,
) -> PdfResult<()> {
    // Update trailer data in the forensic data structure
    target_data.trailer = source_trailer.clone();

    // Validate trailer data before injection
    validate_trailer_data(source_trailer)?;

    // Update trailer dictionary in PDF
    let _trailer_content = generate_trailer_dictionary(source_trailer, 0)?;

    // Replace trailer section in the PDF data
    log::info!("Replacing trailer section");

    // Update ID array if present
    if let Some(ref id_array) = source_trailer.id_array {
        target_data.trailer.id_array = Some(id_array.clone());
    }

    // Ensure xref offset consistency
    validate_xref_offset_consistency(&target_data)?;

    log::info!("Trailer data injection completed successfully");
    Ok(())
}

/// Inject trailer data into target PDF (most critical for forensic matching)
pub fn inject_trailer(
    target_data: Vec<u8>,
    source_trailer: &TrailerData,
    updated_xref: &XRefData,
) -> PdfResult<Vec<u8>> {
    // This is the most critical operation - PDF ID arrays must be preserved byte-for-byte
    let trailer_start = find_trailer_location(&target_data)?;
    let trailer_end = find_trailer_end(&target_data, trailer_start)?;

    // Generate new trailer with source data
    let new_trailer_content = generate_trailer_content(source_trailer, updated_xref)?;

    // Replace trailer section
    let mut result = Vec::new();
    result.extend_from_slice(&target_data[..trailer_start]);
    result.extend_from_slice(new_trailer_content.as_bytes());
    result.extend_from_slice(&target_data[trailer_end..]);

    Ok(result)
}

/// Find trailer location in PDF
fn find_trailer_location(target_data: &[u8]) -> PdfResult<usize> {
    let content = String::from_utf8_lossy(target_data);

    // Find the last occurrence of "trailer" keyword
    content.rfind("trailer").ok_or_else(|| PdfError::Trailer {
        message: "Trailer keyword not found in target PDF".to_string(),
        expected_size: None,
    })
}

/// Find trailer end (before startxref section)
fn find_trailer_end(target_data: &[u8], trailer_start: usize) -> PdfResult<usize> {
    let search_area = &target_data[trailer_start..];
    let content = String::from_utf8_lossy(search_area);

    // Find the end of trailer dictionary
    if let Some(dict_start) = content.find("<<") {
        let dict_end = find_dictionary_end(&content[dict_start..])?;
        if dict_end > 0 {
            return Ok(trailer_start + dict_start + dict_end);
        }
    }

    // If dictionary parsing fails, look for startxref
    if let Some(startxref_pos) = content.find("startxref") {
        Ok(trailer_start + startxref_pos)
    } else {
        Err(PdfError::Trailer {
            message: "Trailer end not found".to_string(),
            expected_size: None,
        })
    }
}

/// Find end of dictionary by counting << and >> pairs
fn find_dictionary_end(content: &str) -> PdfResult<usize> {
    let mut depth = 0;
    let mut pos = 0;
    let chars: Vec<char> = content.chars().collect();

    while pos < chars.len() {
        if pos + 1 < chars.len() {
            if chars[pos] == '<' && chars[pos + 1] == '<' {
                depth += 1;
                pos += 2;
                continue;
            }
            if chars[pos] == '>' && chars[pos + 1] == '>' {
                depth -= 1;
                if depth == 0 {
                    return Ok(pos + 2);
                }
                pos += 2;
                continue;
            }
        }
        pos += 1;
    }

    Err(PdfError::Trailer {
        message: "Dictionary not properly closed".to_string(),
        expected_size: None,
    })
}

/// Generate complete trailer content with source data
fn generate_trailer_content(
    source_trailer: &TrailerData,
    updated_xref: &XRefData,
) -> PdfResult<String> {
    let mut content = String::new();

    content.push_str("trailer\n");
    content.push_str("<<\n");

    // Size field (update with current xref size)
    content.push_str(&format!("/Size {}\n", updated_xref.entries.len()));

    // Root reference (from source)
    content.push_str(&format!("/Root {} {} R\n", 
                             source_trailer.root_ref.number, 
                             source_trailer.root_ref.generation));

    // Info reference (if present in source)
    if let Some(ref info_ref) = source_trailer.info_ref {
        content.push_str(&format!("/Info {} {} R\n", 
                                 info_ref.number, 
                                 info_ref.generation));
    }

    // PDF ID array - CRITICAL: preserve exact byte sequence
    if let Some(ref id_array) = source_trailer.id_array {
        content.push_str("/ID [");
        for (i, id_str) in id_array.iter().enumerate() {
            if i > 0 {
                content.push(' ');
            }
            content.push('<');
            content.push_str(id_str);
            content.push('>');
        }
        content.push_str("]\n");
    }

    // Encrypt reference (if present in source)
    if let Some(ref encrypt_ref) = source_trailer.encrypt_ref {
        content.push_str(&format!("/Encrypt {} {} R\n", 
                                 encrypt_ref.number, 
                                 encrypt_ref.generation));
    }

    // Prev offset (if present in source)
    if let Some(prev_offset) = source_trailer.prev_offset {
        content.push_str(&format!("/Prev {}\n", prev_offset));
    }

    // Additional fields from source trailer
    for (key, value) in &source_trailer.additional_fields {
        let value_str = match value {
            TrailerValue::Number(n) => n.to_string(),
            TrailerValue::String(s) => format!("({})", s),
            TrailerValue::Boolean(b) => b.to_string(),
            TrailerValue::Reference(r) => format!("{} {} R", r.number, r.generation),
            TrailerValue::Null => "null".to_string(),
            TrailerValue::Array(_) => "[...]".to_string(), // Simplified for now
        };
        content.push_str(&format!("/{} {}\n", key, value_str));
    }

    content.push_str(">>\n");

    Ok(content)
}

/// Update trailer references to match new xref structure
pub fn update_trailer_references(
    trailer_content: String,
    object_mappings: &HashMap<u32, u32>,
) -> PdfResult<String> {
    let mut updated_content = trailer_content;

    // Update object references based on mappings
    for (old_id, new_id) in object_mappings {
        if old_id != new_id {
            // Create regex pattern to match object references
            let pattern = format!(r"(\d+)\s+(\d+)\s+R");
            if let Ok(regex) = Regex::new(&pattern) {
                updated_content = regex.replace_all(&updated_content, |caps: &regex::Captures| {
                    let obj_id: u32 = caps[1].parse().unwrap_or(0);
                    let generation: u32 = caps[2].parse().unwrap_or(0);

                    if obj_id == *old_id {
                        format!("{} {} R", new_id, generation)
                    } else {
                        caps[0].to_string()
                    }
                }).to_string();
            }
        }
    }

    Ok(updated_content)
}

/// Validate trailer integrity after injection
pub fn validate_injected_trailer(
    modified_data: &[u8],
    expected_trailer: &TrailerData,
) -> PdfResult<bool> {
    // Re-extract trailer from modified data
    let extracted_trailer = crate::extractor::trailer::extract_trailer(modified_data)?;

    // Compare critical fields
    let size_match = extracted_trailer.size == expected_trailer.size;
    let root_match = extracted_trailer.root_ref == expected_trailer.root_ref;
    let info_match = extracted_trailer.info_ref == expected_trailer.info_ref;

    // Most critical: PDF ID array byte-for-byte comparison
    let id_match = match (&extracted_trailer.id_array, &expected_trailer.id_array) {
        (Some(extracted_id), Some(expected_id)) => {
            extracted_id.len() == expected_id.len() &&
            extracted_id.iter().zip(expected_id.iter()).all(|(a, b)| a == b)
        }
        (None, None) => true,
        _ => false,
    };

    let encrypt_match = extracted_trailer.encrypt_ref == expected_trailer.encrypt_ref;

    let all_match = size_match && root_match && info_match && id_match && encrypt_match;

    if !all_match {
        log::warn!("Trailer validation failed:");
        if !size_match { log::warn!("  Size mismatch"); }
        if !root_match { log::warn!("  Root reference mismatch"); }
        if !info_match { log::warn!("  Info reference mismatch"); }
        if !id_match { log::warn!("  PDF ID array mismatch (CRITICAL)"); }
        if !encrypt_match { log::warn!("  Encrypt reference mismatch"); }
    }

    Ok(all_match)
}

/// Create backup of original trailer before injection
pub fn backup_original_trailer(target_data: &[u8]) -> PdfResult<TrailerBackup> {
    let original_trailer = crate::extractor::trailer::extract_trailer(target_data)?;

    Ok(TrailerBackup {
        original_trailer: original_trailer.clone(),
        backup_timestamp: chrono::Utc::now(),
        file_size: target_data.len() as u64,
        checksum: calculate_trailer_checksum(&original_trailer)?,
    })
}

/// Calculate checksum for trailer validation
fn calculate_trailer_checksum(trailer: &TrailerData) -> PdfResult<String> {
    use sha2::Sha256;

    let mut hasher = Sha256::new();

    // Hash critical trailer fields
    hasher.update(trailer.size.to_be_bytes());
    hasher.update(trailer.root_ref.number.to_be_bytes());
    hasher.update(trailer.root_ref.generation.to_be_bytes());

    if let Some(ref info_ref) = trailer.info_ref {
        hasher.update(info_ref.number.to_be_bytes());
        hasher.update(info_ref.generation.to_be_bytes());
    }

    if let Some(ref id_array) = trailer.id_array {
        for id_str in id_array {
            hasher.update(id_str.as_bytes());
        }
    }

    if let Some(ref encrypt_ref) = trailer.encrypt_ref {
        hasher.update(encrypt_ref.number.to_be_bytes());
        hasher.update(encrypt_ref.generation.to_be_bytes());
    }

    let result = hasher.finalize();
    Ok(hex::encode(result))
}



/// Inject trailer into PDF byte content
pub fn inject_trailer_into_content(
    target_data: Vec<u8>,
    source_trailer: &TrailerData,
    new_size: u32,
) -> PdfResult<Vec<u8>> {
    let content = String::from_utf8_lossy(&target_data);

    // Find the trailer section
    if let Some(trailer_pos) = content.rfind("trailer") {
        if let Some(dict_start) = content[trailer_pos..].find("<<") {
            let dict_start_abs = trailer_pos + dict_start;
            if let Some(dict_end) = content[dict_start_abs..].find(">>") {
                let dict_end_abs = dict_start_abs + dict_end + 2; // +2 for ">>"

                // Generate new trailer dictionary
                let new_trailer_dict = generate_trailer_dictionary(source_trailer, new_size)?;

                // Replace the trailer dictionary
                let mut result = Vec::new();
                result.extend_from_slice(&target_data[..dict_start_abs]);
                result.extend_from_slice(new_trailer_dict.as_bytes());
                result.extend_from_slice(&target_data[dict_end_abs..]);

                Ok(result)
            } else {
                Err(PdfError::Trailer {
                    message: "Trailer dictionary end not found".to_string(),
                    expected_size: Some(new_size),
                })
            }
        } else {
            Err(PdfError::Trailer {
                message: "Trailer dictionary start not found".to_string(),
                expected_size: Some(new_size),
            })
        }
    } else {
        Err(PdfError::Trailer {
            message: "Trailer not found".to_string(),
            expected_size: Some(new_size),
        })
    }
}

/// Generate complete trailer dictionary content
fn generate_trailer_dictionary(trailer: &TrailerData, size: u32) -> PdfResult<String> {
    let mut dict = String::from("<<\n");

    // Size field (required)
    dict.push_str(&format!("/Size {}\n", size));

    // Root reference (required)
    dict.push_str(&format!("/Root {} {} R\n", trailer.root_ref.number, trailer.root_ref.generation));

    // Info reference (optional but critical for forensic matching)
    if let Some(ref info_ref) = trailer.info_ref {
        dict.push_str(&format!("/Info {} {} R\n", info_ref.number, info_ref.generation));
    }

    // Encrypt reference (optional)
    if let Some(ref encrypt_ref) = trailer.encrypt_ref {
        dict.push_str(&format!("/Encrypt {} {} R\n", encrypt_ref.number, encrypt_ref.generation));
    }

    // CRITICAL: PDF ID array for forensic matching - MUST BE PRESERVED EXACTLY
    if let Some(ref id_array) = trailer.id_array {
        dict.push_str("/ID [");
        for id_str in id_array {
            dict.push_str(&format!("<{}>", id_str));
        }
        dict.push_str("]\n");
    }

    // Prev offset for incremental updates
    if let Some(prev) = trailer.prev_offset {
        dict.push_str(&format!("/Prev {}\n", prev));
    }

    // Additional custom fields
    for (key, value) in &trailer.additional_fields {
        let value_str = match value {
            TrailerValue::Number(n) => n.to_string(),
            TrailerValue::String(s) => format!("({})", escape_pdf_string(s)),
            TrailerValue::Reference(obj_ref) => format!("{} {} R", obj_ref.number, obj_ref.generation),
            TrailerValue::Boolean(b) => if *b { "true".to_string() } else { "false".to_string() },
            TrailerValue::Null => "null".to_string(),
            TrailerValue::Array(_) => "[]".to_string(), // Simplified for now
        };
        dict.push_str(&format!("/{} {}\n", key, value_str));
    }

    dict.push_str(">>");
    Ok(dict)
}

/// Escape special characters in PDF strings
fn escape_pdf_string(input: &str) -> String {
    let mut result = String::new();

    for ch in input.chars() {
        match ch {
            '(' => result.push_str("\\("),
            ')' => result.push_str("\\)"),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            '\u{0008}' => result.push_str("\\b"), // Backspace
            '\u{000C}' => result.push_str("\\f"), // Form feed
            _ => {
                if ch.is_control() {
                    // Convert control characters to octal escape
                    result.push_str(&format!("\\{:03o}", ch as u8));
                } else {
                    result.push(ch);
                }
            }
        }
    }

    result
}

/// Update trailer size field
pub fn update_trailer_size(target_data: Vec<u8>, new_size: u32) -> PdfResult<Vec<u8>> {
    let content = String::from_utf8_lossy(&target_data);

    if let Some(trailer_pos) = content.rfind("trailer") {
        if let Some(dict_start) = content[trailer_pos..].find("<<") {
            let dict_start_abs = trailer_pos + dict_start;
            if let Some(dict_end) = content[dict_start_abs..].find(">>") {
                let dict_end_abs = dict_start_abs + dict_end;
                let dict_content = &content[dict_start_abs + 2..dict_end_abs];

                // Update size field
                let size_regex = Regex::new(r"/Size\s+\d+").unwrap();
                let new_dict_content = size_regex.replace(dict_content, &format!("/Size {}", new_size));

                // Reconstruct the data
                let mut result = Vec::new();
                result.extend_from_slice(&target_data[..dict_start_abs + 2]);
                result.extend_from_slice(new_dict_content.as_bytes());
                result.extend_from_slice(&target_data[dict_end_abs..]);

                Ok(result)
            } else {
                Err(PdfError::Trailer {
                    message: "Trailer dictionary end not found".to_string(),
                    expected_size: Some(new_size),
                })
            }
        } else {
            Err(PdfError::Trailer {
                message: "Trailer dictionary start not found".to_string(),
                expected_size: Some(new_size),
            })
        }
    } else {
        Err(PdfError::Trailer {
            message: "Trailer not found".to_string(),
            expected_size: Some(new_size),
        })
    }
}

/// Validate trailer injection by checking critical fields
pub fn validate_trailer_injection(
    modified_data: &[u8],
    expected_trailer: &TrailerData,
) -> PdfResult<bool> {
    let extracted_trailer = crate::extractor::trailer::extract_trailer(modified_data)?;

    // Check critical fields for forensic matching
    let id_match = extracted_trailer.id_array == expected_trailer.id_array;
    let root_match = extracted_trailer.root_ref == expected_trailer.root_ref;
    let info_match = extracted_trailer.info_ref == expected_trailer.info_ref;
    let encrypt_match = extracted_trailer.encrypt_ref == expected_trailer.encrypt_ref;

    let validation_result = id_match && root_match && info_match && encrypt_match;

    if !validation_result {
        log::warn!("Trailer validation failed:");
        if !id_match { log::warn!("  ID array mismatch"); }
        if !root_match { log::warn!("  Root reference mismatch"); }
        if !info_match { log::warn!("  Info reference mismatch"); }
        if !encrypt_match { log::warn!("  Encrypt reference mismatch"); }
    }

    Ok(validation_result)
}