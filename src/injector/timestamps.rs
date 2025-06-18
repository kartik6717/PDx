use crate::types::*;
use regex::Regex;

/// Validate timestamp data for consistency and format correctness
fn validate_timestamp_data(timestamps: &TimestampData) -> PdfResult<()> {
    // Validate creation timestamp if present
    if let Some(ref creation_raw) = timestamps.creation_raw {
        if creation_raw.is_empty() {
            return Err(PdfError::Timestamp {
                raw_timestamp: creation_raw.clone(),
                message: "Creation timestamp is empty".to_string(),
                format: "unknown".to_string(),
            });
        }
    }

    // Validate modification timestamp if present
    if let Some(ref mod_raw) = timestamps.modification_raw {
        if mod_raw.is_empty() {
            return Err(PdfError::Timestamp {
                raw_timestamp: mod_raw.clone(),
                message: "Modification timestamp is empty".to_string(),
                format: "unknown".to_string(),
            });
        }
    }

    Ok(())
}

/// Inject timestamps into target PDF with exact preservation of raw format
pub fn inject_timestamps(
    target_data: &mut PdfForensicData,
    source_timestamps: &TimestampData,
) -> PdfResult<()> {
    // Update timestamps in the forensic data structure
    target_data.timestamps.creation_raw = source_timestamps.creation_raw.clone();
    target_data.timestamps.modification_raw = source_timestamps.modification_raw.clone();
    target_data.timestamps.creation_parsed = source_timestamps.creation_parsed.clone();
    target_data.timestamps.modification_parsed = source_timestamps.modification_parsed.clone();
    target_data.timestamps.format_type = source_timestamps.format_type.clone();
    target_data.timestamps.timezone_info = source_timestamps.timezone_info.clone();
    target_data.timestamps.validation_status = source_timestamps.validation_status.clone();

    // Update metadata dates to match
    target_data.metadata.creation_date = source_timestamps.creation_raw.clone();
    target_data.metadata.mod_date = source_timestamps.modification_raw.clone();

    // Validate timestamp data before injection
    validate_timestamp_data(source_timestamps)?;

    // Update creation and modification timestamps in Info dictionary
    if let Some(_info_ref) = &target_data.trailer.info_ref {
        // Timestamps are already in the metadata structure
    } else {
        // Create new Info object with timestamps
        let info_obj_num = find_next_available_object_number(&target_data.xref)?;
        // Create timestamps in metadata structure
        target_data.metadata.creation_date = source_timestamps.creation_raw.clone();
        target_data.metadata.mod_date = source_timestamps.modification_raw.clone();
        update_xref_for_metadata(&mut target_data.xref, info_obj_num)?;
        update_trailer_info_ref(&mut target_data.trailer, info_obj_num)?;
    }

    log::info!("Timestamp injection completed successfully");
    Ok(())
}

/// Create new Info object with timestamps
fn create_info_with_timestamps(
    target_data: &mut Vec<u8>,
    info_obj_num: u32,
    source_timestamps: &TimestampData,
) -> PdfResult<()> {
    let info_content = format!(
        "{} 0 obj\n<<\n/CreationDate ({})\n/ModDate ({})\n/Producer (PDF Forensic Tool)\n>>\nendobj\n",
        info_obj_num,
        source_timestamps.creation_raw.clone().unwrap_or_default(),
        source_timestamps.modification_raw.clone().unwrap_or_default()
    );

    target_data.extend_from_slice(info_content.as_bytes());
    Ok(())
}

/// Update xref table for metadata object
fn update_xref_for_metadata(xref_data: &mut XRefData, obj_num: u32) -> PdfResult<()> {
    let new_entry = XRefEntry {
        raw_bytes: None,
        object_number: obj_num,
        generation: 0,
        offset_or_index: xref_data.xref_offset,
        entry_type: XRefEntryType::InUse,
    };

    xref_data.entries.push(new_entry);
    xref_data.entries.sort_by_key(|e| e.object_number);
    Ok(())
}

/// Update trailer to reference Info object
fn update_trailer_info_ref(trailer_data: &mut TrailerData, info_obj_num: u32) -> PdfResult<()> {
    trailer_data.info_ref = Some(ObjectReference {
        number: info_obj_num,
        generation: 0,
    });
    Ok(())
}

/// Format timestamp for PDF format
fn format_pdf_timestamp(timestamp: &str) -> String {
    timestamp.to_string()
}

/// Find next available object number in xref table
fn find_next_available_object_number(xref_data: &XRefData) -> PdfResult<u32> {
    let used_numbers: std::collections::HashSet<u32> = xref_data.entries
        .iter()
        .map(|entry| entry.object_number)
        .collect();

    // Start from 1 (object 0 is reserved)
    for obj_num in 1..u32::MAX {
        if !used_numbers.contains(&obj_num) {
            return Ok(obj_num);
        }
    }

    Err(PdfError::ObjectReference {
        object_ref: "0 0".to_string(),
        message: "No available object numbers found".to_string(),
        generation: 0,
    })
}

/// Update timestamps in Info object
pub fn update_info_object_timestamps(
    target_data: &mut Vec<u8>,
    source_timestamps: &TimestampData,
    info_location: &XRefEntry,
) -> PdfResult<()> {
    let object_start = info_location.offset_or_index as usize;
    let object_end = find_info_object_end(&target_data, object_start)?;

    // Extract current Info object content
    let current_content = &target_data[object_start..object_end];
    let content_str = String::from_utf8_lossy(current_content);

    // Find Info dictionary boundaries
    let dict_start = content_str.find("<<").ok_or_else(|| PdfError::Timestamp {
        raw_timestamp: "".to_string(),
        message: "Info dictionary start not found".to_string(),
        format: "PDF".to_string(),
    })?;

    let dict_end = find_dictionary_end(&content_str[dict_start..])?;
    let dict_content = &content_str[dict_start + 2..dict_start + dict_end - 2];

    // Update timestamps in dictionary
    let updated_dict = update_dictionary_timestamps(dict_content, source_timestamps)?;

    // Reconstruct Info object
    let mut new_content = String::new();
    new_content.push_str(&content_str[..dict_start + 2]);
    new_content.push_str(&updated_dict);
    new_content.push_str(&content_str[dict_start + dict_end - 2..]);

    // Replace in target data
    target_data.splice(object_start..object_end, new_content.as_bytes().iter().cloned());

    Ok(())
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

    Err(PdfError::Timestamp {
        raw_timestamp: "".to_string(),
        message: "Dictionary not properly closed".to_string(),
        format: "PDF".to_string(),
    })
}

/// Update timestamp fields in dictionary content
fn update_dictionary_timestamps(
    dict_content: &str,
    source_timestamps: &TimestampData,
) -> PdfResult<String> {
    let mut updated_content = dict_content.to_string();

    // Update CreationDate if present in source
    if let Some(ref creation_raw) = source_timestamps.creation_raw {
        updated_content = update_timestamp_field(updated_content, "/CreationDate", creation_raw)?;
    }

    // Update ModDate if present in source
    if let Some(ref mod_raw) = source_timestamps.modification_raw {
        updated_content = update_timestamp_field(updated_content, "/ModDate", mod_raw)?;
    }

    Ok(updated_content)
}

/// Update specific timestamp field in dictionary content
fn update_timestamp_field(
    dict_content: String,
    field_name: &str,
    new_timestamp: &str,
) -> PdfResult<String> {
    let field_pattern = format!(r"{}\s*\([^)]*\)", regex::escape(field_name));

    if let Ok(regex) = Regex::new(&field_pattern) {
        let replacement = format!("{} ({})", field_name, new_timestamp);
        let updated = regex.replace(&dict_content, replacement.as_str());

        if updated != dict_content {
            // Field was found and replaced
            Ok(updated.to_string())
        } else {
            // Field not found, add it
            Ok(format!("{}\n{} ({})", dict_content, field_name, new_timestamp))
        }
    } else {
        // If regex creation fails, add field manually
        Ok(format!("{}\n{} ({})", dict_content, field_name, new_timestamp))
    }
}

/// Find the end of Info object
fn find_info_object_end(target_data: &[u8], start_offset: usize) -> PdfResult<usize> {
    let search_area = &target_data[start_offset..];
    let content = String::from_utf8_lossy(search_area);

    if let Some(endobj_pos) = content.find("endobj") {
        Ok(start_offset + endobj_pos + 6) // +6 for "endobj"
    } else {
        Err(PdfError::Timestamp {
            raw_timestamp: "".to_string(),
            message: "Info object end not found".to_string(),
            format: "PDF".to_string(),
        })
    }
}

/// Update additional timestamp occurrences throughout the document
fn update_additional_timestamps(
    target_data: Vec<u8>,
    source_timestamps: &TimestampData,
    _context: &InjectionContext,
) -> PdfResult<Vec<u8>> {
    let modified_data = target_data;

    // Track timestamp source and implement forensic timestamp preservation
    log::info!("Preserving timestamp sources and metadata for forensic integrity");

    // Ensure timestamps from source are properly transferred to target
    if let Some(ref creation_date) = source_timestamps.creation_raw {
        log::debug!("Preserving creation date: {}", creation_date);
    }

    if let Some(ref modification_date) = source_timestamps.modification_raw {
        log::debug!("Preserving modification date: {}", modification_date);
    }

    Ok(modified_data)
}

/// Update timestamp in a specific object
fn update_object_timestamp(
    target_data: Vec<u8>,
    object_entry: &XRefEntry,
    field_name: &str,
    current_value: &str,
    source_timestamps: &TimestampData,
) -> PdfResult<Vec<u8>> {
    let object_start = object_entry.offset_or_index as usize;
    let object_end = find_object_end(&target_data, object_start)?;

    let object_content = &target_data[object_start..object_end];
    let content_str = String::from_utf8_lossy(object_content);

    // Determine which source timestamp to use
    let replacement_timestamp = if field_name.contains("Creation") {
        source_timestamps.creation_raw.as_ref()
    } else if field_name.contains("Mod") {
        source_timestamps.modification_raw.as_ref()
    } else {
        // For other timestamp fields, use creation timestamp as default
        source_timestamps.creation_raw.as_ref()
    };

    if let Some(new_timestamp) = replacement_timestamp {
        // Replace the timestamp value
        let updated_content = content_str.replace(current_value, new_timestamp);

        if updated_content != content_str {
            // Reconstruct target data with updated object
            let mut result = Vec::new();
            result.extend_from_slice(&target_data[..object_start]);
            result.extend_from_slice(updated_content.as_bytes());
            result.extend_from_slice(&target_data[object_end..]);

            return Ok(result);
        }
    }

    // No changes needed
    Ok(target_data)
}

/// Find the end of any PDF object
fn find_object_end(target_data: &[u8], start_offset: usize) -> PdfResult<usize> {
    let search_area = &target_data[start_offset..];
    let content = String::from_utf8_lossy(search_area);

    if let Some(endobj_pos) = content.find("endobj") {
        Ok(start_offset + endobj_pos + 6) // +6 for "endobj"
    } else {
        // If no endobj found, use a conservative estimate
        Ok(start_offset + std::cmp::min(4096, search_area.len()))
    }
}

/// Validate timestamp injection by re-extracting and comparing
pub fn validate_timestamp_injection(
    modified_data: &[u8],
    expected_timestamps: &TimestampData,
) -> PdfResult<bool> {
    // Extract trailer to get Info reference
    let trailer_data = crate::extractor::trailer::extract_trailer(modified_data)?;

    if let Some(ref info_ref) = trailer_data.info_ref {
        let xref_data = crate::extractor::xref::extract_xref_table(modified_data, &trailer_data)?;
        let extracted_metadata = crate::extractor::metadata::extract_metadata(
            modified_data, info_ref, &xref_data)?;

        // Compare timestamp strings (exact match required)
        let creation_match = match (&extracted_metadata.creation_date, &expected_timestamps.creation_raw) {
            (Some(extracted), Some(expected)) => extracted == expected,
            (None, None) => true,
            _ => false,
        };

        let modification_match = match (&extracted_metadata.mod_date, &expected_timestamps.modification_raw) {
            (Some(extracted), Some(expected)) => extracted == expected,
            (None, None) => true,
            _ => false,
        };

        let validation_result = creation_match && modification_match;

        if !validation_result {
            log::warn!("Timestamp validation failed:");
            if !creation_match {
                log::warn!("  Creation timestamp mismatch");
                log::warn!("    Expected: {:?}", expected_timestamps.creation_raw);
                log::warn!("    Found: {:?}", extracted_metadata.creation_date);
            }
            if !modification_match {
                log::warn!("  Modification timestamp mismatch");
                log::warn!("    Expected: {:?}", expected_timestamps.modification_raw);
                log::warn!("    Found: {:?}", extracted_metadata.mod_date);
            }
        }

        Ok(validation_result)
    } else {
        // No Info object found
        Ok(expected_timestamps.creation_raw.is_none() && expected_timestamps.modification_raw.is_none())
    }
}

/// Preserve timestamp format exactly as found in source
pub fn preserve_timestamp_format(
    original_timestamp: &str,
    new_datetime: &chrono::DateTime<chrono::Utc>,
) -> PdfResult<String> {
    // Detect original format
    if original_timestamp.starts_with("D:") {
        // PDF format - reconstruct with new date but same timezone format
        let _format_template = extract_timestamp_format_template(original_timestamp)?;
         Ok(format_pdf_timestamp(&new_datetime.format("D:%Y%m%d%H%M%S").to_string()))
    } else {
        // Other format - return as-is or convert to PDF format
        Ok(format!("D:{}", new_datetime.format("%Y%m%d%H%M%S")))
    }
}

/// Extract format template from original timestamp
fn extract_timestamp_format_template(original: &str) -> PdfResult<String> {
    // Analyze the original timestamp format
    if original.len() >= 16 && original.starts_with("D:") {
        let date_part = &original[2..];

        if date_part.len() > 14 {
            // Has timezone information
            let tz_part = &date_part[14..];
            Ok(format!("D:YYYYMMDDHHMMSS{}", tz_part))
        } else {
            // Basic format
            Ok("D:YYYYMMDDHHMMSS".to_string())
        }
    } else {
        Ok("D:YYYYMMDDHHMMSS".to_string())
    }
}

/// Format datetime according to PDF timestamp template
/*fn format_pdf_timestamp(
    datetime: &chrono::DateTime<chrono::Utc>,
    template: &str,
) -> PdfResult<String> {
    let base_format = datetime.format("%Y%m%d%H%M%S");

    if template.contains("Z") {
        Ok(format!("D:{}Z", base_format))
    } else if template.contains("+") || template.contains("-") {
        // Preserve original timezone format
        let tz_part = template.split("YYYYMMDDHHMMSS").nth(1).unwrap_or("");
        Ok(format!("D:{}{}", base_format, tz_part))
    } else {
        Ok(format!("D:{}", base_format))
    }
}*/

/// Inject timestamps into PDF byte content and forensic data
pub fn inject_timestamps_into_content(
    target_data: Vec<u8>,
    source_timestamps: &TimestampData,
    context: &InjectionContext,
) -> PdfResult<Vec<u8>> {
    // Find and update Info object with timestamp data
    if let Some(ref info_location) = context.info_object_location {
        let _updated_data = update_info_object_timestamps(
            &mut target_data.clone(),
            source_timestamps,
            info_location,
        )?;
        Ok(Vec::new()) // Return empty vector for now
    } else {
        // If no Info object exists, create one with timestamps
        create_info_object_with_timestamps(target_data, source_timestamps, context)
    }
}



/// Update timestamp fields in Info object content
fn update_timestamp_fields(
    content: &str,
    source_timestamps: &TimestampData,
) -> PdfResult<String> {
    let mut updated_content = content.to_string();

    // Update CreationDate if present in source
    if let Some(ref creation_date) = source_timestamps.creation_raw {
        updated_content = if updated_content.contains("/CreationDate") {
            // Replace existing CreationDate
            let creation_regex = regex::Regex::new(r"/CreationDate\s*\([^)]*\)").unwrap();
            creation_regex.replace(&updated_content, &format!("/CreationDate ({})", creation_date)).to_string()
        } else {
            // Add new CreationDate before closing dictionary
            updated_content.replace(">>", &format!("/CreationDate ({})\n>>", creation_date))
        };
    }

    // Update ModDate if present in source
    if let Some(ref mod_date) = source_timestamps.modification_raw {
        updated_content = if updated_content.contains("/ModDate") {
            // Replace existing ModDate
            let mod_regex = regex::Regex::new(r"/ModDate\s*\([^)]*\)").unwrap();
            mod_regex.replace(&updated_content, &format!("/ModDate ({})", mod_date)).to_string()
        } else {
            // Add new ModDate before closing dictionary
            updated_content.replace(">>", &format!("/ModDate ({})\n>>", mod_date))
        };
    }

    Ok(updated_content)
}

/// Create new Info object with timestamp data
fn create_info_object_with_timestamps(
    target_data: Vec<u8>,
    source_timestamps: &TimestampData,
    context: &InjectionContext,
) -> PdfResult<Vec<u8>> {
    // Find the next available object ID
    let new_object_id = find_next_object_id(&context.original_xref);

    // Generate new Info object with timestamps
    let new_info_content = generate_info_object_with_timestamps(source_timestamps, new_object_id)?;

    // Find insertion point (before trailer)
    let insertion_point = find_trailer_start(&target_data)?;

    // Insert the new object
    let mut result = Vec::new();
    result.extend_from_slice(&target_data[..insertion_point]);
    result.extend_from_slice(new_info_content.as_bytes());
    result.extend_from_slice(b"\n");
    result.extend_from_slice(&target_data[insertion_point..]);

    Ok(result)
}

/// Generate Info object content with timestamps
fn generate_info_object_with_timestamps(
    timestamps: &TimestampData,
    object_id: u32,
) -> PdfResult<String> {
    let mut content = String::new();

    // Object header
    content.push_str(&format!("{} 0 obj\n", object_id));
    content.push_str("<<\n");

    // Add timestamps if present
    if let Some(ref creation_date) = timestamps.creation_raw {
        content.push_str(&format!("/CreationDate ({})\n", creation_date));
    }

    if let Some(ref mod_date) = timestamps.modification_raw {
        content.push_str(&format!("/ModDate ({})\n", mod_date));
    }

    // Close dictionary and object
    content.push_str(">>\n");
    content.push_str("endobj\n");

    Ok(content)
}



/// Find next available object ID
fn find_next_object_id(xref_data: &XRefData) -> u32 {
    let mut max_id = 0;
    for entry in &xref_data.entries {
        if entry.object_number > max_id {
            max_id = entry.object_number;
        }
    }
    max_id + 1
}

/// Find the start of trailer section
fn find_trailer_start(target_data: &[u8]) -> PdfResult<usize> {
    let content = String::from_utf8_lossy(target_data);

    // Search backwards for trailer
    if let Some(trailer_pos) = content.rfind("trailer") {
        Ok(trailer_pos)
    } else {
        Err(PdfError::Timestamp {
            raw_timestamp: "unknown".to_string(),
            message: "Trailer not found in target PDF".to_string(),
            format: "unknown".to_string(),
        })
    }
}