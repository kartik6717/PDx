/// Extract cross-reference table data from PDF
pub fn extract_xref_table(
    file_data: &[u8], 
    trailer_data: &TrailerData,
) -> PdfResult<XRefData> {
    // Determine xref location from trailer
    let xref_offset = find_xref_offset(file_data)?;

    // Determine xref type and extract accordingly
    let xref_type = determine_xref_type(file_data, xref_offset)?;

    match xref_type {
        XRefType::Table => extract_traditional_xref(file_data, xref_offset, trailer_data),
        XRefType::Stream => extract_xref_stream(file_data, xref_offset, trailer_data),
        XRefType::Hybrid => extract_hybrid_xref(file_data, xref_offset, trailer_data),
    }
}

/// Find cross-reference table offset from startxref
fn find_xref_offset(file_data: &[u8]) -> PdfResult<u64> {
    // Search backwards from end for "startxref"
    let search_start = if file_data.len() > 1024 { file_data.len() - 1024 } else { 0 };
    let search_area = &file_data[search_start..];

    let content = std::str::from_utf8(search_area).map_err(|e| PdfError::XRef {
        offset: search_start as u64,
        message: format!("Invalid UTF-8 in startxref area: {}", e),
        entry_count: 0,
    })?;

    let startxref_pos = content.rfind("startxref").ok_or_else(|| PdfError::XRef {
        offset: search_start as u64,
        message: "startxref keyword not found".to_string(),
        entry_count: 0,
    })?;

    // Extract offset number after startxref
    let offset_start = startxref_pos + "startxref".len();
    let offset_str = content[offset_start..].lines().next().ok_or_else(|| PdfError::XRef {
        offset: search_start as u64 + startxref_pos as u64,
        message: "No offset line after startxref".to_string(),
        entry_count: 0,
    })?.trim();

    let xref_offset: u64 = offset_str.parse().map_err(|e| PdfError::XRef {
        offset: search_start as u64 + startxref_pos as u64,
        message: format!("Invalid xref offset '{}': {}", offset_str, e),
        entry_count: 0,
    })?;

    Ok(xref_offset)
}

/// Determine whether xref is traditional table or stream
fn determine_xref_type(file_data: &[u8], offset: u64) -> PdfResult<XRefType> {
    let start = offset as usize;
    if start >= file_data.len() {
        return Err(PdfError::XRef {
            offset,
            message: "XRef offset beyond file size".to_string(),
            entry_count: 0,
        });
    }

    let search_area = &file_data[start..std::cmp::min(start + 100, file_data.len())];
    let content = std::str::from_utf8(search_area).map_err(|e| PdfError::XRef {
        offset,
        message: format!("Invalid UTF-8 at xref location: {}", e),
        entry_count: 0,
    })?;

    if content.trim_start().starts_with("xref") {
        Ok(XRefType::Table)
    } else {
        Ok(XRefType::Stream)
    }
}

/// Extract traditional xref table
fn extract_traditional_xref(
    file_data: &[u8], 
    offset: u64, 
    _trailer_data: &TrailerData
) -> PdfResult<XRefData> {
    let start = offset as usize;

    // Read enough data to contain the entire xref table
    let end_pos = find_xref_table_end(file_data, start)?;
    let xref_content = &file_data[start..end_pos];

    let content = std::str::from_utf8(xref_content).map_err(|e| PdfError::XRef {
        offset,
        message: format!("Invalid UTF-8 in xref table: {}", e),
        entry_count: 0,
    })?;

    let lines: Vec<&str> = content.lines().collect();

    if lines.is_empty() || lines[0].trim() != "xref" {
        return Err(PdfError::XRef {
            offset,
            message: "XRef table does not start with 'xref'".to_string(),
            entry_count: 0,
        });
    }

    let mut entries = Vec::new();
    let mut line_idx = 1;
    let mut total_entries = 0;

    // Parse subsections
    while line_idx < lines.len() {
        let line = lines[line_idx].trim();

        if line.starts_with("trailer") {
            break;
        }

        // Parse subsection header: start_num count
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 2 {
            return Err(PdfError::XRef {
                offset: offset + calculate_line_offset(&lines, line_idx),
                message: format!("Invalid subsection header: {}", line),
                entry_count: total_entries,
            });
        }

        let start_num: u32 = parts[0].parse().map_err(|e| PdfError::XRef {
            offset: offset + calculate_line_offset(&lines, line_idx),
            message: format!("Invalid start number '{}': {}", parts[0], e),
            entry_count: total_entries,
        })?;

        let count: u32 = parts[1].parse().map_err(|e| PdfError::XRef {
            offset: offset + calculate_line_offset(&lines, line_idx),
            message: format!("Invalid count '{}': {}", parts[1], e),
            entry_count: total_entries,
        })?;

        line_idx += 1;

        // Parse entries in this subsection
        for entry_idx in 0..count {
            if line_idx >= lines.len() {
                return Err(PdfError::XRef {
                    offset,
                    message: format!("XRef table truncated at entry {}", entry_idx),
                    entry_count: total_entries,
                });
            }

            let entry_line = lines[line_idx].trim();
            let entry = parse_xref_entry(entry_line, start_num + entry_idx, offset)?;
            entries.push(entry);

            line_idx += 1;
            total_entries += 1;
        }
    }

    Ok(XRefData {
        xref_type: XRefType::Table,
        entries,
        subsections: Vec::new(), // Could be populated with subsection info
        xref_offset: offset,
        raw_xref_bytes: Vec::new(),
        stream_dict: None,
        hybrid_info: None,
        trailer: _trailer_data.clone(),
    })
}

/// Find the end of xref table by looking for "trailer"
fn find_xref_table_end(file_data: &[u8], start: usize) -> PdfResult<usize> {
    let search_area = &file_data[start..];
    let content = std::str::from_utf8(search_area).map_err(|e| PdfError::XRef {
        offset: start as u64,
        message: format!("Invalid UTF-8 in xref search area: {}", e),
        entry_count: 0,
    })?;

    if let Some(trailer_pos) = content.find("trailer") {
        Ok(start + trailer_pos)
    } else {
        // If no trailer found, read until end of file or reasonable limit
        Ok(std::cmp::min(start + 50000, file_data.len()))
    }
}

/// Calculate byte offset of a line within the lines array
fn calculate_line_offset(lines: &[&str], line_idx: usize) -> u64 {
    let mut offset = 0u64;
    for i in 0..line_idx {
        if i < lines.len() {
            offset += lines[i].len() as u64 + 1; // +1 for newline
        }
    }
    offset
}

/// Parse individual xref entry
fn parse_xref_entry(entry_line: &str, object_number: u32, base_offset: u64) -> PdfResult<XRefEntry> {
    let parts: Vec<&str> = entry_line.split_whitespace().collect();

    if parts.len() != 3 {
        return Err(PdfError::XRef {
            offset: base_offset,
            message: format!("Invalid xref entry format: {}", entry_line),
            entry_count: 0,
        });
    }

    let offset: u64 = parts[0].parse().map_err(|e| PdfError::XRef {
        offset: base_offset,
        message: format!("Invalid offset in xref entry: {}", e),
        entry_count: 0,
    })?;

    let generation: u16 = parts[1].parse().map_err(|e| PdfError::XRef {
        offset: base_offset,
        message: format!("Invalid generation in xref entry: {}", e),
        entry_count: 0,
    })?;

    let entry_type = match parts[2] {
        "n" => XRefEntryType::InUse,
        "f" => XRefEntryType::Free,
        _ => return Err(PdfError::XRef {
            offset: base_offset,
            message: format!("Invalid flag in xref entry: {}", parts[2]),
            entry_count: 0,
        }),
    };

    Ok(XRefEntry {
        object_number,
        generation,
        offset_or_index: offset,
        entry_type,
        raw_bytes: Some(entry_line.as_bytes().to_vec()),
    })
}

/// Extract xref stream (PDF 1.5+)
fn extract_xref_stream(
    file_data: &[u8], 
    offset: u64, 
    _trailer_data: &TrailerData
) -> PdfResult<XRefData> {
    let _start = offset as usize;

    // For now, return a basic structure for xref streams
    // Full implementation would require stream decompression and parsing
    let entries = Vec::new();

    Ok(XRefData {
        xref_type: XRefType::Stream,
        entries,
        subsections: extract_xref_subsections(file_data, offset)?,
        xref_offset: offset,
        raw_xref_bytes: extract_raw_xref_bytes(file_data, offset)?,
        stream_dict: None,
        hybrid_info: None,
        trailer: _trailer_data.clone(),
    })
}

/// Extract hybrid xref (both table and stream)
fn extract_hybrid_xref(
    file_data: &[u8], 
    offset: u64, 
    trailer_data: &TrailerData
) -> PdfResult<XRefData> {
    // For hybrid, try table first, then stream
    match extract_traditional_xref(file_data, offset, trailer_data) {
        Ok(mut xref_data) => {
            xref_data.xref_type = XRefType::Hybrid;
            Ok(xref_data)
        }
        Err(_) => {
            let mut xref_data = extract_xref_stream(file_data, offset, trailer_data)?;
            xref_data.xref_type = XRefType::Hybrid;
            Ok(xref_data)
        }
    }
}
use crate::types::*;
// use std::collections::HashMap;

fn extract_xref_subsections(_file_data: &[u8], _offset: u64) -> PdfResult<Vec<XRefSubsection>> {
    Ok(Vec::new()) // Placeholder implementation
}

fn extract_raw_xref_bytes(_file_data: &[u8], _offset: u64) -> PdfResult<Vec<u8>> {
    Ok(Vec::new()) // Placeholder implementation
}

fn find_startxref_offset(
    file_data: &[u8], 
    _trailer_data: &TrailerData
) -> PdfResult<u64> {
    // Search from end of file backwards for "startxref"
    let search_start = if file_data.len() > 2048 { file_data.len() - 2048 } else { 0 };
    let search_area = &file_data[search_start..];

    let content = std::str::from_utf8(search_area).map_err(|e| PdfError::XRef {
        offset: search_start as u64,
        message: format!("Invalid UTF-8 in trailer area: {}", e),
        entry_count: 0,
    })?;

    // Find the last occurrence of "startxref"
    let startxref_pos = content.rfind("startxref").ok_or_else(|| PdfError::XRef {
        offset: search_start as u64,
        message: "startxref keyword not found".to_string(),
        entry_count: 0,
    })?;

    // Extract the number following startxref
    let after_startxref = &content[startxref_pos + "startxref".len()..];
    let lines: Vec<&str> = after_startxref.lines().collect();

    for line in &lines {
        let trimmed = line.trim();
        if !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_digit()) {
            return trimmed.parse::<u64>().map_err(|e| PdfError::XRef {
                offset: search_start as u64 + startxref_pos as u64,
                message: format!("Invalid startxref offset: {}", e),
                entry_count: 0,
            });
        }
    }

    Err(PdfError::XRef {
        offset: search_start as u64 + startxref_pos as u64,
        message: "No valid offset found after startxref".to_string(),
        entry_count: 0,
    })
}

fn validate_xref_table_integrity(
    file_data: &[u8], 
    xref_data: &XRefData
) -> PdfResult<()> {
    // Validate that all in-use entries point to valid object locations
    for entry in &xref_data.entries {
        if let XRefEntryType::InUse = entry.entry_type {
            let offset = entry.offset_or_index as usize;

            // Check if offset is within file bounds
            if offset >= file_data.len() {
                return Err(PdfError::XRef {
                    offset: offset as u64,
                    message: format!("Object {} offset {} beyond file size {}", 
                                   entry.object_number, offset, file_data.len()),
                    entry_count: xref_data.entries.len() as u32,
                });
            }

            // Check if there's a valid object at this location
            let remaining = &file_data[offset..];
            let content = String::from_utf8_lossy(&remaining[..std::cmp::min(100, remaining.len())]);

            // Look for object header pattern: "n g obj"
            let expected_header = format!("{} {} obj", entry.object_number, entry.generation);
            if !content.contains(&expected_header) {
                return Err(PdfError::XRef {
                    offset: offset as u64,
                    message: format!("Object {} {} not found at offset {}", 
                                   entry.object_number, entry.generation, offset),
                    entry_count: xref_data.entries.len() as u32,
                });
            }
        }
    }

    // Validate that object numbers are sequential or have reasonable gaps
    let mut object_numbers: Vec<u32> = xref_data.entries.iter()
        .filter(|e| matches!(e.entry_type, XRefEntryType::InUse))
        .map(|e| e.object_number)
        .collect();

    object_numbers.sort();

    // Check for unreasonable gaps (more than 1000 objects)
    for window in object_numbers.windows(2) {
        if window[1] - window[0] > 1000 {
            return Err(PdfError::XRef {
                offset: xref_data.xref_offset,
                message: format!("Large gap in object numbering: {} to {}", window[0], window[1]),
                entry_count: xref_data.entries.len() as u32,
            });
        }
    }

    // Validate xref table integrity
    validate_xref_table_integrity(file_data, xref_data)?;

    // Check for cross-references consistency
    validate_cross_references(xref_data)?;

    Ok(())
}

/// Validate cross-references consistency
fn validate_cross_references(xref_data: &XRefData) -> PdfResult<()> {
    let mut referenced_objects = std::collections::HashSet::new();
    let mut available_objects = std::collections::HashSet::new();

    // Collect all available objects
    for entry in &xref_data.entries {
        if let XRefEntryType::InUse = entry.entry_type {
            available_objects.insert((entry.object_number, entry.generation));
        }
    }

    // Check trailer references
    let root_ref = &xref_data.trailer.root_ref;
    referenced_objects.insert((root_ref.number, root_ref.generation));

    if let Some(info_ref) = &xref_data.trailer.info_ref {
        referenced_objects.insert((info_ref.number, info_ref.generation));
    }

    if let Some(encrypt_ref) = &xref_data.trailer.encrypt_ref {
        referenced_objects.insert((encrypt_ref.number, encrypt_ref.generation));
    }

    // Verify that all referenced objects exist
    for (obj_num, gen_num) in &referenced_objects {
        if !available_objects.contains(&(*obj_num, *gen_num)) {
            return Err(PdfError::XRef {
                offset: xref_data.xref_offset,
                message: format!("Referenced object {} {} not found in xref table", obj_num, gen_num),
                entry_count: xref_data.entries.len() as u32,
            });
        }
    }

    // Check for orphaned objects (objects that exist but are never referenced)
    let orphaned_count = available_objects.len().saturating_sub(referenced_objects.len());
    if orphaned_count > available_objects.len() / 2 {
        log::warn!("High number of orphaned objects detected: {}", orphaned_count);
    }

    Ok(())
}

// Missing functions from Category 6 - Error Resolution Sheet removed to fix duplicate definitions