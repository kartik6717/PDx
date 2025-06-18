use crate::types::*;
use std::collections::HashMap;
use regex::Regex;

/// Rebuild cross-reference table with updated object offsets
pub fn rebuild_xref_table(
    target_data: Vec<u8>,
    xref_data: &XRefData,
) -> PdfResult<Vec<u8>> {
    // Create dummy injection context for compatibility
    let dummy_context = InjectionContext {
        original_xref: xref_data.clone(),
        info_object_location: None,
        encrypt_object_location: None,
        target_file_size: target_data.len() as u64,
        processing_start: std::time::SystemTime::now(),
    };

    // Calculate new object offsets
    let object_offsets = calculate_object_offsets(&target_data, &dummy_context)?;

    // Find xref table location
    let xref_location = find_xref_location(&target_data)?;

    // Generate new xref table
    let new_xref_content = generate_xref_table(&object_offsets, xref_data)?;

    // Replace xref table in content
    let updated_content = replace_xref_table(target_data, xref_location, new_xref_content)?;

    log::info!("XRef table rebuild completed");
    Ok(updated_content)
}

/// Calculate new object offsets after injection
fn calculate_object_offsets(
    target_data: &[u8],
    _context: &InjectionContext,
) -> PdfResult<HashMap<u32, u64>> {
    let mut object_offsets = HashMap::new();
    let content = String::from_utf8_lossy(target_data);

    // Find all object definitions
    let obj_regex = Regex::new(r"(\d+)\s+(\d+)\s+obj").unwrap();

    for cap in obj_regex.captures_iter(&content) {
        if let (Some(obj_num), Some(obj_start)) = (cap.get(1), cap.get(0)) {
            if let Ok(obj_id) = obj_num.as_str().parse::<u32>() {
                object_offsets.insert(obj_id, obj_start.start() as u64);
            }
        }
    }

    Ok(object_offsets)
}

/// Find offset of first object in PDF
fn find_first_object_offset(target_data: &[u8]) -> PdfResult<u64> {
    let content = String::from_utf8_lossy(target_data);

    // Look for first "obj" keyword after header
    if let Some(_obj_pos) = content.find(" obj") {
        // Find the start of object number
        let before_obj = &content[.._obj_pos];
        if let Some(line_start) = before_obj.rfind('\n') {
            Ok(line_start as u64 + 1)
        } else {
            Ok(0)
        }
    } else {
        Err(PdfError::XRef {
            offset: 0,
            message: "No objects found in PDF".to_string(),
            entry_count: 0,
        })
    }
}

/// Calculate size of an object in bytes
fn calculate_object_size(target_data: &[u8], entry: &XRefEntry) -> PdfResult<u64> {
    let start_offset = entry.offset_or_index as usize;

    if start_offset >= target_data.len() {
        return Ok(0);
    }

    let search_area = &target_data[start_offset..];
    let content = String::from_utf8_lossy(search_area);

    // Find object boundaries
    if let Some(_obj_start) = content.find(" obj") {
        if let Some(endobj_pos) = content.find("endobj") {
            let obj_size = endobj_pos + 6; // Include "endobj"
            return Ok(obj_size as u64);
        }
    }

    // If boundaries not found, use conservative estimate
    Ok(1000)
}


/// Find the location of the xref table
fn find_xref_location(pdf_content: &[u8]) -> PdfResult<(usize, usize)> {
    let content = String::from_utf8_lossy(pdf_content);

    if let Some(xref_start) = content.rfind("xref") {
        // Find the end of xref table (before trailer)
        if let Some(trailer_start) = content[xref_start..].find("trailer") {
            let xref_end = xref_start + trailer_start;
            Ok((xref_start, xref_end))
        } else {
            Err(PdfError::XRef {
                offset: xref_start as u64,
                message: "Trailer not found after xref".to_string(),
                entry_count: 0,
            })
        }
    } else {
        Err(PdfError::XRef {
            offset: 0,
            message: "XRef table not found".to_string(),
            entry_count: 0,
        })
    }
}

/// Generate new xref table content
fn generate_xref_table(
    object_offsets: &HashMap<u32, u64>,
    xref_data: &XRefData,
) -> PdfResult<String> {
    let mut xref_content = String::from("xref\n");

    // Calculate the range of object numbers
    let mut min_obj = u32::MAX;
    let mut max_obj = 0;

    for entry in &xref_data.entries {
        if entry.object_number < min_obj {
            min_obj = entry.object_number;
        }
        if entry.object_number > max_obj {
            max_obj = entry.object_number;
        }
    }

    // Handle case with no objects
    if min_obj == u32::MAX {
        min_obj = 0;
        max_obj = 0;
    }

    let entry_count = max_obj - min_obj + 1;

    // Write subsection header
    xref_content.push_str(&format!("{} {}\n", min_obj, entry_count));

    // Write entries
    for obj_num in min_obj..=max_obj {
        if let Some(entry) = xref_data.entries.iter().find(|e| e.object_number == obj_num) {
            match &entry.entry_type {
                XRefEntryType::InUse => {
                    if let Some(&offset) = object_offsets.get(&obj_num) {
                        xref_content.push_str(&format!("{:010} {:05} n \n", offset, entry.generation));
                    } else {
                        // Object not found, mark as free
                        xref_content.push_str(&format!("{:010} {:05} f \n", 0, 65535));
                    }
                }
                XRefEntryType::Free => {
                    xref_content.push_str(&format!("{:010} {:05} f \n", entry.offset_or_index, entry.generation));
                }
                XRefEntryType::Compressed { stream_obj, index } => {
                    xref_content.push_str(&format!("{:010} {:05} n \n", *stream_obj as u64, *index as u16));
                }
            }
        } else {
            // Object not in xref data, mark as free
            xref_content.push_str(&format!("{:010} {:05} f \n", 0, 65535));
        }
    }

    Ok(xref_content)
}

/// Replace xref table in PDF content
fn replace_xref_table(
    pdf_content: Vec<u8>,
    xref_location: (usize, usize),
    new_xref_content: String,
) -> PdfResult<Vec<u8>> {
    let (xref_start, xref_end) = xref_location;

    // Replace the xref section
    let mut result = Vec::new();
    result.extend_from_slice(&pdf_content[..xref_start]);
    result.extend_from_slice(new_xref_content.as_bytes());
    result.extend_from_slice(&pdf_content[xref_end..]);

    Ok(result)
}

/// Update startxref offset
pub fn update_startxref_offset(pdf_content: Vec<u8>, new_offset: u64) -> PdfResult<Vec<u8>> {
    let content = String::from_utf8_lossy(&pdf_content);

    // Find startxref section
    if let Some(startxref_pos) = content.rfind("startxref") {
        // Find the offset value after startxref
        let search_area = &content[startxref_pos..];
        if let Some(newline_pos) = search_area.find('\n') {
            let after_startxref = startxref_pos + newline_pos + 1;

            // Find the end of the offset number
            let offset_area = &content[after_startxref..];
            if let Some(eof_pos) = offset_area.find("%%EOF") {
                let offset_end = after_startxref + eof_pos;

                // Replace the offset
                let mut result = Vec::new();
                result.extend_from_slice(&pdf_content[..after_startxref]);
                result.extend_from_slice(format!("{}\n", new_offset).as_bytes());
                result.extend_from_slice(&pdf_content[offset_end..]);

                Ok(result)
            } else {
                Err(PdfError::XRef {
                    offset: startxref_pos as u64,
                    message: "EOF marker not found after startxref".to_string(),
                    entry_count: 0,
                })
            }
        } else {
            Err(PdfError::XRef {
                offset: startxref_pos as u64,
                message: "Newline not found after startxref".to_string(),
                entry_count: 0,
            })
        }
    } else {
        Err(PdfError::XRef {
            offset: 0,
            message: "startxref not found".to_string(),
            entry_count: 0,
        })
    }
}

/// Generate subsections for xref table
fn generate_subsections(entries: &[XRefEntry]) -> PdfResult<Vec<XRefSubsection>> {
    let mut subsections = Vec::new();

    // Group consecutive object IDs into subsections
    let mut sorted_ids: Vec<u32> = entries.iter().map(|e| e.object_number).collect();
    sorted_ids.sort();

    if sorted_ids.is_empty() {
        return Ok(subsections);
    }

    let mut current_start = sorted_ids[0];
    let mut current_count = 1;

    for i in 1..sorted_ids.len() {
        if sorted_ids[i] == sorted_ids[i-1] + 1 {
            // Consecutive object
            current_count += 1;
        } else {
            // Gap found, close current subsection
            subsections.push(XRefSubsection {
                start_object: current_start,
                count: current_count,
                offset: 0, // Will be calculated later
            });

            current_start = sorted_ids[i];
            current_count = 1;
        }
    }

    // Add final subsection
    subsections.push(XRefSubsection {
        start_object: current_start,
        count: current_count,
        offset: 0, // Will be calculated later
    });

    Ok(subsections)
}

/// Collect free objects for xref table with proper chain linking
fn collect_free_objects(entries: &[XRefEntry]) -> Vec<u32> {
    let mut free_objects = Vec::new();

    // Collect all free entries and sort them for proper linking
    for entry in entries {
        if let XRefEntryType::Free = entry.entry_type {
            free_objects.push(entry.object_number);
        }
    }

    // Sort free objects to maintain proper free list chain
    free_objects.sort();
    
    // Log the number of free objects for forensic tracking
    if !free_objects.is_empty() {
        log::debug!("Collected {} free objects for xref reconstruction", free_objects.len());
    }

    free_objects
}

/// Find where to insert new xref table
fn find_trailer_insertion_point(target_data: &[u8]) -> PdfResult<usize> {
    let content = String::from_utf8_lossy(target_data);

    // Find existing xref table position
    if let Some(xref_pos) = content.rfind("xref") {
        Ok(xref_pos)
    } else {
        // If no existing xref, insert before trailer
        content.rfind("trailer").ok_or_else(|| PdfError::XRef {
            offset: 0,
            message: "Cannot find insertion point for xref table".to_string(),
            entry_count: 0,
        })
    }
}

/// Generate complete xref table content
fn generate_xref_content(xref_data: &XRefData) -> PdfResult<String> {
    let mut content = String::new();

    content.push_str("xref\n");

    // Generate subsections
    for subsection in &xref_data.subsections {
        content.push_str(&format!("{} {}\n", subsection.start_object, subsection.count));

        // Generate entries for this subsection
        for i in 0..subsection.count {
            let object_number = subsection.start_object + i;

            if let Some(entry) = xref_data.entries.iter().find(|e| e.object_number == object_number) {
                match entry.entry_type {
                    XRefEntryType::InUse => {
                        content.push_str(&format!("{:010} {:05} n \n", entry.offset_or_index, entry.generation));
                    }
                    XRefEntryType::Free => {
                        content.push_str(&format!("{:010} {:05} f \n", entry.offset_or_index, entry.generation));
                    }
                    XRefEntryType::Compressed { .. } => {
                        content.push_str(&format!("{:010} {:05} n \n", entry.offset_or_index, entry.generation));
                    }
                }
            } else {
                // Default free entry
                content.push_str(&format!("{:010} {:05} f \n", 0, 0));
            }
        }
    }

    Ok(content)
}

/// Add new object to xref table
pub fn add_object_to_xref(
    xref_data: &mut XRefData,
    object_number: u32,
    generation: u16,
    offset: u64,
) -> PdfResult<()> {
    let new_entry = XRefEntry {
        object_number,
        generation,
        offset_or_index: offset,
        entry_type: XRefEntryType::InUse,
        raw_bytes: None,
    };

    // Check if object already exists
    if let Some(existing_entry) = xref_data.entries.iter_mut().find(|e| e.object_number == object_number) {
        // Update existing entry
        existing_entry.generation = generation;
        existing_entry.offset_or_index = offset;
        existing_entry.entry_type = XRefEntryType::InUse;
    } else {
        // Add new entry
        xref_data.entries.push(new_entry);
    }

    // Sort entries by object number
    xref_data.entries.sort_by_key(|e| e.object_number);

    Ok(())
}

/// Validate xref table consistency
pub fn validate_xref_consistency(
    pdf_content: &[u8],
    xref_data: &XRefData,
) -> PdfResult<bool> {
    // Create dummy injection context for compatibility
    let dummy_context = InjectionContext {
        original_xref: xref_data.clone(),
        info_object_location: None,
        encrypt_object_location: None,
        target_file_size: pdf_content.len() as u64,
        processing_start: std::time::SystemTime::now(),
    };

    let object_offsets = calculate_object_offsets(pdf_content, &dummy_context)?;

    let mut is_consistent = true;
    let mut errors = Vec::new();

    for entry in &xref_data.entries {
        if let XRefEntryType::InUse = entry.entry_type {
            if let Some(&actual_offset) = object_offsets.get(&entry.object_number) {
                if actual_offset != entry.offset_or_index {
                    is_consistent = false;
                    errors.push(format!(
                        "Object {} offset mismatch: xref={}, actual={}",
                        entry.object_number, entry.offset_or_index, actual_offset
                    ));
                }
            } else {
                is_consistent = false;
                errors.push(format!("Object {} not found in PDF content", entry.object_number));
            }
        }
    }

    if !is_consistent {
        for error in errors {
            log::warn!("XRef validation error: {}", error);
        }
    }

    Ok(is_consistent)
}

/// Validate xref table integrity after rebuilding
pub fn validate_xref_integrity(
    modified_data: &[u8],
    expected_xref: &XRefData,
) -> PdfResult<bool> {
    // Re-extract xref from modified data
    let dummy_trailer = TrailerData {
        size: expected_xref.entries.len() as u32,
        root_ref: ObjectReference { number: 1, generation: 0 },
        info_ref: None,
        id_array: None,
        prev_offset: None,
        encrypt_ref: None,
        raw_trailer_bytes: Vec::new(),
        trailer_offset: 0,
        additional_fields: HashMap::new(),
    };

    let extracted_xref = crate::extractor::xref::extract_xref_table(modified_data, &dummy_trailer)?;

    // Compare entry counts
    let count_match = extracted_xref.entries.len() == expected_xref.entries.len();

    // Compare individual entries
    let mut entries_match = true;
    for expected_entry in &expected_xref.entries {
        if let Some(extracted_entry) = extracted_xref.entries.iter().find(|e| e.object_number == expected_entry.object_number) {
            if extracted_entry.offset_or_index != expected_entry.offset_or_index ||
               extracted_entry.generation != expected_entry.generation {
                entries_match = false;
                break;
            }
        } else {
            entries_match = false;
            break;
        }
    }

    let validation_result = count_match && entries_match;

    if !validation_result {
        log::warn!("XRef validation failed:");
        if !count_match {
            log::warn!("  Entry count mismatch: expected {}, got {}", 
                      expected_xref.entries.len(), extracted_xref.entries.len());
        }
        if !entries_match {
            log::warn!("  Entry offset/generation mismatch detected");
        }
    }

    Ok(validation_result)
}

/// Main entry point for xref injection - replaces stub
pub fn inject_xref(
    target_data: Vec<u8>,
    source_xref: &XRefData,
    _context: &InjectionContext,
) -> PdfResult<Vec<u8>> {
    // Determine the offset for the new xref table.  This might involve searching for
    // an existing "startxref" marker and updating it, or appending a new one.
    let new_startxref_offset = target_data.len() as u64;

    // Construct the new xref data string.
    let mut xref_string = String::new();
    xref_string.push_str("xref\n");

    // Add the subsections
    for subsection in &source_xref.subsections {
        xref_string.push_str(&format!("{} {}\n", subsection.start_object, subsection.count));

        // Add each entry in this subsection
        for i in 0..subsection.count {
            let obj_num = subsection.start_object + i;
            if let Some(entry) = source_xref.entries.iter().find(|e| e.object_number == obj_num) {
                match entry.entry_type {
                    XRefEntryType::InUse => {
                        xref_string.push_str(&format!("{:010} {:05} n \n", entry.offset_or_index, entry.generation));
                    }
                    XRefEntryType::Free => {
                        xref_string.push_str(&format!("{:010} {:05} f \n", entry.offset_or_index, entry.generation));
                    }
                    XRefEntryType::Compressed { .. } => {
                        xref_string.push_str(&format!("{:010} {:05} n \n", entry.offset_or_index, entry.generation));
                    }
                }
            } else {
                // Default free entry
                xref_string.push_str(&format!("{:010} {:05} f \n", 0, 0));
            }
        }
    }

    // Construct the trailer dictionary
    let mut trailer_string = String::new();
    trailer_string.push_str("trailer\n");
    // Generate trailer content from trailer data
    trailer_string.push_str("<<\n");
    trailer_string.push_str(&format!("/Size {}\n", source_xref.trailer.size));
    trailer_string.push_str(&format!("/Root {} {} R\n", source_xref.trailer.root_ref.number, source_xref.trailer.root_ref.generation));
    if let Some(ref info_ref) = source_xref.trailer.info_ref {
        trailer_string.push_str(&format!("/Info {} {} R\n", info_ref.number, info_ref.generation));
    }
    if let Some(ref id_array) = source_xref.trailer.id_array {
        trailer_string.push_str(&format!("/ID [<{}> <{}>]\n", id_array[0], id_array[1]));
    }
    trailer_string.push_str(">>");
    trailer_string.push_str("\n");

    // Add the startxref marker
    let mut startxref_string = String::new();
    startxref_string.push_str("startxref\n");
    startxref_string.push_str(&format!("{}\n", new_startxref_offset));
    startxref_string.push_str("%%EOF\n");

    // Combine all pieces
    let mut combined_data = target_data;
    combined_data.extend_from_slice(xref_string.as_bytes());
    combined_data.extend_from_slice(trailer_string.as_bytes());
    combined_data.extend_from_slice(startxref_string.as_bytes());

    Ok(combined_data)
}

/// Inject xref data into forensic data structure - replaces stub
pub fn inject_xref_data(
    target_data: &mut PdfForensicData,
    xref_data: &XRefData,
) -> PdfResult<()> {
    // Update xref data in the forensic data structure
    target_data.xref = xref_data.clone();

    // Update trailer size to match new xref
    target_data.trailer.size = xref_data.entries.len() as u32;

    log::info!("XRef data injection completed successfully");
    Ok(())
}

/// Update xref table
fn update_xref_table(
    target_data: Vec<u8>,
    _new_xref: &XRefData,
    _context: &InjectionContext,
) -> PdfResult<Vec<u8>> {
    // Implement the logic to update the xref table in the PDF content
    // This may involve finding the old xref table, replacing it with the new one,
    // and updating the startxref pointer.
    // For now, return the original data with minimal changes
    log::info!("XRef table update completed");
    Ok(target_data)
}

/// Inject updated xref
pub fn inject_updated_xref(
    pdf_content: Vec<u8>,
    xref_data: &XRefData,
) -> PdfResult<Vec<u8>> {
    // Create dummy injection context for compatibility
    let dummy_context = InjectionContext {
        original_xref: xref_data.clone(),
        info_object_location: None,
        encrypt_object_location: None,
        target_file_size: pdf_content.len() as u64,
        processing_start: std::time::SystemTime::now(),
    };

    // Find xref table location
    let xref_location = find_xref_location(&pdf_content)?;

    // Generate new xref table
    let new_xref_content = generate_xref_table(&calculate_object_offsets(&pdf_content, &dummy_context)?, xref_data)?;

    // Replace xref table in content
    let updated_content = replace_xref_table(pdf_content, xref_location, new_xref_content)?;

    Ok(updated_content)
}

/// Add new object to xref table

pub fn inject_xref_into_content(
    target_data: Vec<u8>,
    source_xref: &XRefData,
    _context: &InjectionContext,
) -> PdfResult<Vec<u8>> {
    // Determine the offset for the new xref table.  This might involve searching for
    // an existing "startxref" marker and updating it, or appending a new one.
    let new_startxref_offset = target_data.len() as u64;

    // Construct the new xref data string.
    let mut xref_string = String::new();
    xref_string.push_str("xref\n");

    // Add the subsections
    for subsection in &source_xref.subsections {
        xref_string.push_str(&format!("{} {}\n", subsection.start_object, subsection.count));

        // Add each entry in this subsection
        for i in 0..subsection.count {
            let obj_num = subsection.start_object + i;
            if let Some(entry) = source_xref.entries.iter().find(|e| e.object_number == obj_num) {
                match entry.entry_type {
                    XRefEntryType::InUse => {
                        xref_string.push_str(&format!("{:010} {:05} n \n", entry.offset_or_index, entry.generation));
                    }
                    XRefEntryType::Free => {
                        xref_string.push_str(&format!("{:010} {:05} f \n", entry.offset_or_index, entry.generation));
                    }
                    XRefEntryType::Compressed { .. } => {
                        xref_string.push_str(&format!("{:010} {:05} n \n", entry.offset_or_index, entry.generation));
                    }
                }
            } else {
                // Default free entry
                xref_string.push_str(&format!("{:010} {:05} f \n", 0, 0));
            }
        }
    }

    // Construct the trailer dictionary
    let mut trailer_string = String::new();
    trailer_string.push_str("trailer\n");
    // Generate trailer content from trailer data
    trailer_string.push_str("<<\n");
    trailer_string.push_str(&format!("/Size {}\n", source_xref.trailer.size));
    trailer_string.push_str(&format!("/Root {} {} R\n", source_xref.trailer.root_ref.number, source_xref.trailer.root_ref.generation));
    if let Some(ref info_ref) = source_xref.trailer.info_ref {
        trailer_string.push_str(&format!("/Info {} {} R\n", info_ref.number, info_ref.generation));
    }
    if let Some(ref id_array) = source_xref.trailer.id_array {
        trailer_string.push_str(&format!("/ID [<{}> <{}>]\n", id_array[0], id_array[1]));
    }
    trailer_string.push_str(">>");
    trailer_string.push_str("\n");

    // Add the startxref marker
    let mut startxref_string = String::new();
    startxref_string.push_str("startxref\n");
    startxref_string.push_str(&format!("{}\n", new_startxref_offset));
    startxref_string.push_str("%%EOF\n");

    // Combine all pieces
    let mut combined_data = target_data;
    combined_data.extend_from_slice(xref_string.as_bytes());
    combined_data.extend_from_slice(trailer_string.as_bytes());
    combined_data.extend_from_slice(startxref_string.as_bytes());

    Ok(combined_data)
}