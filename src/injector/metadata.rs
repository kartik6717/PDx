use crate::types::*;

fn validate_metadata_fields(metadata: &DocumentMetadata) -> PdfResult<()> {
    if let Some(ref title) = metadata.title {
        if title.is_empty() {
            return Err(PdfError::MetadataExtraction {
                field: "title".to_string(),
                message: "Title field is empty".to_string(),
                object_id: 0,
            });
        }
    }
    Ok(())
}

fn serialize_info_dictionary(metadata: &DocumentMetadata) -> PdfResult<String> {
    let mut dict_parts = Vec::new();

    if let Some(ref title) = metadata.title {
        dict_parts.push(format!("/Title ({})", title));
    }
    if let Some(ref author) = metadata.author {
        dict_parts.push(format!("/Author ({})", author));
    }
    if let Some(ref subject) = metadata.subject {
        dict_parts.push(format!("/Subject ({})", subject));
    }
    if let Some(ref producer) = metadata.producer {
        dict_parts.push(format!("/Producer ({})", producer));
    }

    Ok(format!("<< {} >>", dict_parts.join(" ")))
}

fn create_info_object(metadata: &DocumentMetadata) -> PdfResult<String> {
    let dict = serialize_info_dictionary(metadata)?;
    Ok(format!("obj\n{}\nendobj", dict))
}

use regex::Regex;

/// Inject metadata into target PDF
pub fn inject_metadata(
    target_data: &mut PdfForensicData,
    source_metadata: &DocumentMetadata,
) -> PdfResult<()> {
    // Update metadata in the forensic data structure
    target_data.metadata.title = source_metadata.title.clone();
    target_data.metadata.author = source_metadata.author.clone();
    target_data.metadata.subject = source_metadata.subject.clone();
    target_data.metadata.keywords = source_metadata.keywords.clone();
    target_data.metadata.creator = source_metadata.creator.clone();
    target_data.metadata.producer = source_metadata.producer.clone();
    target_data.metadata.creation_date = source_metadata.creation_date.clone();
    target_data.metadata.mod_date = source_metadata.mod_date.clone();
    target_data.metadata.custom_fields = source_metadata.custom_fields.clone();

    // Validate metadata before injection
    validate_metadata_fields(source_metadata)?;

    // Find or create Info object location
    let info_obj_num = if let Some(info_ref) = &target_data.trailer.info_ref {
        info_ref.number
    } else {
        find_next_available_object_number(&target_data.xref)?
    };

    // Serialize metadata to PDF dictionary format
    let _info_dict_content = serialize_info_dictionary(source_metadata)?;

    // Inject into PDF structure
    let _info_dict_content = create_info_object(&target_data.metadata)?;

    // Update xref table
    update_xref_for_metadata(&mut target_data.xref, info_obj_num)?;

    // Update trailer to reference Info object
    update_trailer_info_ref(&mut target_data.trailer, info_obj_num)?;

    log::info!("Metadata injection completed successfully");
    Ok(())
}

/// Find next available object number in xref table
fn find_next_available_object_number(xref_data: &XRefData) -> PdfResult<u32> {
    let used_numbers: std::collections::HashSet<u32> = xref_data.entries
        .iter()
        .map(|entry| entry.object_number)
        .collect();

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

/// Update xref table for metadata object
fn update_xref_for_metadata(xref_data: &mut XRefData, obj_num: u32) -> PdfResult<()> {
    let new_entry = XRefEntry {
        object_number: obj_num,
        generation: 0,
        offset_or_index: xref_data.xref_offset,
        entry_type: XRefEntryType::InUse,
        raw_bytes: Some(format!("{:010} {:05} n \r\n", 0, 0).into_bytes()),
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

/// Replace existing Info object with source metadata
fn replace_info_object(
    target_data: Vec<u8>,
    source_metadata: &DocumentMetadata,
    info_location: &XRefEntry,
) -> PdfResult<Vec<u8>> {
    let object_start = info_location.offset_or_index as usize;
    let object_end = find_info_object_end(&target_data, object_start)?;

    // Generate new Info object content
    let new_info_content = generate_info_object_content(source_metadata, info_location.object_number)?;

    // Replace the object in the data
    let mut result = Vec::new();
    result.extend_from_slice(&target_data[..object_start]);
    result.extend_from_slice(new_info_content.as_bytes());
    result.extend_from_slice(&target_data[object_end..]);

    Ok(result)
}

/// Find the end of Info object
fn find_info_object_end(target_data: &[u8], start_offset: usize) -> PdfResult<usize> {
    let search_area = &target_data[start_offset..];
    let content = std::str::from_utf8(search_area).map_err(|e| PdfError::MetadataInjection {
        field: "object_parsing".to_string(),
        message: format!("Invalid UTF-8 in Info object: {}", e),
        target_object: 0,
    })?;

    if let Some(endobj_pos) = content.find("endobj") {
        Ok(start_offset + endobj_pos + 6) // +6 for "endobj"
    } else {
        Err(PdfError::MetadataInjection {
            field: "object_boundary".to_string(),
            message: "Info object end not found".to_string(),
            target_object: 0,
        })
    }
}

/// Generate complete Info object content with proper PDF syntax
fn generate_info_object_content(metadata: &DocumentMetadata, object_id: u32) -> PdfResult<String> {
    let mut content = String::new();

    // Object header
    content.push_str(&format!("{} 0 obj\n", object_id));
    content.push_str("<<\n");

    // Inject all metadata fields with proper escaping
    if let Some(ref title) = metadata.title {
        content.push_str(&format!("/Title ({})\n", escape_pdf_string(title)));
    }

    if let Some(ref author) = metadata.author {
        content.push_str(&format!("/Author ({})\n", escape_pdf_string(author)));
    }

    if let Some(ref subject) = metadata.subject {
        content.push_str(&format!("/Subject ({})\n", escape_pdf_string(subject)));
    }

    if let Some(ref keywords) = metadata.keywords {
        content.push_str(&format!("/Keywords ({})\n", escape_pdf_string(keywords)));
    }

    if let Some(ref creator) = metadata.creator {
        content.push_str(&format!("/Creator ({})\n", escape_pdf_string(creator)));
    }

    if let Some(ref producer) = metadata.producer {
        content.push_str(&format!("/Producer ({})\n", escape_pdf_string(producer)));
    }

    // Preserve exact timestamp format from source
    if let Some(ref creation_date) = metadata.creation_date {
        content.push_str(&format!("/CreationDate ({})\n", creation_date));
    }

    if let Some(ref mod_date) = metadata.mod_date {
        content.push_str(&format!("/ModDate ({})\n", mod_date));
    }

    // Inject custom fields
    for (key, value) in &metadata.custom_fields {
        content.push_str(&format!("/{} ({})\n", key, escape_pdf_string(value)));
    }

    // Close dictionary and object
    content.push_str(">>\n");
    content.push_str("endobj\n");

    Ok(content)
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
        Err(PdfError::MetadataInjection {
            field: "trailer_location".to_string(),
            message: "Trailer not found in target PDF".to_string(),
            target_object: 0,
        })
    }
}

/// Update metadata references in existing objects
pub fn update_metadata_references(
    target_data: Vec<u8>,
    old_info_ref: Option<&ObjectReference>,
    new_info_ref: &ObjectReference,
) -> PdfResult<Vec<u8>> {
    let mut modified_data = target_data;

    // Update trailer reference to Info object
    modified_data = update_trailer_info_reference(modified_data, new_info_ref)?;

    // Update any other references if needed
    if let Some(old_ref) = old_info_ref {
        if old_ref.number != new_info_ref.number {
            modified_data = update_cross_references(modified_data, old_ref, new_info_ref)?;
        }
    }

    Ok(modified_data)
}

/// Update trailer's Info reference
fn update_trailer_info_reference(
    target_data: Vec<u8>,
    new_info_ref: &ObjectReference,
) -> PdfResult<Vec<u8>> {
    let content = String::from_utf8_lossy(&target_data);

    if let Some(trailer_pos) = content.rfind("trailer") {
        if let Some(dict_start) = content[trailer_pos..].find("<<") {
            let dict_start_abs = trailer_pos + dict_start;
            if let Some(dict_end) = content[dict_start_abs..].find(">>") {
                let dict_end_abs = dict_start_abs + dict_end;
                let dict_content = &content[dict_start_abs + 2..dict_end_abs];

                // Replace or add Info reference
                let new_dict_content = if dict_content.contains("/Info") {
                    // Replace existing Info reference
                    let info_regex = Regex::new(r"/Info\s+\d+\s+\d+\s+R").unwrap();
                    info_regex.replace(dict_content, &format!("/Info {} {} R", new_info_ref.number, new_info_ref.generation)).to_string()
                } else {
                    // Add new Info reference
                    format!("{}\n/Info {} {} R", dict_content, new_info_ref.number, new_info_ref.generation)
                };

                // Reconstruct the data
                let mut result = Vec::new();
                result.extend_from_slice(&target_data[..dict_start_abs + 2]);
                result.extend_from_slice(new_dict_content.as_bytes());
                result.extend_from_slice(&target_data[dict_end_abs..]);

                Ok(result)
            } else {
                Err(PdfError::MetadataInjection {
                    field: "trailer_dict".to_string(),
                    message: "Trailer dictionary end not found".to_string(),
                    target_object: 0,
                })
            }
        } else {
            Err(PdfError::MetadataInjection {
                field: "trailer_dict".to_string(),
                message: "Trailer dictionary start not found".to_string(),
                target_object: 0,
            })
        }
    } else {
        Err(PdfError::MetadataInjection {
            field: "trailer".to_string(),
            message: "Trailer not found".to_string(),
            target_object: 0,
        })
    }
}

/// Update cross-references to changed objects
fn update_cross_references(
    target_data: Vec<u8>,
    old_ref: &ObjectReference,
    new_ref: &ObjectReference,
) -> PdfResult<Vec<u8>> {
    let content = String::from_utf8_lossy(&target_data);

    // Create regex pattern for old reference
    let old_pattern = format!(r"{}\s+{}\s+R", old_ref.number, old_ref.generation);
    let new_replacement = format!("{} {} R", new_ref.number, new_ref.generation);

    if let Ok(regex) = Regex::new(&old_pattern) {
        let updated_content = regex.replace_all(&content, new_replacement.as_str());
        Ok(updated_content.as_bytes().to_vec())
    } else {
        // If regex fails, return original data
        Ok(target_data)
    }
}