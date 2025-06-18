use crate::types::*;

/// Inject encryption data into target PDF forensic data
pub fn inject_encryption_data(
    target_data: &mut PdfForensicData,
    source_encryption: &Option<EncryptionData>,
) -> PdfResult<()> {
    // Update encryption data in the forensic data structure
    target_data.encryption = source_encryption.clone();

    // Validate encryption data before injection
    validate_encryption_data(source_encryption)?;

    // Create new encrypt object in target
    let encrypt_obj_num = find_next_available_object_number(&target_data.xref)?;
    let encrypt_dict_content = serialize_encryption_dictionary(source_encryption)?;

    // Inject into PDF structure
    inject_encrypt_object(&mut target_data.structure, encrypt_obj_num, &encrypt_dict_content)?;

    // Update xref table
    update_xref_for_encryption(&mut target_data.xref, encrypt_obj_num)?;

    // Update trailer to reference new encrypt object
    update_trailer_encrypt_ref(&mut target_data.trailer, encrypt_obj_num)?;

    log::info!("Encryption data injection completed successfully");
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

/// Validate encryption data before injection
fn validate_encryption_data(encryption: &Option<EncryptionData>) -> PdfResult<()> {
    if let Some(ref enc) = encryption {
        if enc.filter.is_empty() {
            return Err(PdfError::Encryption {
                algorithm: Some("validate".to_string()),
                message: "Encryption filter cannot be empty".to_string(),
            });
        }

        let key_len = enc.length.unwrap_or(40);
        if key_len < 40 || key_len > 256 {
            return Err(PdfError::Encryption {
                algorithm: Some("validate".to_string()),
                message: format!("Invalid key length: {}", key_len),
            });
        }
    }
    Ok(())
}

/// Serialize encryption dictionary to PDF format
fn serialize_encryption_dictionary(encryption: &Option<EncryptionData>) -> PdfResult<String> {
    if let Some(ref enc) = encryption {
        let dict = format!(
            "<<\n/Filter /Standard\n/V {}\n/R {}\n/Length {}\n/P {}\n/O <{}>\n/U <{}>\n>>",
            enc.v,
            enc.r,
            enc.length.unwrap_or(40),
            enc.p,
            hex::encode(&enc.o),
            hex::encode(&enc.u)
        );
        Ok(dict)
    } else {
        Err(PdfError::Encryption {
            algorithm: Some("serialize".to_string()),
            message: "No encryption data to serialize".to_string(),
        })
    }
}

/// Inject encrypt object into PDF structure
fn inject_encrypt_object(structure: &mut StructuralData, obj_num: u32, dict_content: &str) -> PdfResult<()> {
    // Create new indirect object for encryption dictionary
    let encrypt_obj = IndirectObject {
        reference: ObjectReference { number: obj_num, generation: 0 },
        offset: 0, // Will be set during serialization
        size: dict_content.len() as u64,
        object_type: Some("Encrypt".to_string()),
        subtype: None,
        has_stream: false,
        stream_length: None,
        dictionary: None, // Will be populated during parsing
        stream_filters: Vec::new(),
        compressed: false,
        object_stream_ref: None,
        object_stream_index: None,
    };
    
    // Add to structure's indirect objects
    structure.indirect_objects.push(encrypt_obj);
    structure.object_count += 1;
    
    log::debug!("Injected encryption object {} into structure", obj_num);
    Ok(())
}

/// Update xref table for encryption object
fn update_xref_for_encryption(xref_data: &mut XRefData, obj_num: u32) -> PdfResult<()> {
    let new_entry = XRefEntry {
        object_number: obj_num,
        generation: 0,
        offset_or_index: xref_data.xref_offset,
        entry_type: XRefEntryType::InUse,
        raw_bytes: Some(Vec::new()),
    };

    xref_data.entries.push(new_entry);
    xref_data.entries.sort_by_key(|e| e.object_number);
    Ok(())
}

/// Update trailer to reference encrypt object
fn update_trailer_encrypt_ref(trailer_data: &mut TrailerData, encrypt_obj_num: u32) -> PdfResult<()> {
    trailer_data.encrypt_ref = Some(ObjectReference {
        number: encrypt_obj_num,
        generation: 0,
    });
    Ok(())
}

/// Inject encryption dictionary into target PDF content
pub fn inject_encryption(
    target_data: Vec<u8>,
    source_encryption: &EncryptionData,
    context: &InjectionContext,
) -> PdfResult<Vec<u8>> {
    // If there's an existing encryption object, replace it
    if let Some(ref encrypt_location) = context.encrypt_object_location {
        replace_encryption_object(target_data, source_encryption, encrypt_location)
    } else {
        // Create new encryption object
        create_encryption_object(target_data, source_encryption, context)
    }
}

/// Replace existing encryption object with source data
fn replace_encryption_object(
    target_data: Vec<u8>,
    source_encryption: &EncryptionData,
    encrypt_location: &XRefEntry,
) -> PdfResult<Vec<u8>> {
    let object_start = encrypt_location.offset_or_index as usize;
    let object_end = find_encryption_object_end(&target_data, object_start)?;

    // Generate new encryption object content
    let new_encrypt_content = generate_encryption_object_content(source_encryption, encrypt_location.object_number)?;

    // Replace the object in the data
    let mut result = Vec::new();
    result.extend_from_slice(&target_data[..object_start]);
    result.extend_from_slice(new_encrypt_content.as_bytes());
    result.extend_from_slice(&target_data[object_end..]);

    Ok(result)
}

/// Create new encryption object when none exists
fn create_encryption_object(
    target_data: Vec<u8>,
    source_encryption: &EncryptionData,
    context: &InjectionContext,
) -> PdfResult<Vec<u8>> {
    // Find the next available object ID
    let new_object_id = find_next_object_id(&context.original_xref);

    // Generate new encryption object
    let new_encrypt_content = generate_encryption_object_content(source_encryption, new_object_id)?;

    // Find insertion point (before trailer)
    let insertion_point = find_trailer_start(&target_data)?;

    // Insert the new object
    let mut result = Vec::new();
    result.extend_from_slice(&target_data[..insertion_point]);
    result.extend_from_slice(new_encrypt_content.as_bytes());
    result.extend_from_slice(b"\n");
    result.extend_from_slice(&target_data[insertion_point..]);

    Ok(result)
}

/// Find the end of encryption object
fn find_encryption_object_end(target_data: &[u8], start_offset: usize) -> PdfResult<usize> {
    let search_area = &target_data[start_offset..];
    let content = std::str::from_utf8(search_area).map_err(|e| PdfError::Encryption {
        message: format!("Invalid UTF-8 in encryption object: {}", e),
        algorithm: Some("Standard".to_string()),
    })?;

    if let Some(endobj_pos) = content.find("endobj") {
        Ok(start_offset + endobj_pos + 6) // +6 for "endobj"
    } else {
        Err(PdfError::Encryption {
            message: "Encryption object end not found".to_string(),
            algorithm: Some("Standard".to_string()),
        })
    }
}

/// Generate complete encryption object content with proper PDF syntax
fn generate_encryption_object_content(encryption: &EncryptionData, object_id: u32) -> PdfResult<String> {
    let mut content = String::new();

    // Object header
    content.push_str(&format!("{} 0 obj\n", object_id));
    content.push_str("<<\n");

    // Inject all encryption fields
    content.push_str(&format!("/Filter /{}\n", encryption.filter));
    content.push_str(&format!("/V {}\n", encryption.v));
    content.push_str(&format!("/R {}\n", encryption.r));
    content.push_str(&format!("/P {}\n", encryption.p));

    // O and U strings (byte arrays)
    content.push_str("/O <");
    for byte in &encryption.o {
        content.push_str(&format!("{:02X}", byte));
    }
    content.push_str(">\n");

    content.push_str("/U <");
    for byte in &encryption.u {
        content.push_str(&format!("{:02X}", byte));
    }
    content.push_str(">\n");

    // Optional fields
    if let Some(length) = encryption.length {
        content.push_str(&format!("/Length {}\n", length));
    }

    if let Some(ref str_f) = encryption.str_f {
        content.push_str(&format!("/StrF /{}\n", str_f));
    }

    if let Some(ref stm_f) = encryption.stm_f {
        content.push_str(&format!("/StmF /{}\n", stm_f));
    }

    if let Some(encrypt_metadata) = encryption.encrypt_metadata {
        content.push_str(&format!("/EncryptMetadata {}\n", encrypt_metadata));
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
        Err(PdfError::Encryption {
            message: "Trailer not found in target PDF".to_string(),
            algorithm: Some("Standard".to_string()),
        })
    }
}

/// Update encryption references in trailer and other objects
pub fn update_encryption_references(
    target_data: Vec<u8>,
    old_encrypt_ref: Option<&ObjectReference>,
    new_encrypt_ref: &ObjectReference,
) -> PdfResult<Vec<u8>> {
    let mut modified_data = target_data;

    // Update trailer reference to Encrypt object
    modified_data = update_trailer_encrypt_reference(modified_data, new_encrypt_ref)?;

    // Update any other references if needed
    if let Some(old_ref) = old_encrypt_ref {
        if old_ref.number != new_encrypt_ref.number {
            modified_data = update_cross_references(modified_data, old_ref, new_encrypt_ref)?;
        }
    }

    Ok(modified_data)
}

/// Update trailer's Encrypt reference
fn update_trailer_encrypt_reference(
    target_data: Vec<u8>,
    new_encrypt_ref: &ObjectReference,
) -> PdfResult<Vec<u8>> {
    let content = String::from_utf8_lossy(&target_data);

    if let Some(trailer_pos) = content.rfind("trailer") {
        if let Some(dict_start) = content[trailer_pos..].find("<<") {
            let dict_start_abs = trailer_pos + dict_start;
            if let Some(dict_end) = content[dict_start_abs..].find(">>") {
                let dict_end_abs = dict_start_abs + dict_end;
                let dict_content = &content[dict_start_abs + 2..dict_end_abs];

                // Replace or add Encrypt reference
                let new_dict_content = if dict_content.contains("/Encrypt") {
                    // Replace existing Encrypt reference
                    let encrypt_regex = regex::Regex::new(r"/Encrypt\s+\d+\s+\d+\s+R").unwrap();
                    encrypt_regex.replace(dict_content, &format!("/Encrypt {} {} R", new_encrypt_ref.number, new_encrypt_ref.generation)).to_string()
                } else {
                    // Add new Encrypt reference
                    format!("{}\n/Encrypt {} {} R", dict_content, new_encrypt_ref.number, new_encrypt_ref.generation)
                };

                // Reconstruct the data
                let mut result = Vec::new();
                result.extend_from_slice(&target_data[..dict_start_abs + 2]);
                result.extend_from_slice(new_dict_content.as_bytes());
                result.extend_from_slice(&target_data[dict_end_abs..]);

                Ok(result)
            } else {
                Err(PdfError::Encryption {
                    message: "Trailer dictionary end not found".to_string(),
                    algorithm: Some("Standard".to_string()),
                })
            }
        } else {
            Err(PdfError::Encryption {
                message: "Trailer dictionary start not found".to_string(),
                algorithm: Some("Standard".to_string()),
            })
        }
    } else {
        Err(PdfError::Encryption {
            message: "Trailer not found".to_string(),
            algorithm: Some("Standard".to_string()),
        })
    }
}

/// Update cross-references to changed encryption objects
fn update_cross_references(
    target_data: Vec<u8>,
    old_ref: &ObjectReference,
    new_ref: &ObjectReference,
) -> PdfResult<Vec<u8>> {
    let content = String::from_utf8_lossy(&target_data);

    // Create regex pattern for old reference
    let old_pattern = format!(r"{}\s+{}\s+R", old_ref.number, old_ref.generation);
    let new_replacement = format!("{} {} R", new_ref.number, new_ref.generation);

    if let Ok(regex) = regex::Regex::new(&old_pattern) {
        let updated_content = regex.replace_all(&content, new_replacement.as_str());
        Ok(updated_content.as_bytes().to_vec())
    } else {
        // If regex fails, return original data
        Ok(target_data)
    }
}

/// Validate encryption injection by re-extracting and comparing
pub fn validate_encryption_injection(
    modified_data: &[u8],
    expected_encryption: &EncryptionData,
) -> PdfResult<bool> {
    // Extract trailer to get Encrypt reference
    let trailer_data = crate::extractor::trailer::extract_trailer(modified_data)?;

    if let Some(ref encrypt_ref) = trailer_data.encrypt_ref {
        let xref_data = crate::extractor::xref::extract_xref_table(modified_data, &trailer_data)?;
        let extracted_encryption = crate::extractor::encryption::extract_encryption(
            modified_data, encrypt_ref, &xref_data)?;

        // Compare critical encryption fields
        let validation_result = if let Some(ref extracted) = extracted_encryption {
            let filter_match = extracted.filter == expected_encryption.filter;
            let v_match = extracted.v == expected_encryption.v;
            let r_match = extracted.r == expected_encryption.r;
            let p_match = extracted.p == expected_encryption.p;
            let o_match = extracted.o == expected_encryption.o;
            let u_match = extracted.u == expected_encryption.u;

            if !(filter_match && v_match && r_match && p_match && o_match && u_match) {
                log::warn!("Encryption validation failed:");
                if !filter_match { log::warn!("  Filter mismatch"); }
                if !v_match { log::warn!("  V value mismatch"); }
                if !r_match { log::warn!("  R value mismatch"); }
                if !p_match { log::warn!("  P value mismatch"); }
                if !o_match { log::warn!("  O string mismatch"); }
                if !u_match { log::warn!("  U string mismatch"); }
            }

            filter_match && v_match && r_match && p_match && o_match && u_match
        } else {
            false
        };

        Ok(validation_result)
    } else {
        // No encryption reference found
        Ok(false)
    }
}