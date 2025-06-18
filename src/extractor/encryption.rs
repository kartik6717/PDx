use std::collections::HashMap;
use crate::types::*;

/// Extract encryption data from PDF Encrypt dictionary
pub fn extract_encryption_data(
    file_data: &[u8],
    encrypt_ref: &ObjectReference,
    xref_data: &XRefData,
) -> PdfResult<EncryptionData> {
    // Find the Encrypt object in the xref table
    let encrypt_entry = xref_data.entries.iter()
        .find(|entry| entry.object_number == encrypt_ref.number && entry.generation == encrypt_ref.generation)
        .ok_or_else(|| PdfError::Encryption {
            message: format!("Encrypt object {} not found in xref table", encrypt_ref.number),
            algorithm: Some("Standard".to_string()),
        })?;

    // Extract object data from file
    let object_data = extract_encrypt_object_data(file_data, encrypt_entry)?;
    let encrypt_dict = parse_encrypt_dictionary(&object_data).unwrap_or_else(|_| EncryptionData::default_with_error("Failed to parse encryption dictionary"));

    Ok(encrypt_dict)
}

/// Extract encryption object data from file using xref entry
fn extract_encrypt_object_data(file_data: &[u8], entry: &XRefEntry) -> PdfResult<Vec<u8>> {
    let offset = entry.offset_or_index as usize;

    if offset >= file_data.len() {
        return Err(PdfError::Encryption {
            message: format!("Encrypt object offset {} beyond file size {}", offset, file_data.len()),
            algorithm: Some("Standard".to_string()),
        });
    }

    // Find the object boundary
    let search_area = &file_data[offset..];
    let content = std::str::from_utf8(search_area).map_err(|e| PdfError::Encryption {
        message: format!("Invalid UTF-8 in encrypt object data: {}", e),
        algorithm: Some("Standard".to_string()),
    })?;

    // Find object start
    let obj_start = content.find("obj").ok_or_else(|| PdfError::Encryption {
        message: "Encrypt object 'obj' keyword not found".to_string(),
        algorithm: Some("Standard".to_string()),
    })?;

    // Find object end
    let obj_end = content.find("endobj").ok_or_else(|| PdfError::Encryption {
        message: "Encrypt object 'endobj' keyword not found".to_string(),
        algorithm: Some("Standard".to_string()),
    })?;

    let object_content = &content[obj_start + 3..obj_end];
    Ok(object_content.as_bytes().to_vec())
}

/// Parse Encrypt dictionary from object data
fn parse_encrypt_dictionary(object_data: &[u8]) -> PdfResult<EncryptionData> {
    let content = std::str::from_utf8(object_data).map_err(|e| PdfError::Encryption {
        message: format!("Invalid UTF-8 in Encrypt dictionary: {}", e),
        algorithm: Some("Standard".to_string()),
    })?;

    // Find dictionary boundaries
    let dict_start = content.find("<<").ok_or_else(|| PdfError::Encryption {
        message: "Encrypt dictionary start '<<' not found".to_string(),
        algorithm: Some("Standard".to_string()),
    })?;

    let dict_end = find_dictionary_end(&content[dict_start..])?;
    let dict_content = &content[dict_start + 2..dict_start + dict_end - 2];

    // Extract encryption parameters
    let filter = extract_filter(dict_content)?;
    let v = extract_v_value(dict_content)?;
    let r = extract_r_value(dict_content)?;
    let length = extract_length(dict_content);
    let p = extract_p_value(dict_content)?;
    let o = extract_o_string(dict_content)?;
    let u = extract_u_string(dict_content)?;
    let _oe = extract_oe_string(dict_content);
    let _ue = extract_ue_string(dict_content);
    let _perms = extract_perms_string(dict_content);
    let encrypt_metadata = extract_encrypt_metadata(dict_content);
    let _cf = extract_crypt_filters(dict_content)?;
    let stm_f = extract_stm_f(dict_content);
    let str_f = extract_str_f(dict_content);
    let _eff = extract_eff(dict_content);

    Ok(EncryptionData {
        filter,
        v: v.try_into().unwrap(),
        r: r.try_into().unwrap(),
        o,
        u,
        p,
        length: length.map(|l| l.try_into().unwrap()),
        str_f,
        stm_f,
        encrypt_metadata,
        cf: None, // TODO: Implement CF dictionary extraction
        additional_params: HashMap::new(),
        raw_dict_bytes: dict_content.as_bytes().to_vec(),
    })
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

    Err(PdfError::Encryption {
        message: "Encrypt dictionary not properly closed".to_string(),
        algorithm: Some("Standard".to_string()),
    })
}

/// Extract Filter field (required)
fn extract_filter(dict_content: &str) -> PdfResult<String> {
    let filter_pos = dict_content.find("/Filter").ok_or_else(|| PdfError::Encryption {
        message: "Filter field not found in Encrypt dictionary".to_string(),
        algorithm: Some("Standard".to_string()),
    })?;

    let after_filter = &dict_content[filter_pos + "/Filter".len()..];
    let filter_value = after_filter.split_whitespace().next().ok_or_else(|| PdfError::Encryption {
        message: "Filter value not found".to_string(),
        algorithm: Some("Standard".to_string()),
    })?;

    // Remove leading slash if present
    let filter_name = if filter_value.starts_with('/') {
        &filter_value[1..]
    } else {
        filter_value
    };

    Ok(filter_name.to_string())
}

/// Extract V field (version)
fn extract_v_value(dict_content: &str) -> PdfResult<u32> {
    extract_numeric_field(dict_content, "/V", "V")
}

/// Extract R field (revision)
fn extract_r_value(dict_content: &str) -> PdfResult<u32> {
    extract_numeric_field(dict_content, "/R", "R")
}

/// Extract Length field (optional)
fn extract_length(dict_content: &str) -> Option<u32> {
    extract_numeric_field(dict_content, "/Length", "Length").ok()
}

/// Extract P field (permissions)
fn extract_p_value(dict_content: &str) -> PdfResult<i32> {
    let p_pos = dict_content.find("/P").ok_or_else(|| PdfError::Encryption {
        message: "P field not found in Encrypt dictionary".to_string(),
        algorithm: Some("Standard".to_string()),
    })?;

    let after_p = &dict_content[p_pos + "/P".len()..];
    let p_str = after_p.split_whitespace().next().ok_or_else(|| PdfError::Encryption {
        message: "P value not found".to_string(),
        algorithm: Some("Standard".to_string()),
    })?;

    p_str.parse().map_err(|e| PdfError::Encryption {
        message: format!("Invalid P value '{}': {}", p_str, e),
        algorithm: Some("Standard".to_string()),
    })
}

/// Extract O string (owner password hash)
fn extract_o_string(dict_content: &str) -> PdfResult<Vec<u8>> {
    extract_hex_string_field(dict_content, "/O", "O")
}

/// Extract U string (user password hash)
fn extract_u_string(dict_content: &str) -> PdfResult<Vec<u8>> {
    extract_hex_string_field(dict_content, "/U", "U")
}

/// Extract OE string (PDF 2.0, optional)
fn extract_oe_string(dict_content: &str) -> Option<Vec<u8>> {
    extract_hex_string_field(dict_content, "/OE", "OE").ok()
}

/// Extract UE string (PDF 2.0, optional)
fn extract_ue_string(dict_content: &str) -> Option<Vec<u8>> {
    extract_hex_string_field(dict_content, "/UE", "UE").ok()
}

/// Extract Perms string (PDF 2.0, optional)
fn extract_perms_string(dict_content: &str) -> Option<Vec<u8>> {
    extract_hex_string_field(dict_content, "/Perms", "Perms").ok()
}

/// Extract EncryptMetadata boolean (optional)
fn extract_encrypt_metadata(dict_content: &str) -> Option<bool> {
    if let Some(pos) = dict_content.find("/EncryptMetadata") {
        let after_field = &dict_content[pos + "/EncryptMetadata".len()..];
        if let Some(value) = after_field.split_whitespace().next() {
            match value {
                "true" => Some(true),
                "false" => Some(false),
                // Handle boolean variations and numeric representations
                "1" | "yes" | "on" => Some(true),
                "0" | "no" | "off" => Some(false),
                // Log unknown value for debugging
                unknown => {
                    log::warn!("Unknown EncryptMetadata value: {}", unknown);
                    None
                }
            }
        } else {
            // Default to true if value is missing but field exists
            Some(true)
        }
    } else {
        Some(true) // Default to true if field is not present (PDF spec default)
    }
}

/// Extract StmF field (optional)
fn extract_stm_f(dict_content: &str) -> Option<String> {
    extract_name_field(dict_content, "/StmF")
}

/// Extract StrF field (optional)
fn extract_str_f(dict_content: &str) -> Option<String> {
    extract_name_field(dict_content, "/StrF")
}

/// Extract CF (Crypt Filter) dictionary
fn extract_cf_dictionary(dict_content: &str) -> Option<std::collections::HashMap<String, String>> {
    if let Some(cf_pos) = dict_content.find("/CF") {
        let after_cf = &dict_content[cf_pos + 3..];
        if let Some(dict_start) = after_cf.find("<<") {
            if let Some(dict_end) = after_cf[dict_start..].find(">>") {
                let cf_dict_content = &after_cf[dict_start + 2..dict_start + dict_end];
                let mut cf_map = std::collections::HashMap::new();

                // Parse crypt filter entries
                let mut pos = 0;
                while pos < cf_dict_content.len() {
                    if let Some(name_start) = cf_dict_content[pos..].find('/') {
                        let name_pos = pos + name_start + 1;
                        if let Some(name_end) = cf_dict_content[name_pos..].find(char::is_whitespace) {
                            let filter_name = cf_dict_content[name_pos..name_pos + name_end].to_string();

                            // Look for the filter configuration
                            if let Some(config_start) = cf_dict_content[name_pos + name_end..].find("<<") {
                                if let Some(config_end) = cf_dict_content[name_pos + name_end + config_start..].find(">>") {
                                    let config_content = &cf_dict_content[name_pos + name_end + config_start + 2..name_pos + name_end + config_start + config_end];
                                    cf_map.insert(filter_name, config_content.trim().to_string());
                                }
                            }
                            pos = name_pos + name_end + 1;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }

                if !cf_map.is_empty() {
                    return Some(cf_map);
                }
            }
        }
    }
    None
}

/// Extract EFF field (optional)
fn extract_eff(dict_content: &str) -> Option<String> {
    extract_name_field(dict_content, "/EFF")
}

/// Extract crypt filters dictionary (optional)
fn extract_crypt_filters(dict_content: &str) -> PdfResult<HashMap<String, CryptFilter>> {
    let mut filters = HashMap::new();

    if let Some(cf_pos) = dict_content.find("/CF") {
        let after_cf = &dict_content[cf_pos + "/CF".len()..];
        if let Some(dict_start) = after_cf.find("<<") {
            if let Ok(dict_end) = find_dictionary_end(&after_cf[dict_start..]) {
                let cf_content = &after_cf[dict_start + 2..dict_start + dict_end - 2];

                // Parse individual crypt filters
                // This is a simplified parser - full implementation would be more complex
                filters = parse_crypt_filters_content(cf_content)?;
            }
        }
    }

    Ok(filters)
}

/// Parse crypt filters content
fn parse_crypt_filters_content(cf_content: &str) -> PdfResult<HashMap<String, CryptFilter>> {
    let mut filters = HashMap::new();

    // Parse each filter entry in the CF dictionary
    let mut pos = 0;
    while pos < cf_content.len() {
        // Skip whitespace
        while pos < cf_content.len() && cf_content.chars().nth(pos).unwrap().is_whitespace() {
            pos += 1;
        }

        if pos >= cf_content.len() {
            break;
        }

        // Look for filter name (starts with /)
        if cf_content.chars().nth(pos) == Some('/') {
            let name_start = pos + 1;
            let mut name_end = name_start;

            // Find end of name
            while name_end < cf_content.len() {
                let ch = cf_content.chars().nth(name_end).unwrap();
                if ch.is_whitespace() || ch == '<' {
                    break;
                }
                name_end += 1;
            }

            let filter_name = cf_content[name_start..name_end].to_string();

            // Skip to dictionary start
            pos = name_end;
            while pos < cf_content.len() && cf_content.chars().nth(pos) != Some('<') {
                pos += 1;
            }

            if pos < cf_content.len() && cf_content.chars().nth(pos) == Some('<') {
                // Find matching closing bracket
                let dict_start = pos + 1;
                let mut bracket_count = 1;
                pos += 1;

                while pos < cf_content.len() && bracket_count > 0 {
                    match cf_content.chars().nth(pos) {
                        Some('<') => bracket_count += 1,
                        Some('>') => bracket_count -= 1,
                        _ => {}
                    }
                    pos += 1;
                }

                if bracket_count == 0 {
                    let dict_content = &cf_content[dict_start..pos-1];

                    // Parse filter dictionary
                    let cfm = extract_name_field(dict_content, "/CFM")
                        .unwrap_or_else(|| "V2".to_string());

                    let auth_event = extract_name_field(dict_content, "/AuthEvent")
                        .unwrap_or_else(|| "DocOpen".to_string());

                    let length = extract_numeric_field(dict_content, "/Length", "Length").unwrap_or(128);

                    filters.insert(filter_name, CryptFilter {
                        cfm,
                        auth_event: Some(auth_event),
                        length: Some(length as u16),
                    });
                }
            }
        } else {
            pos += 1;
        }
    }

    Ok(filters)
}

/// Extract numeric field value
fn extract_numeric_field(dict_content: &str, field_name: &str, field_desc: &str) -> PdfResult<u32> {
    let field_pos = dict_content.find(field_name).ok_or_else(|| PdfError::Encryption {
        message: format!("{} field not found in Encrypt dictionary", field_desc),
        algorithm: Some("Standard".to_string()),
    })?;

    let after_field = &dict_content[field_pos + field_name.len()..];
    let field_str = after_field.split_whitespace().next().ok_or_else(|| PdfError::Encryption {
        message: format!("{} value not found", field_desc),
        algorithm: Some("Standard".to_string()),
    })?;

    field_str.parse().map_err(|e| PdfError::Encryption {
        message: format!("Invalid {} value '{}': {}", field_desc, field_str, e),
        algorithm: Some("Standard".to_string()),
    })
}

/// Extract hex string field value
fn extract_hex_string_field(dict_content: &str, field_name: &str, field_desc: &str) -> PdfResult<Vec<u8>> {
    let field_pos = dict_content.find(field_name).ok_or_else(|| PdfError::Encryption {
        message: format!("{} field not found in Encrypt dictionary", field_desc),
        algorithm: Some("Standard".to_string()),
    })?;

    let after_field = &dict_content[field_pos + field_name.len()..].trim_start();

    if after_field.starts_with('<') {
        if let Some(end_pos) = after_field.find('>') {
            let hex_content = &after_field[1..end_pos];

            hex::decode(hex_content).map_err(|e| PdfError::Encryption {
                message: format!("Invalid hex string in {} field: {}", field_desc, e),
                algorithm: Some("Standard".to_string()),
            })
        } else {
            Err(PdfError::Encryption {
                message: format!("Unterminated hex string in {} field", field_desc),
                algorithm: Some("Standard".to_string()),
            })
        }
    } else {
        Err(PdfError::Encryption {
            message: format!("{} field is not a hex string", field_desc),
            algorithm: Some("Standard".to_string()),
        })
    }
}

/// Extract name field value
fn extract_name_field(dict_content: &str, field_name: &str) -> Option<String> {
    if let Some(field_pos) = dict_content.find(field_name) {
        let after_field = &dict_content[field_pos + field_name.len()..];
        if let Some(name_value) = after_field.split_whitespace().next() {
            if name_value.starts_with('/') {
                return Some(name_value[1..].to_string());
            }
        }
    }
    None
}

pub fn extract_encryption(mmap: &[u8], encrypt_ref: &ObjectReference, xref_data: &XRefData) -> PdfResult<Option<EncryptionData>> {
    // Find the encryption object in the xref table
    let encrypt_entry = xref_data.entries.iter()
        .find(|entry| entry.object_number == encrypt_ref.number && entry.generation == encrypt_ref.generation);

    if let Some(entry) = encrypt_entry {
        if let XRefEntryType::InUse = entry.entry_type {
            let offset = entry.offset_or_index as usize;

            if offset < mmap.len() {
                // Extract object content
                let remaining = &mmap[offset..];
                let content = String::from_utf8_lossy(remaining);

                // Find object boundaries
                if let Some(obj_start) = content.find("obj") {
                    if let Some(obj_end) = content[obj_start..].find("endobj") {
                        let obj_content = &content[obj_start..obj_start + obj_end];

                        // Parse encryption dictionary
                        if let Some(dict_start) = obj_content.find("<<") {
                            if let Some(dict_end) = obj_content[dict_start..].find(">>") {
                                let dict_content = &obj_content[dict_start + 2..dict_start + dict_end];

                                return parse_encryption_dictionary(dict_content);
                            } else {
                                log::warn!("Encryption dictionary not properly closed at object {}", encrypt_ref.number);
                                return Ok(Some(EncryptionData::default_with_error("Malformed dictionary")));
                            }
                        } else {
                            log::warn!("No dictionary found in encryption object {}", encrypt_ref.number);
                            return Ok(Some(EncryptionData::default_with_error("No dictionary found")));
                        }
                    }
                }
            }
        }
    }

    // If no encryption found, return None
    Ok(None)
}

fn parse_encryption_dictionary(dict_content: &str) -> PdfResult<Option<EncryptionData>> {
    let mut filter = "Standard".to_string();
    let mut v = 1u8;
    let mut r = 2u8;
    let mut o = Vec::new();
    let mut u = Vec::new();

    let length = None;
    let str_f = None;
    let stm_f = None;
    let encrypt_metadata = None;

    // Simple parsing - look for key patterns
    if let Some(filter_pos) = dict_content.find("/Filter") {
        if let Some(filter_start) = dict_content[filter_pos..].find('/') {
            if let Some(filter_end) = dict_content[filter_pos + filter_start + 1..].find(char::is_whitespace) {
                filter = dict_content[filter_pos + filter_start + 1..filter_pos + filter_start + 1 + filter_end].to_string();
            }
        }
    }

    if let Some(v_pos) = dict_content.find("/V") {
        if let Some(v_start) = dict_content[v_pos..].find(char::is_numeric) {
            v = dict_content[v_pos + v_start..v_pos + v_start + 1].parse().unwrap_or(1);
        }
    }

    if let Some(r_pos) = dict_content.find("/R") {
        if let Some(r_start) = dict_content[r_pos..].find(char::is_numeric) {
            r = dict_content[r_pos + r_start..r_pos + r_start + 1].parse().unwrap_or(2);
        }
    }

    let mut p = 0i32;
    if let Some(p_pos) = dict_content.find("/P") {
        if let Some(p_start) = dict_content[p_pos..].find(|c: char| c == '-' || c.is_numeric()) {
            if let Some(p_end) = dict_content[p_pos + p_start..].find(char::is_whitespace) {
                p = dict_content[p_pos + p_start..p_pos + p_start + p_end].parse().unwrap_or(0);
            }
        }
    }

    // Extract O and U strings from the dictionary
    o = extract_o_string(dict_content)?;
    u = extract_u_string(dict_content)?;
    Ok(Some(EncryptionData {
        filter,
        v,
        r,
        o,
        u,
        p,
        length,
        str_f,
        stm_f,
        encrypt_metadata,
        cf: None, // Simplified for now - full implementation would parse CryptFilters
        additional_params: std::collections::HashMap::new(),
        raw_dict_bytes: dict_content.as_bytes().to_vec(),
    }))
}