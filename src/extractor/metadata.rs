use crate::types::*;
use std::collections::HashMap;

/// Extract metadata from PDF Info dictionary
pub fn extract_metadata(
    file_data: &[u8],
    info_ref: &ObjectReference,
    xref_data: &XRefData,
) -> PdfResult<DocumentMetadata> {
    // Find the Info object in the xref table
    let info_entry = xref_data.entries.iter()
        .find(|entry| entry.object_number == info_ref.number)
        .ok_or_else(|| PdfError::MetadataExtraction {
            field: "info_object".to_string(),
            message: format!("Info object {} not found in xref table", info_ref.number),
            object_id: info_ref.number,
        })?;
    
    // Extract object data from file
    let object_data = extract_object_data(file_data, info_entry)?;
    let info_dict = parse_info_dictionary(&object_data, info_ref.number)?;
    
    // Validate extracted metadata
    // Dictionary validation happens during parsing
    
    Ok(info_dict)
}

/// Extract object data from file using xref entry
fn extract_object_data(file_data: &[u8], entry: &XRefEntry) -> PdfResult<Vec<u8>> {
    let offset = entry.offset_or_index as usize;
    
    if offset >= file_data.len() {
        return Err(PdfError::Parse {
            offset: entry.offset_or_index,
            message: "Object offset beyond file size".to_string(),
            context: "object_extraction".to_string(),
        });
    }
    
    // Find the object boundary
    let search_area = &file_data[offset..];
    let content = std::str::from_utf8(search_area).map_err(|e| PdfError::Parse {
        offset: entry.offset_or_index,
        message: format!("Invalid UTF-8 in object data: {}", e),
        context: "object_parsing".to_string(),
    })?;
    
    // Find object start
    let obj_start = content.find("obj").ok_or_else(|| PdfError::Parse {
        offset: entry.offset_or_index,
        message: "Object 'obj' keyword not found".to_string(),
        context: "object_parsing".to_string(),
    })?;
    
    // Find object end
    let obj_end = content.find("endobj").ok_or_else(|| PdfError::Parse {
        offset: entry.offset_or_index,
        message: "Object 'endobj' keyword not found".to_string(),
        context: "object_parsing".to_string(),
    })?;
    
    let object_content = &content[obj_start + 3..obj_end];
    Ok(object_content.as_bytes().to_vec())
}

/// Parse Info dictionary from object data
fn parse_info_dictionary(object_data: &[u8], object_id: u32) -> PdfResult<DocumentMetadata> {
    let content = std::str::from_utf8(object_data).map_err(|e| PdfError::MetadataExtraction {
        field: "dictionary_parsing".to_string(),
        message: format!("Invalid UTF-8 in Info dictionary: {}", e),
        object_id,
    })?;
    
    // Find dictionary boundaries
    let dict_start = content.find("<<").ok_or_else(|| PdfError::MetadataExtraction {
        field: "dictionary_start".to_string(),
        message: "Info dictionary start '<<' not found".to_string(),
        object_id,
    })?;
    
    let dict_end = content.rfind(">>").ok_or_else(|| PdfError::MetadataExtraction {
        field: "dictionary_end".to_string(),
        message: "Info dictionary end '>>' not found".to_string(),
        object_id,
    })?;
    
    let dict_content = &content[dict_start + 2..dict_end];
    
    // Parse standard metadata fields
    let title = extract_string_field(dict_content, "/Title")?;
    let author = extract_string_field(dict_content, "/Author")?;
    let subject = extract_string_field(dict_content, "/Subject")?;
    let keywords = extract_string_field(dict_content, "/Keywords")?;
    let creator = extract_string_field(dict_content, "/Creator")?;
    let producer = extract_string_field(dict_content, "/Producer")?;
    let creation_date = extract_string_field(dict_content, "/CreationDate")?;
    let modification_date = extract_string_field(dict_content, "/ModDate")?;
    
    // Extract custom fields (any field not in standard set)
    let custom_fields = extract_custom_fields(dict_content)?;
    
    Ok(DocumentMetadata {
        title,
        author,
        subject,
        keywords,
        creator,
        producer,
        creation_date,
        mod_date: modification_date,
        trapped: extract_string_field(&dict_content, "/Trapped")?.map(|s| {
            match s.as_str() {
                "True" => TrappedValue::True,
                "False" => TrappedValue::False,
                _ => TrappedValue::Unknown,
            }
        }),
        custom_fields,
        raw_info_bytes: object_data.to_vec(),
        info_object_ref: Some(ObjectReference::new(object_id, 0)),
    })
}

/// Extract string value from dictionary field
fn extract_string_field(dict_content: &str, field_name: &str) -> PdfResult<Option<String>> {
    if let Some(field_pos) = dict_content.find(field_name) {
        let after_field = &dict_content[field_pos + field_name.len()..];
        
        // Skip whitespace
        let after_field = after_field.trim_start();
        
        if after_field.starts_with('(') {
            // Literal string format: (string)
            return extract_literal_string(after_field);
        } else if after_field.starts_with('<') {
            // Hex string format: <hex>
            return extract_hex_string(after_field);
        }
    }
    
    Ok(None)
}

/// Extract literal string in (string) format
fn extract_literal_string(content: &str) -> PdfResult<Option<String>> {
    if !content.starts_with('(') {
        return Ok(None);
    }
    
    let mut end_pos = 1;
    let mut paren_depth = 1;
    let mut in_escape = false;
    let chars: Vec<char> = content.chars().collect();
    
    while end_pos < chars.len() && paren_depth > 0 {
        let ch = chars[end_pos];
        
        if in_escape {
            in_escape = false;
        } else if ch == '\\' {
            in_escape = true;
        } else if ch == '(' {
            paren_depth += 1;
        } else if ch == ')' {
            paren_depth -= 1;
        }
        
        end_pos += 1;
    }
    
    if paren_depth == 0 {
        let string_content: String = chars[1..end_pos-1].iter().collect();
        Ok(Some(process_escape_sequences(&string_content)))
    } else {
        Err(PdfError::Parse {
            offset: 0,
            message: "Unterminated literal string".to_string(),
            context: "string_parsing".to_string(),
        })
    }
}

/// Extract hex string in <hex> format
fn extract_hex_string(content: &str) -> PdfResult<Option<String>> {
    if !content.starts_with('<') {
        return Ok(None);
    }
    
    if let Some(end_pos) = content.find('>') {
        let hex_content = &content[1..end_pos];
        
        // Convert hex to string
        let hex_bytes = hex::decode(hex_content).map_err(|e| PdfError::Parse {
            offset: 0,
            message: format!("Invalid hex string: {}", e),
            context: "hex_string_parsing".to_string(),
        })?;
        
        // Convert bytes to UTF-8 string
        let result_string = String::from_utf8(hex_bytes).map_err(|e| PdfError::Parse {
            offset: 0,
            message: format!("Invalid UTF-8 in hex string: {}", e),
            context: "hex_string_utf8_conversion".to_string(),
        })?;
        
        Ok(Some(result_string))
    } else {
        Err(PdfError::Parse {
            offset: 0,
            message: "Unterminated hex string".to_string(),
            context: "hex_string_parsing".to_string(),
        })
    }
}

/// Process escape sequences in literal strings
fn process_escape_sequences(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();
    
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(&next_ch) = chars.peek() {
                match next_ch {
                    'n' => {
                        result.push('\n');
                        chars.next();
                    }
                    'r' => {
                        result.push('\r');
                        chars.next();
                    }
                    't' => {
                        result.push('\t');
                        chars.next();
                    }
                    'b' => {
                        result.push('\u{0008}'); // Backspace
                        chars.next();
                    }
                    'f' => {
                        result.push('\u{000C}'); // Form feed
                        chars.next();
                    }
                    '(' => {
                        result.push('(');
                        chars.next();
                    }
                    ')' => {
                        result.push(')');
                        chars.next();
                    }
                    '\\' => {
                        result.push('\\');
                        chars.next();
                    }
                    _ => {
                        // Check for octal escape sequence
                        if next_ch.is_ascii_digit() {
                            let mut octal = String::new();
                            for _ in 0..3 {
                                if let Some(&digit_ch) = chars.peek() {
                                    if digit_ch.is_ascii_digit() && digit_ch <= '7' {
                                        octal.push(digit_ch);
                                        chars.next();
                                    } else {
                                        break;
                                    }
                                } else {
                                    break;
                                }
                            }
                            
                            if !octal.is_empty() {
                                if let Ok(code) = u8::from_str_radix(&octal, 8) {
                                    result.push(code as char);
                                } else {
                                    result.push(ch);
                                }
                            } else {
                                result.push(ch);
                            }
                        } else {
                            result.push(ch);
                        }
                    }
                }
            } else {
                result.push(ch);
            }
        } else {
            result.push(ch);
        }
    }
    
    result
}

/// Extract custom metadata fields not in standard set
fn extract_custom_fields(dict_content: &str) -> PdfResult<HashMap<String, String>> {
    let mut custom_fields = HashMap::new();
    
    let standard_fields = [
        "/Title", "/Author", "/Subject", "/Keywords",
        "/Creator", "/Producer", "/CreationDate", "/ModDate"
    ];
    
    // Find all field definitions in dictionary
    let mut pos = 0;
    while pos < dict_content.len() {
        if let Some(field_start) = dict_content[pos..].find('/') {
            let field_pos = pos + field_start;
            let field_area = &dict_content[field_pos..];
            
            // Extract field name
            let field_end = field_area.find(|c: char| c.is_whitespace() || c == '(')
                .unwrap_or(field_area.len());
            let field_name = &field_area[..field_end];
            
            // Check if this is a custom field
            if !standard_fields.contains(&field_name) {
                // Extract field value
                let _after_field = &field_area[field_end..].trim_start();
                if let Ok(Some(value)) = extract_string_field(field_area, field_name) {
                    custom_fields.insert(field_name[1..].to_string(), value); // Remove leading '/'
                }
            }
            
            pos = field_pos + field_end;
        } else {
            break;
        }
    }
    
    Ok(custom_fields)
}
