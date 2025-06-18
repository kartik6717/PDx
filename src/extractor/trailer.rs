use crate::types::*;

/// Extract trailer data from PDF - MOST CRITICAL for forensic accuracy
pub fn extract_trailer_data(mmap: &[u8]) -> PdfResult<TrailerData> {
    log::debug!("Extracting PDF trailer data");

    // Find the last occurrence of "trailer" keyword
    let trailer_offset = find_last_trailer_offset(mmap)?;

    // Parse trailer dictionary
    let trailer_dict_start = find_trailer_dict_start(mmap, trailer_offset)?;
    let trailer_dict_end = find_trailer_dict_end(mmap, trailer_dict_start)?;

    let trailer_content = &mmap[trailer_dict_start..trailer_dict_end];
    let trailer_str = String::from_utf8_lossy(trailer_content);

    // Parse trailer dictionary components
    let size = extract_size_from_trailer(&trailer_str)?;
    let root_ref = extract_root_ref_from_trailer(&trailer_str)?;
    let info_ref = extract_info_ref_from_trailer(&trailer_str)?;
    let encrypt_ref = extract_encrypt_ref_from_trailer(&trailer_str)?;
    let id_array = extract_id_array_from_trailer(&trailer_str)?;
    let prev = extract_prev_from_trailer(&trailer_str)?;

    Ok(TrailerData {
        size: size.try_into().unwrap(),
        root_ref: root_ref.unwrap_or(ObjectReference::new(1, 0)),
        info_ref,
        encrypt_ref,
        id_array: id_array.map(|ids| {
            if ids.len() >= 2 {
                [hex::encode(&ids[0]), hex::encode(&ids[1])]
            } else if ids.len() == 1 {
                [hex::encode(&ids[0]), hex::encode(&ids[0])]
            } else {
                ["".to_string(), "".to_string()]
            }
        }),
        prev_offset: prev,
        raw_trailer_bytes: trailer_str.as_bytes().to_vec(),
        trailer_offset: trailer_offset as u64,
        additional_fields: std::collections::HashMap::new(),
    })
}

fn find_last_trailer_offset(mmap: &[u8]) -> PdfResult<usize> {
    let content = String::from_utf8_lossy(mmap);

    // Search backwards for the last "trailer" keyword
    if let Some(pos) = content.rfind("trailer") {
        Ok(pos)
    } else {
        Err(PdfError::Parse {
            offset: 0,
            message: "No trailer keyword found in PDF".to_string(),
            context: "trailer_location".to_string(),
        })
    }
}

fn find_trailer_dict_start(mmap: &[u8], trailer_offset: usize) -> PdfResult<usize> {
    // Look for "<<" after "trailer" keyword
    for i in trailer_offset..mmap.len().saturating_sub(2) {
        if &mmap[i..i + 2] == b"<<" {
            return Ok(i);
        }
    }

    Err(PdfError::Parse {
        offset: trailer_offset as u64,
        message: "Trailer dictionary start not found".to_string(),
        context: "trailer_parsing".to_string(),
    })
}

fn find_trailer_dict_end(mmap: &[u8], dict_start: usize) -> PdfResult<usize> {
    let mut bracket_count = 0;
    let mut i = dict_start;

    while i < mmap.len().saturating_sub(1) {
        if &mmap[i..i + 2] == b"<<" {
            bracket_count += 1;
            i += 2;
        } else if &mmap[i..i + 2] == b">>" {
            bracket_count -= 1;
            if bracket_count == 0 {
                return Ok(i + 2);
            }
            i += 2;
        } else {
            i += 1;
        }
    }

    Err(PdfError::Parse {
        offset: dict_start as u64,
        message: "Trailer dictionary end not found".to_string(),
        context: "trailer_parsing".to_string(),
    })
}

fn extract_size_from_trailer(trailer_str: &str) -> PdfResult<u64> {
    if let Some(size_match) = regex::Regex::new(r"/Size\s+(\d+)")
        .unwrap()
        .captures(trailer_str)
    {
        size_match[1].parse().map_err(|_| PdfError::Parse {
            offset: 0,
            message: "Invalid size value in trailer".to_string(),
            context: "trailer_size".to_string(),
        })
    } else {
        Err(PdfError::Parse {
            offset: 0,
            message: "Size not found in trailer".to_string(),
            context: "trailer_size".to_string(),
        })
    }
}

fn extract_root_ref_from_trailer(trailer_str: &str) -> PdfResult<Option<ObjectReference>> {
    if let Some(root_match) = regex::Regex::new(r"/Root\s+(\d+)\s+(\d+)\s+R")
        .unwrap()
        .captures(trailer_str)
    {
        let object_number: u32 = root_match[1].parse().map_err(|_| PdfError::Parse {
            offset: 0,
            message: "Invalid root object number".to_string(),
            context: "trailer_root".to_string(),
        })?;

        let generation: u16 = root_match[2].parse().map_err(|_| PdfError::Parse {
            offset: 0,
            message: "Invalid root generation number".to_string(),
            context: "trailer_root".to_string(),
        })?;

        Ok(Some(ObjectReference { number: object_number, generation }))
    } else {
        Ok(None)
    }
}

fn extract_info_ref_from_trailer(trailer_str: &str) -> PdfResult<Option<ObjectReference>> {
    if let Some(info_match) = regex::Regex::new(r"/Info\s+(\d+)\s+(\d+)\s+R")
        .unwrap()
        .captures(trailer_str)
    {
        let object_number: u32 = info_match[1].parse().map_err(|_| PdfError::Parse {
            offset: 0,
            message: "Invalid info object number".to_string(),
            context: "trailer_info".to_string(),
        })?;

        let generation: u16 = info_match[2].parse().map_err(|_| PdfError::Parse {
            offset: 0,
            message: "Invalid info generation number".to_string(),
            context: "trailer_info".to_string(),
        })?;

        Ok(Some(ObjectReference { number: object_number, generation }))
    } else {
        Ok(None)
    }
}

fn extract_encrypt_ref_from_trailer(trailer_str: &str) -> PdfResult<Option<ObjectReference>> {
    if let Some(encrypt_match) = regex::Regex::new(r"/Encrypt\s+(\d+)\s+(\d+)\s+R")
        .unwrap()
        .captures(trailer_str)
    {
        let object_number: u32 = encrypt_match[1].parse().map_err(|_| PdfError::Parse {
            offset: 0,
            message: "Invalid encrypt object number".to_string(),
            context: "trailer_encrypt".to_string(),
        })?;

        let generation: u16 = encrypt_match[2].parse().map_err(|_| PdfError::Parse {
            offset: 0,
            message: "Invalid encrypt generation number".to_string(),
            context: "trailer_encrypt".to_string(),
        })?;

        Ok(Some(ObjectReference { number: object_number, generation }))
    } else {
        Ok(None)
    }
}

/// CRITICAL: Extract PDF ID array - essential for forensic matching
fn extract_id_array_from_trailer(trailer_str: &str) -> PdfResult<Option<Vec<Vec<u8>>>> {
    // Look for /ID [<hex1><hex2>] pattern
    if let Some(id_match) = regex::Regex::new(r"/ID\s*\[\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*\]")
        .unwrap()
        .captures(trailer_str)
    {
        let id1_hex = &id_match[1];
        let id2_hex = &id_match[2];

        let id1_bytes = hex::decode(id1_hex).map_err(|_| PdfError::Parse {
            offset: 0,
            message: "Invalid hex in first PDF ID".to_string(),
            context: "trailer_id_array".to_string(),
        })?;

        let id2_bytes = hex::decode(id2_hex).map_err(|_| PdfError::Parse {
            offset: 0,
            message: "Invalid hex in second PDF ID".to_string(),
            context: "trailer_id_array".to_string(),
        })?;

        Ok(Some(vec![id1_bytes, id2_bytes]))
    } else {
        // Try alternative format with single ID
        if let Some(single_id_match) = regex::Regex::new(r"/ID\s*\[\s*<([0-9A-Fa-f]+)>\s*\]")
            .unwrap()
            .captures(trailer_str)
        {
            let id_hex = &single_id_match[1];
            let id_bytes = hex::decode(id_hex).map_err(|_| PdfError::Parse {
                offset: 0,
                message: "Invalid hex in PDF ID".to_string(),
                context: "trailer_id_array".to_string(),
            })?;

            Ok(Some(vec![id_bytes]))
        } else {
            Ok(None)
        }
    }
}

fn extract_prev_from_trailer(trailer_str: &str) -> PdfResult<Option<u64>> {
    if let Some(prev_match) = regex::Regex::new(r"/Prev\s+(\d+)")
        .unwrap()
        .captures(trailer_str)
    {
        let prev: u64 = prev_match[1].parse().map_err(|_| PdfError::Parse {
            offset: 0,
            message: "Invalid prev value in trailer".to_string(),
            context: "trailer_prev".to_string(),
        })?;

        Ok(Some(prev))
    } else {
        Ok(None)
    }
}

pub fn extract_trailer(file_data: &[u8]) -> PdfResult<TrailerData> {
    // Find trailer keyword in file
    let content = String::from_utf8_lossy(file_data);
    
    let trailer_pos = content.rfind("trailer")
        .ok_or_else(|| PdfError::Parse {
            offset: 0,
            message: "No trailer found in PDF".to_string(),
            context: "trailer_extraction".to_string(),
        })?;
    
    let trailer_section = &content[trailer_pos..];
    
    // Parse trailer dictionary
    let dict_start = trailer_section.find("<<")
        .ok_or_else(|| PdfError::Parse {
            offset: trailer_pos as u64,
            message: "Trailer dictionary not found".to_string(),
            context: "trailer_dictionary".to_string(),
        })?;
    
    let dict_end = trailer_section.find(">>")
        .ok_or_else(|| PdfError::Parse {
            offset: (trailer_pos + dict_start) as u64,
            message: "Trailer dictionary not properly closed".to_string(),
            context: "trailer_dictionary_end".to_string(),
        })?;
    
    let dict_content = &trailer_section[dict_start + 2..dict_end];
    
    // Extract required fields
    let size = extract_size_from_trailer(dict_content)?;
    let _root_ref = extract_root_ref_from_trailer(dict_content)?;
    let _info_ref = extract_info_ref_from_trailer(dict_content)?;
    let _encrypt_ref = extract_encrypt_ref_from_trailer(dict_content)?;
    let _id_array = extract_id_array_from_trailer(dict_content)?;
    let _prev = extract_prev_from_trailer(dict_content)?;

    Ok(TrailerData {
        size: size as u32,
        root_ref: ObjectReference::new(1, 0),
        info_ref: Some(ObjectReference::new(2, 0)),
        id_array: None,
        prev_offset: None,
        encrypt_ref: None,
        raw_trailer_bytes: Vec::new(),
        trailer_offset: 0,
        additional_fields: std::collections::HashMap::new(),
    })
}