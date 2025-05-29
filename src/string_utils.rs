use crate::encodings::pdf_doc::PDF_DOC_ENCODING;
use crate::object::{Object, StringFormat};
use crate::error::{PdfError, Result};

/// Encodes a text string to a PDF string object.
pub fn encode_pdf_string(text: &str) -> Object {
    if text.is_ascii() {
        Object::String(text.into(), StringFormat::Literal)
    } else {
        Object::String(encode_utf16be(text), StringFormat::Hexadecimal)
    }
}

/// Decodes a text string object into a Rust String.
pub fn decode_pdf_string(obj: &Object) -> Result<String> {
    let data = obj.as_str()?;
    if data.starts_with(b"\xFE\xFF") {
        // UTF-16BE with BOM
        decode_utf16be(&data[2..])
    } else {
        // Fallback to PDFDocEncoding
        Ok(bytes_to_string(&PDF_DOC_ENCODING, data))
    }
}

/// Encode Rust string to UTF-16BE bytes.
pub fn encode_utf16be(input: &str) -> Vec<u8> {
    input.encode_utf16()
        .flat_map(|u| u.to_be_bytes())
        .collect()
}

/// Decode UTF-16BE bytes to Rust String.
pub fn decode_utf16be(bytes: &[u8]) -> Result<String> {
    if bytes.len() % 2 != 0 {
        return Err(PdfError::TextStringDecode);
    }
    let utf16: Vec<u16> = bytes.chunks(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16(&utf16).map_err(|_| PdfError::TextStringDecode)
}

/// Convert a byte slice using PDFDocEncoding to a Rust string.
pub fn bytes_to_string(encoding: &[&str], bytes: &[u8]) -> String {
    bytes.iter().map(|&b| {
        if (b as usize) < encoding.len() {
            encoding[b as usize]
        } else {
            "\u{FFFD}" // Replacement character for unknown
        }
    }).collect::<String>()
}