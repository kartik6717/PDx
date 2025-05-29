use crate::encodings::pdf_doc::PDF_DOC_ENCODING;
use crate::encodings::{bytes_to_string, encode_utf16_be};
use crate::object::{Object, StringFormat};
use crate::error::{PdfError, Result};

/// Encodes a Rust string into a PDF string object.
/// Uses PDFDocEncoding if all characters are ASCII, otherwise uses UTF-16BE with BOM.
pub fn encode_pdf_string(text: &str) -> Object {
    if text.is_ascii() {
        Object::String(text.as_bytes().to_vec(), StringFormat::Literal)
    } else {
        let mut encoded = vec![0xFE, 0xFF]; // BOM
        encoded.extend(encode_utf16_be(text));
        Object::String(encoded, StringFormat::Hexadecimal)
    }
}

/// Decodes a PDF string object into a Rust String.
/// Handles PDFDocEncoding, UTF-16BE (with BOM), and UTF-8 BOM fallback.
pub fn decode_pdf_string(obj: &Object) -> Result<String> {
    let s = obj.as_str()?;
    if s.starts_with(b"\xFE\xFF") {
        // UTF-16BE with BOM
        let utf16: Vec<u16> = s[2..]
            .chunks(2)
            .map(|chunk| {
                if chunk.len() == 2 {
                    u16::from_be_bytes([chunk[0], chunk[1]])
                } else {
                    u16::from_be_bytes([chunk[0], 0])
                }
            })
            .collect();
        String::from_utf16(&utf16).map_err(|_| PdfError::TextStringDecode)
    } else if s.starts_with(b"\xEF\xBB\xBF") {
        // UTF-8 BOM
        String::from_utf8(s.to_vec()).map_err(|_| PdfError::TextStringDecode)
    } else {
        // PDFDocEncoding fallback
        Ok(bytes_to_string(&PDF_DOC_ENCODING, s))
    }
}