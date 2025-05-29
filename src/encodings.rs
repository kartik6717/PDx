pub const WIN_ANSI_ENCODING: [char; 256] = include!("encoding_tables/win_ansi.rs");
pub const MAC_ROMAN_ENCODING: [char; 256] = include!("encoding_tables/mac_roman.rs");
pub const MAC_EXPERT_ENCODING: [char; 256] = include!("encoding_tables/mac_expert.rs");
pub const STANDARD_ENCODING: [char; 256] = include!("encoding_tables/standard.rs");
pub const PDF_DOC_ENCODING: [char; 256] = include!("encoding_tables/pdf_doc.rs");

/// A font encoding used for decoding character codes.
#[derive(Clone, Copy)]
pub enum Encoding<'a> {
    OneByteEncoding(&'a [char; 256]),
    SimpleEncoding(&'a [u8]),
    UnicodeMapEncoding(crate::encodings::cmap::ToUnicodeCMap),
}

pub fn string_to_bytes(encoding: &[char; 256], text: &str) -> Vec<u8> {
    text.chars()
        .map(|c| {
            encoding
                .iter()
                .position(|&ch| ch == c)
                .unwrap_or(b'?'.into())
                as u8
        })
        .collect()
}

pub fn bytes_to_string(encoding: &[char; 256], bytes: &[u8]) -> String {
    bytes.iter().map(|&b| encoding[b as usize]).collect()
}

pub fn encode_utf16_be(text: &str) -> Vec<u8> {
    let mut encoded = vec![0xFE, 0xFF]; // UTF-16BE BOM
    for unit in text.encode_utf16() {
        encoded.extend_from_slice(&unit.to_be_bytes());
    }
    encoded
}