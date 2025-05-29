pub mod cmap;
pub mod pdf_doc;

pub mod mac_expert;
pub mod mac_roman;
pub mod standard;
pub mod win_ansi;

pub use self::mac_expert::MAC_EXPERT_ENCODING;
pub use self::mac_roman::MAC_ROMAN_ENCODING;
pub use self::pdf_doc::PDF_DOC_ENCODING;
pub use self::standard::STANDARD_ENCODING;
pub use self::win_ansi::WIN_ANSI_ENCODING;

/// Returns a string from a byte slice using a given encoding.
pub fn bytes_to_string(encoding: &[&str; 256], bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| encoding[b as usize])
        .collect::<Vec<&str>>()
        .concat()
}

/// Encodes a Rust string into UTF-16BE byte format (used for PDF strings).
pub fn encode_utf16_be(s: &str) -> Vec<u8> {
    let mut out = vec![0xFE, 0xFF]; // BOM for UTF-16BE
    for code_unit in s.encode_utf16() {
        out.push((code_unit >> 8) as u8);
        out.push((code_unit & 0xFF) as u8);
    }
    out
}