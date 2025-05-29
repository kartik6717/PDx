use crate::object::{Object, Stream};
use crate::error::PdfError;

/// Extracts raw XMP metadata XML string from a PDF metadata stream.
pub fn extract_xmp_metadata(stream: &Stream) -> Result<String, PdfError> {
    let data = &stream.content;
    let xml = std::str::from_utf8(data).map_err(|_| PdfError::TextStringDecode)?;
    Ok(xml.to_string())
}

/// Replaces the contents of a metadata stream with a new XMP XML string.
pub fn update_xmp_metadata(stream: &mut Stream, xmp_xml: &str) {
    stream.content = xmp_xml.as_bytes().to_vec();
    stream.dict.set("Length", Object::Integer(stream.content.len() as i64));
}