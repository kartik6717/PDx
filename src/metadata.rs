use std::collections::HashMap;
use crate::object::{Object, Dictionary, StringFormat};
use crate::{PdfDocument, PdfError, Result};

/// Remove sensitive metadata like ModDate or CreationDate.
pub fn sanitize_metadata(doc: &mut PdfDocument) -> Result<()> {
    if let Some(info) = doc.info_mut() {
        info.remove(b"ModDate");
        info.remove(b"CreationDate");
        info.remove(b"Producer");
        info.remove(b"Creator");
    }
    Ok(())
}

/// Update or insert new metadata fields.
pub fn update_metadata(doc: &mut PdfDocument, meta: HashMap<String, String>) -> Result<()> {
    let info = doc.info_mut().ok_or(PdfError::MissingTrailerEntry)?;

    for (key, value) in meta {
        info.insert(
            key.as_bytes().to_vec(),
            Object::String(value.into_bytes(), StringFormat::Literal),
        );
    }

    Ok(())
}

/// Extracts metadata from the Info dictionary into a key-value map.
pub fn extract_metadata_map(doc: &PdfDocument) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    if let Some(info) = doc.info() {
        for (key, value) in info.iter() {
            if let Ok(text) = value.as_str() {
                map.insert(String::from_utf8_lossy(key).to_string(), text.to_string());
            }
        }
    }
    Ok(map)
}

/// Converts metadata map into minimal XMP XML.
pub fn serialize_metadata_to_xmp(meta: &HashMap<String, String>) -> Result<String> {
    let mut xml = String::from(r#"<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?>"#);
    xml.push_str(r#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">"#);
    xml.push_str(r#"<rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/">"#);

    for (key, value) in meta {
        xml.push_str(&format!(r#"<dc:{}>{}</dc:{}>"#, key, escape_xml(value), key));
    }

    xml.push_str(r#"</rdf:Description></rdf:RDF></x:xmpmeta>"#);
    xml.push_str(r#"<?xpacket end="w"?>"#);

    Ok(xml)
}

/// Escapes characters for XML safety
fn escape_xml(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}