use crate::{
    object::{Object, Stream, StringFormat},
    PdfDocument, PdfError, Result,
};
use std::collections::HashMap;

/// Synchronize DocInfo metadata into XMP stream.
pub fn sync_xmp(doc: &mut PdfDocument) -> Result<()> {
    let meta = extract_metadata_map(doc)?;
    let xmp = serialize_metadata_to_xmp(&meta)?;

    // Create XMP stream
    let mut dict = HashMap::new();
    dict.insert(b"Type".to_vec(), Object::Name(b"Metadata".to_vec()));
    dict.insert(b"Subtype".to_vec(), Object::Name(b"XML".to_vec()));
    dict.insert(b"Length".to_vec(), Object::Integer(xmp.len() as i64));

    let xmp_obj = Object::Stream(Stream {
        dict: dict.into(),
        content: xmp.into_bytes(),
    });

    // Remove old metadata if present
    let catalog_id = doc.trailer.get(b"Root").and_then(Object::as_reference).ok_or(PdfError::MissingXrefEntry)?;
    let catalog = doc.get_object_mut(catalog_id)?.as_dict_mut().ok_or(PdfError::ExpectedDictionary)?;

    if let Some(Object::Reference(old_id)) = catalog.remove(b"Metadata") {
        doc.objects.remove(&old_id);
    }

    let xmp_id = doc.add_object(xmp_obj);
    catalog.insert(b"Metadata".to_vec(), Object::Reference(xmp_id));

    Ok(())
}

/// Extract metadata from the Info dictionary into a key-value map.
fn extract_metadata_map(doc: &PdfDocument) -> Result<HashMap<String, String>> {
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
fn serialize_metadata_to_xmp(meta: &HashMap<String, String>) -> Result<String> {
    let mut xml = String::from(r#"<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?>"#);
    xml.push_str(r#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">"#);
    xml.push_str(r#"<rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/">"#);

    for (key, value) in meta {
        xml.push_str(&format!(r#"<dc:{}>{}</dc:{}>"#, key, value, key));
    }

    xml.push_str(r#"</rdf:Description></rdf:RDF></x:xmpmeta>"#);
    xml.push_str(r#"<?xpacket end="w"?>"#);

    Ok(xml)
}