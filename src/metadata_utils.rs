use crate::object::{Dictionary, Object, ObjectId};
use crate::pdf_metadata::{parse_xmp, Metadata};
use crate::PdfDocument;
use crate::error::PdfError;

/// Retrieves the Info dictionary metadata from the PDF trailer.
pub fn get_info_metadata(doc: &PdfDocument) -> Result<Metadata, PdfError> {
    let info_ref = doc.trailer.get(b"Info").and_then(Object::as_reference)?;
    let dict = doc.get_object(info_ref)?.as_dict()?;
    Metadata::from_info_dict(dict)
}

/// Extracts and parses XMP metadata if present.
pub fn get_xmp_metadata(doc: &PdfDocument) -> Result<Option<Metadata>, PdfError> {
    let catalog_ref = doc.trailer.get(b"Root").and_then(Object::as_reference)?;
    let catalog = doc.get_object(catalog_ref)?.as_dict()?;

    let metadata_ref = catalog.get(b"Metadata").and_then(Object::as_reference).ok();
    if let Some(obj_id) = metadata_ref {
        let stream = doc.get_object(obj_id)?.as_stream()?;
        let content = String::from_utf8_lossy(&stream.content).to_string();
        Ok(parse_xmp(&content).ok())
    } else {
        Ok(None)
    }
}

/// Syncs the given Metadata struct into both DocInfo and XMP.
pub fn apply_metadata(doc: &mut PdfDocument, metadata: &Metadata) -> Result<(), PdfError> {
    let info_id = doc.trailer.get(b"Info").and_then(Object::as_reference)?;
    let dict = doc.get_object_mut(info_id)?.as_dict_mut()?;
    metadata.apply_to_info_dict(dict)?;

    // Also sync to XMP if exists
    if let Some(xmp_id) = get_xmp_object_id(doc) {
        let xmp_string = metadata.to_xmp();
        if let Some(Object::Stream(stream)) = doc.get_object_mut(xmp_id) {
            stream.content = xmp_string.into_bytes();
        }
    }

    Ok(())
}

/// Retrieves XMP metadata object ID, if it exists.
fn get_xmp_object_id(doc: &PdfDocument) -> Option<ObjectId> {
    let catalog_ref = doc.trailer.get(b"Root").and_then(Object::as_reference).ok()?;
    let catalog = doc.get_object(catalog_ref).ok()?.as_dict().ok()?;
    catalog.get(b"Metadata").and_then(Object::as_reference).ok()
}