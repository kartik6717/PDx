use crate::document::PdfDocument;
use crate::error::{PdfError, Result};
use crate::object::{Object, ObjectId};
use crate::parser::parse_document;
use crate::writer::write_document;

/// Loads a PDF document from bytes.
pub fn load_pdf(data: &[u8]) -> Result<PdfDocument> {
    parse_document(data)
}

/// Saves a PDF document to bytes.
pub fn save_pdf(doc: &PdfDocument) -> Result<Vec<u8>> {
    write_document(doc)
}

/// Gets an object by ID.
pub fn get_object(doc: &PdfDocument, id: ObjectId) -> Result<&Object> {
    doc.objects.get(&id).ok_or(PdfError::ObjectNotFound(id))
}

/// Gets a mutable object by ID.
pub fn get_object_mut(doc: &mut PdfDocument, id: ObjectId) -> Result<&mut Object> {
    doc.objects.get_mut(&id).ok_or(PdfError::ObjectNotFound(id))
}