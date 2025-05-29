use crate::object::{Object, ObjectId};
use crate::error::{PdfError, Result};
use std::collections::BTreeMap;

/// Placeholder for a minimal PDF writer.
pub struct PdfWriter;

impl PdfWriter {
    pub fn write_document(
        version: &str,
        trailer: &crate::object::Dictionary,
        objects: &BTreeMap<ObjectId, Object>,
    ) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(format!("%PDF-{}\n", version).as_bytes());

        for (&(id, gen), obj) in objects {
            buffer.extend_from_slice(format!("{} {} obj\n", id, gen).as_bytes());
            buffer.extend_from_slice(format!("{:?}\nendobj\n", obj).as_bytes());
        }

        buffer.extend_from_slice(b"trailer\n");
        buffer.extend_from_slice(format!("{:?}\n", trailer).as_bytes());
        buffer.extend_from_slice(b"startxref\n0\n%%EOF");

        Ok(buffer)
    }
}