use crate::object::{Dictionary, Object, ObjectId};
use crate::error::{PdfError, Result};

use std::collections::BTreeMap;

/// Placeholder for a minimal PDF parser.
pub struct PdfReader;

#[derive(Debug, Clone)]
pub struct PdfParsed {
    pub version: String,
    pub trailer: Dictionary,
    pub objects: BTreeMap<ObjectId, Object>,
}

impl PdfReader {
    pub fn parse_document(_data: &[u8]) -> Result<PdfParsed> {
        // Placeholder: return a dummy document with no objects.
        Ok(PdfParsed {
            version: "1.7".into(),
            trailer: Dictionary::new(),
            objects: BTreeMap::new(),
        })
    }
}