use crate::object::{Dictionary, Object, ObjectId};
use crate::error::{PdfError, Result};
use std::collections::BTreeMap;

/// Represents a minimal PDF document structure for WASM use.
#[derive(Debug, Clone)]
pub struct PdfDocument {
    pub objects: BTreeMap<ObjectId, Object>,
    pub trailer: Dictionary,
    pub version: String,
}

impl PdfDocument {
    /// Load the PDF from bytes (placeholder for WASM).
    pub fn load(_data: &[u8]) -> Result<Self> {
        Ok(PdfDocument {
            objects: BTreeMap::new(),
            trailer: Dictionary::new(),
            version: "1.7".to_string(),
        })
    }

    /// Retrieve object by ID.
    pub fn get_object(&self, id: ObjectId) -> Option<&Object> {
        self.objects.get(&id)
    }

    /// Retrieve mutable object by ID.
    pub fn get_object_mut(&mut self, id: ObjectId) -> Option<&mut Object> {
        self.objects.get_mut(&id)
    }

    /// Add a new object and return its ID.
    pub fn add_object(&mut self, obj: Object) -> ObjectId {
        let new_id = (self.objects.len() as u32 + 1, 0);
        self.objects.insert(new_id, obj);
        new_id
    }

    /// Return max object ID or default.
    pub fn max_id(&self) -> ObjectId {
        self.objects.keys().cloned().max().unwrap_or((1, 0))
    }
}