use crate::object::{Dictionary, Object, ObjectId};
use crate::error::PdfError;
use std::collections::BTreeMap;

/// Represents a PDF document with all its objects and metadata.
#[derive(Debug, Clone)]
pub struct PdfDocument {
    pub objects: BTreeMap<ObjectId, Object>,
    pub trailer: Dictionary,
    pub version: String,
}

impl PdfDocument {
    /// Loads a PDF document from bytes (placeholder stub for WASM use).
    pub fn load(_data: &[u8]) -> Result<Self, PdfError> {
        Ok(PdfDocument {
            objects: BTreeMap::new(),
            trailer: Dictionary::new(),
            version: "1.7".to_string(),
        })
    }

    /// Retrieves an object by its ID (read-only).
    pub fn get_object(&self, id: ObjectId) -> Option<&Object> {
        self.objects.get(&id)
    }

    /// Retrieves a mutable reference to an object by its ID.
    pub fn get_object_mut(&mut self, id: ObjectId) -> Option<&mut Object> {
        self.objects.get_mut(&id)
    }

    /// Adds a new object and returns its assigned ID.
    pub fn add_object(&mut self, obj: Object) -> ObjectId {
        let new_id = ObjectId(self.objects.len() as u32 + 1, 0);
        self.objects.insert(new_id, obj);
        new_id
    }

    /// Returns the highest used object ID (or 1,0 if empty).
    pub fn max_id(&self) -> ObjectId {
        self.objects.keys().cloned().max().unwrap_or((1, 0))
    }
}