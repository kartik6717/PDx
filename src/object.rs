use std::fmt;
use std::ops::{Deref, DerefMut};
use indexmap::IndexMap;
use crate::error::PdfError;

/// Represents a PDF object ID (object number, generation number)
pub type ObjectId = (u32, u16);

/// Represents a PDF dictionary (key-value map)
#[derive(Clone, PartialEq, Eq)]
pub struct Dictionary(pub IndexMap<Vec<u8>, Object>);

impl Dictionary {
    pub fn new() -> Self {
        Dictionary(IndexMap::new())
    }

    pub fn insert(&mut self, key: Vec<u8>, value: Object) {
        self.0.insert(key, value);
    }

    pub fn get(&self, key: &[u8]) -> Option<&Object> {
        self.0.get(key)
    }

    pub fn get_mut(&mut self, key: &[u8]) -> Option<&mut Object> {
        self.0.get_mut(key)
    }

    pub fn remove(&mut self, key: &[u8]) -> Option<Object> {
        self.0.swap_remove(key)
    }

    pub fn contains_key(&self, key: &[u8]) -> bool {
        self.0.contains_key(key)
    }

    pub fn iter(&self) -> indexmap::map::Iter<Vec<u8>, Object> {
        self.0.iter()
    }
}

impl Default for Dictionary {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Dictionary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.0.iter()).finish()
    }
}

impl Deref for Dictionary {
    type Target = IndexMap<Vec<u8>, Object>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Dictionary {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Represents a PDF stream object
#[derive(Debug, Clone, PartialEq)]
pub struct Stream {
    pub dict: Dictionary,
    pub content: Vec<u8>,
}

/// Format of PDF string
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringFormat {
    Literal,
    Hexadecimal,
}

/// Core enum representing all possible PDF objects
#[derive(Debug, Clone, PartialEq)]
pub enum Object {
    Null,
    Boolean(bool),
    Integer(i64),
    Real(f64),
    Name(Vec<u8>),
    String(Vec<u8>, StringFormat),
    Array(Vec<Object>),
    Dictionary(Dictionary),
    Stream(Stream),
    Reference(ObjectId),
}

impl Object {
    pub fn as_str(&self) -> Result<&str, PdfError> {
        match self {
            Object::String(bytes, _) => Ok(std::str::from_utf8(bytes).unwrap_or("").trim()),
            _ => Err(PdfError::UnexpectedType("String")),
        }
    }

    pub fn as_reference(&self) -> Option<&ObjectId> {
        match self {
            Object::Reference(id) => Some(id),
            _ => None,
        }
    }

    pub fn as_dict(&self) -> Option<&Dictionary> {
        match self {
            Object::Dictionary(dict) => Some(dict),
            _ => None,
        }
    }

    pub fn as_dict_mut(&mut self) -> Option<&mut Dictionary> {
        match self {
            Object::Dictionary(ref mut dict) => Some(dict),
            _ => None,
        }
    }

    pub fn as_stream(&self) -> Result<&Stream, PdfError> {
        match self {
            Object::Stream(s) => Ok(s),
            _ => Err(PdfError::UnexpectedType("Stream")),
        }
    }
}