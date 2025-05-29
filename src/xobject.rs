use crate::object::{Dictionary, Object, Stream};

/// XObject subtype identifiers
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XObjectSubtype {
    Image,
    Form,
    Unknown(Vec<u8>),
}

/// Extracts the subtype of an XObject from its dictionary
pub fn get_xobject_subtype(dict: &Dictionary) -> XObjectSubtype {
    match dict.get(b"Subtype") {
        Ok(Object::Name(name)) => match name.as_slice() {
            b"Image" => XObjectSubtype::Image,
            b"Form" => XObjectSubtype::Form,
            other => XObjectSubtype::Unknown(other.to_vec()),
        },
        _ => XObjectSubtype::Unknown(b"Unknown".to_vec()),
    }
}

/// Represents a parsed XObject
#[derive(Debug, Clone)]
pub struct XObject {
    pub subtype: XObjectSubtype,
    pub stream: Stream,
}

impl XObject {
    pub fn from_stream(stream: Stream) -> Self {
        let subtype = get_xobject_subtype(&stream.dict);
        XObject { subtype, stream }
    }

    pub fn is_image(&self) -> bool {
        self.subtype == XObjectSubtype::Image
    }

    pub fn is_form(&self) -> bool {
        self.subtype == XObjectSubtype::Form
    }
}