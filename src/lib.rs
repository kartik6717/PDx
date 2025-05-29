use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn process_pdf(input: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mut doc = PdfDocument::load_bytes(input).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    crate::verifier::verify_pdf(&doc).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    crate::metadata::sanitize_metadata(&mut doc).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    let bytes = crate::writer::save_pdf(&doc).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    Ok(bytes)
}

#![allow(clippy::result_large_err)]

mod document;
mod encryption;
mod error;
mod metadata;
mod object;
mod parser;
mod permission;
mod security;
mod utils;
mod verifier;
mod writer;
mod xmp;

#[cfg(feature = "wasm")]
mod wasm;

pub use document::PdfDocument;
pub use error::{PdfError, Result};
pub use metadata::{sanitize_metadata, update_metadata};
pub use object::{
    Dictionary, Object, ObjectId, Stream, StringFormat,
};
pub use parser::parse_pdf;
pub use permission::Permissions;
pub use security::{encrypt_pdf, decrypt_pdf};
pub use verifier::verify_pdf;
pub use writer::save_pdf;
pub use xmp::sync_xmp;

#[cfg(feature = "wasm")]
pub use wasm::*;