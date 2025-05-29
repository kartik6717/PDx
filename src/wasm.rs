use wasm_bindgen::prelude::*;
use crate::{
    encrypt_pdf, sanitize_pdf, update_pdf_metadata, verify_pdf_file,
};

#[wasm_bindgen]
pub fn sanitize_pdf_wasm(data: &[u8]) -> Result<Vec<u8>, JsValue> {
    sanitize_pdf(data).map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn update_metadata_wasm(data: &[u8], metadata_json: &str) -> Result<Vec<u8>, JsValue> {
    update_pdf_metadata(data, metadata_json).map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn encrypt_pdf_wasm(data: &[u8], password: &str) -> Result<Vec<u8>, JsValue> {
    encrypt_pdf(data, password).map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn verify_pdf_wasm(data: &[u8]) -> Result<JsValue, JsValue> {
    let info = verify_pdf_file(data).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    JsValue::from_serde(&info).map_err(|e| JsValue::from_str(&e.to_string()))
}