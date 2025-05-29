use crate::object::{Dictionary, Object};
use crate::error::PdfError;

/// Extracts common metadata fields from a PDF dictionary.
pub fn extract_metadata(info_dict: &Dictionary) -> Result<Metadata, PdfError> {
    Ok(Metadata {
        title: get_string(info_dict, b"Title")?,
        author: get_string(info_dict, b"Author")?,
        subject: get_string(info_dict, b"Subject")?,
        keywords: get_string(info_dict, b"Keywords")?,
        creator: get_string(info_dict, b"Creator")?,
        producer: get_string(info_dict, b"Producer")?,
        creation_date: get_string(info_dict, b"CreationDate")?,
        mod_date: get_string(info_dict, b"ModDate")?,
    })
}

fn get_string(dict: &Dictionary, key: &[u8]) -> Result<Option<String>, PdfError> {
    if let Ok(obj) = dict.get(key) {
        if let Ok(bytes) = obj.as_str() {
            return Ok(Some(String::from_utf8_lossy(bytes).to_string()));
        }
    }
    Ok(None)
}

/// Structure to hold extracted metadata.
#[derive(Debug, Default)]
pub struct Metadata {
    pub title: Option<String>,
    pub author: Option<String>,
    pub subject: Option<String>,
    pub keywords: Option<String>,
    pub creator: Option<String>,
    pub producer: Option<String>,
    pub creation_date: Option<String>,
    pub mod_date: Option<String>,
}