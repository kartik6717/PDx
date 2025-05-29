use crate::object::{Dictionary, Object, ObjectId};
use crate::error::PdfError;
use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use getrandom::getrandom;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

/// Creates a placeholder encryption dictionary (not actual PDF-compatible encryption yet).
pub fn create_encryption_dictionary(password: &str) -> Dictionary {
    let mut key = [0u8; 16];
    let _ = getrandom(&mut key);

    let mut dict = Dictionary::new();
    dict.insert(b"Filter".to_vec(), Object::Name(b"Standard".to_vec()));
    dict.insert(b"V".to_vec(), Object::Integer(2));
    dict.insert(b"R".to_vec(), Object::Integer(3));
    dict.insert(b"O".to_vec(), Object::String(hex::encode(key).into_bytes(), crate::object::StringFormat::Literal));
    dict.insert(b"U".to_vec(), Object::String(hex::encode(key).into_bytes(), crate::object::StringFormat::Literal));
    dict.insert(b"P".to_vec(), Object::Integer(-1852));
    dict.insert(b"Length".to_vec(), Object::Integer(128));

    dict
}