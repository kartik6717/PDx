use std::io;
use thiserror::Error;
use crate::object::ObjectId;

/// Top-level result alias for the PDF library
pub type Result<T> = std::result::Result<T, PdfError>;

#[derive(Error, Debug)]
pub enum PdfError {
    #[error("Unimplemented feature: {0}")]
    Unimplemented(String),

    #[error("Wrong object type: expected {expected}, found {found}")]
    WrongType { expected: String, found: String },

    #[error("Wrong dictionary type: expected {expected}, found {found}")]
    WrongDictionaryType { expected: String, found: String },

    #[error("PDF is already encrypted")]
    AlreadyEncrypted,

    #[error("PDF is not encrypted")]
    NotEncrypted,

    #[error("Missing trailer entry: {0}")]
    MissingTrailerEntry(&'static str),

    #[error("Missing key: {0}")]
    MissingKey(String),

    #[error("Invalid encoding")]
    InvalidEncoding,

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Decompression error: {0}")]
    Decompress(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Missing xref entry")]
    MissingXrefEntry,

    #[error("Object not found: {0:?}")]
    ObjectNotFound(ObjectId),

    #[error("Reference cycle detected for object {0:?}")]
    ReferenceCycle(ObjectId),

    #[error("Page number not found")]
    PageNotFound,

    #[error("Integer cast failed: {0}")]
    TryFromInt(#[from] std::num::TryFromIntError),

    #[error("Verification failed: {0}")]
    VerificationFailed(&'static str),

    #[error("Unexpected object type: {0}")]
    UnexpectedType(&'static str),

    #[error("ToUnicode CMap parse error: {0}")]
    ToUnicodeCMap(String),

    #[error("Invalid trailer")]
    InvalidTrailer,

    #[error("Invalid xref table")]
    InvalidXref,

    #[error("Invalid startxref")]
    InvalidStartXref,

    #[error("Invalid content stream")]
    InvalidContentStream,

    #[error("Invalid file header")]
    InvalidFileHeader,

    #[error("Unsupported security handler: {0:?}")]
    UnsupportedSecurityHandler(String),
}