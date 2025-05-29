use thiserror::Error;

/// Error types for stream decompression.
#[derive(Debug, Error)]
pub enum DecompressError {
    #[error("Flate (zlib) decompression failed")]
    Flate,

    #[error("LZW decompression failed")]
    Lzw,

    #[error("RunLength decompression failed")]
    RunLength,

    #[error("ASCII85 decoding failed")]
    Ascii85(&'static str),

    #[error("unsupported or unknown compression filter")]
    UnsupportedFilter,
}