use flate2::read::ZlibDecoder;
use std::io::Read;
use crate::error::{PdfError, Result};

/// Decode FlateDecode (zlib-compressed) PDF stream data.
pub fn decode_flate(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decoded = Vec::new();
    decoder.read_to_end(&mut decoded)?;
    Ok(decoded)
}