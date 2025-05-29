pub mod flate;

use crate::object::Stream;
use crate::error::{PdfError, Result};

/// Decompress a stream if it has known filters.
pub fn decode_stream(stream: &Stream) -> Result<Vec<u8>> {
    if let Some(filters) = stream.filters() {
        let mut data = stream.content.clone();
        for filter in filters {
            match filter.as_str() {
                "FlateDecode" => {
                    data = flate::decode_flate(&data)?;
                }
                unknown => {
                    return Err(PdfError::UnsupportedFilter(unknown.into()));
                }
            }
        }
        Ok(data)
    } else {
        Ok(stream.content.clone())
    }
}