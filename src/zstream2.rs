use crate::{
    object::{Object, Stream},
    error::PdfError,
};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use std::io::{Read, Write};

/// Alternate compressor for FlateDecode streams
pub fn compress_stream(stream: &mut Stream) -> Result<(), PdfError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&stream.content)?;
    let compressed = encoder.finish()?;

    stream.content = compressed;
    stream.dict.set(b"Filter".to_vec(), Object::Name(b"FlateDecode".to_vec()));
    stream.dict.set(b"Length".to_vec(), Object::Integer(stream.content.len() as i64));

    Ok(())
}

/// Alternate decompressor for FlateDecode streams
pub fn decompress_stream(stream: &mut Stream) -> Result<(), PdfError> {
    if let Some(Object::Name(ref filter)) = stream.dict.get(b"Filter") {
        if filter == b"FlateDecode" {
            let mut decoder = ZlibDecoder::new(&stream.content[..]);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)?;
            stream.content = decompressed;
            stream.dict.remove(b"Filter");
            stream.dict.set(b"Length".to_vec(), Object::Integer(stream.content.len() as i64));
        }
    }
    Ok(())
}