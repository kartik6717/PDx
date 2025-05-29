use crate::{
    object::{Dictionary, Object, Stream},
    error::PdfError,
};
use std::io::{Read, Write};
use flate2::{write::ZlibEncoder, read::ZlibDecoder, Compression};

/// Compress the content of a stream using FlateDecode.
pub fn deflate_stream(stream: &mut Stream) -> Result<(), PdfError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&stream.content)?;
    let compressed = encoder.finish()?;

    stream.dict.set(b"Filter".to_vec(), Object::Name(b"FlateDecode".to_vec()));
    stream.dict.set(b"Length".to_vec(), Object::Integer(compressed.len() as i64));
    stream.content = compressed;

    Ok(())
}

/// Decompress the stream content if it's FlateDecode.
pub fn inflate_stream(stream: &mut Stream) -> Result<(), PdfError> {
    if let Some(Object::Name(ref filter)) = stream.dict.get(b"Filter") {
        if filter.as_slice() == b"FlateDecode" {
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