use flate2::read::{DeflateDecoder, DeflateEncoder}; use std::io::{Read, Result, Write};

/// Compresses the given input using DEFLATE algorithm. pub fn compress_deflate(input: &[u8]) -> Result<Vec<u8>> { let mut encoder = DeflateEncoder::new(input); let mut buffer = Vec::new(); encoder.read_to_end(&mut buffer)?; Ok(buffer) }

/// Decompresses the given input using DEFLATE algorithm. pub fn decompress_deflate(input: &[u8]) -> Result<Vec<u8>> { let mut decoder = DeflateDecoder::new(input); let mut buffer = Vec::new(); decoder.read_to_end(&mut buffer)?; Ok(buffer) }