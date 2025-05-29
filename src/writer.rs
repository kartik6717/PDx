use crate::{
    PdfDocument, PdfError, Result,
    object::{Dictionary, Object, ObjectId, Stream, StringFormat},
    verifier::verify_pdf,
};
use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;
use flate2::{write::ZlibEncoder, Compression};

/// Save the entire PDF to a vector of bytes.
pub fn save_pdf(doc: &PdfDocument) -> Result<Vec<u8>> {
    verify_pdf(doc)?;

    let mut buffer = Vec::new();
    let mut xref = BTreeMap::<ObjectId, usize>::new();
    let max_id = doc.max_id().0;

    buffer.extend_from_slice(b"%PDF-1.4\n");

    for (&id, obj) in &doc.objects {
        let offset = buffer.len();
        xref.insert(id, offset);
        write!(buffer, "{} {} obj\n", id.0, id.1)?;
        write_object(&mut buffer, obj)?;
        buffer.extend_from_slice(b"\nendobj\n");
    }

    let xref_offset = buffer.len();
    render_xref(&mut buffer, &xref, max_id)?;

    let mut trailer = doc.trailer.clone();
    trailer.insert(b"Size".to_vec(), Object::Integer((max_id + 1) as i64));
    if !trailer.contains_key(b"Root") {
        return Err(PdfError::MissingTrailerEntry("Root"));
    }
    buffer.extend_from_slice(b"trailer\n");
    write_dictionary(&mut buffer, &trailer)?;
    buffer.push(b'\n');

    write!(buffer, "startxref\n{}\n%%EOF\n", xref_offset)?;
    Ok(buffer)
}

fn render_xref(buf: &mut Vec<u8>, xref: &BTreeMap<ObjectId, usize>, max_id: u32) -> Result<(), PdfError> {
    writeln!(buf, "xref\n0 {}", max_id + 1)?;
    buf.extend_from_slice(b"0000000000 65535 f \n");

    for id in 1..=max_id {
        let key = (id, 0);
        if let Some(offset) = xref.get(&key) {
            writeln!(buf, "{:010} 00000 n \n", offset)?;
        } else {
            buf.extend_from_slice(b"0000000000 00000 f \n");
        }
    }
    Ok(())
}

fn write_object(buf: &mut Vec<u8>, obj: &Object) -> Result<(), PdfError> {
    match obj {
        Object::Null => buf.extend_from_slice(b"null"),
        Object::Boolean(v) => write!(buf, "{}", v)?,
        Object::Integer(i) => write!(buf, "{}", i)?,
        Object::Real(r) => write!(buf, "{}", r)?,
        Object::Name(name) => {
            buf.push(b'/');
            buf.extend_from_slice(name);
        }
        Object::String(bytes, format) => write_string(buf, bytes, format)?,
        Object::Array(arr) => write_array(buf, arr)?,
        Object::Dictionary(dict) => write_dictionary(buf, dict)?,
        Object::Stream(stream) => write_stream(buf, stream)?,
        Object::Reference((id, gen)) => write!(buf, "{} {} R", id, gen)?,
    }
    Ok(())
}

fn write_string(buf: &mut Vec<u8>, bytes: &[u8], format: &StringFormat) -> Result<(), PdfError> {
    match format {
        StringFormat::Literal => {
            buf.push(b'(');
            for &b in bytes {
                if b == b'(' || b == b')' || b == b'\\' {
                    buf.push(b'\\');
                }
                buf.push(b);
            }
            buf.push(b')');
        }
        StringFormat::Hexadecimal => {
            buf.push(b'<');
            for &b in bytes {
                write!(buf, "{:02X}", b)?;
            }
            buf.push(b'>');
        }
    }
    Ok(())
}

fn write_array(buf: &mut Vec<u8>, array: &[Object]) -> Result<(), PdfError> {
    buf.push(b'[');
    for (i, obj) in array.iter().enumerate() {
        if i > 0 {
            buf.push(b' ');
        }
        write_object(buf, obj)?;
    }
    buf.push(b']');
    Ok(())
}

fn write_dictionary(buf: &mut Vec<u8>, dict: &Dictionary) -> Result<(), PdfError> {
    buf.extend_from_slice(b"<<");
    for (key, value) in dict.iter().collect::<BTreeMap<_, _>>() {
        buf.push(b'/');
        buf.extend_from_slice(key);
        buf.push(b' ');
        write_object(buf, value)?;
    }
    buf.extend_from_slice(b">>");
    Ok(())
}

fn write_stream(buf: &mut Vec<u8>, stream: &Stream) -> Result<(), PdfError> {
    let mut compressed = Vec::new();
    let mut encoder = ZlibEncoder::new(&mut compressed, Compression::default());
    encoder.write_all(&stream.content)?;
    encoder.finish()?;

    let mut dict = stream.dict.clone();
    dict.insert(b"Filter".to_vec(), Object::Name(b"FlateDecode".to_vec()));
    dict.insert(b"Length".to_vec(), Object::Integer(compressed.len() as i64));

    write_dictionary(buf, &dict)?;
    buf.extend_from_slice(b"\nstream\n");
    buf.extend_from_slice(&compressed);
    buf.extend_from_slice(b"\nendstream");
    Ok(())
}