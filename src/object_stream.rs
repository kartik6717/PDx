use crate::{Document, Object, ObjectId, Result, Stream};

/// Represents a decoded object stream.
pub struct ObjectStream {
    pub objects: Vec<(ObjectId, Object)>,
}

impl ObjectStream {
    /// Creates a new ObjectStream from a stream object.
    pub fn new(stream: &mut Stream) -> Result<Self> {
        let n = stream.dict.get(b"N")?.as_i64()? as usize;
        let first = stream.dict.get(b"First")?.as_i64()? as usize;

        let data = stream.get_plain_content()?;
        let mut offset_table = vec![];
        let mut rest = &data[..];

        for _ in 0..n {
            let (id, rest2) = parse_unsigned(rest)?;
            let (offset, rest3) = parse_unsigned(rest2)?;
            offset_table.push((id as u32, offset as usize));
            rest = rest3;
        }

        let mut objects = vec![];
        for (i, (id, offset)) in offset_table.iter().enumerate() {
            let start = first + offset;
            let end = if i + 1 < offset_table.len() {
                first + offset_table[i + 1].1
            } else {
                data.len()
            };
            let slice = &data[start..end];
            let mut parser = crate::parser::Parser::new(slice);
            let obj = parser.next_object()?;
            objects.push(((*id, 0), obj));
        }

        Ok(ObjectStream { objects })
    }
}

fn parse_unsigned(data: &[u8]) -> Result<(usize, &[u8])> {
    let mut i = 0;
    while i < data.len() && data[i].is_ascii_digit() {
        i += 1;
    }
    let number = std::str::from_utf8(&data[..i])?.parse()?;
    let rest = &data[i..];
    let rest = skip_whitespace(rest);
    Ok((number, rest))
}

fn skip_whitespace(mut data: &[u8]) -> &[u8] {
    while let Some(&b) = data.first() {
        if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' || b == b'\x0C' || b == b'\x00' {
            data = &data[1..];
        } else {
            break;
        }
    }
    data
}