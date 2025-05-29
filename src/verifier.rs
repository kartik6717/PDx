use crate::{
    object::{Object, Dictionary},
    PdfDocument, PdfError, Result,
};

/// Runs a full verification of the PDF before writing.
pub fn verify_pdf(doc: &PdfDocument) -> Result<()> {
    verify_mod_date_is_blank(doc)?;
    verify_metadata_sync(doc)?;
    verify_permissions_applied(doc)?;
    Ok(())
}

/// Ensure that ModDate is either absent or blank.
fn verify_mod_date_is_blank(doc: &PdfDocument) -> Result<()> {
    if let Some(info) = doc.info() {
        if let Some(Object::String(date, _)) = info.get(b"ModDate") {
            if !date.is_empty() {
                return Err(PdfError::Validation(
                    "ModDate must be removed or blank.".into(),
                ));
            }
        }
    }
    Ok(())
}

/// Ensures that Info dictionary and XMP metadata are synchronized.
fn verify_metadata_sync(doc: &PdfDocument) -> Result<()> {
    let info = match doc.info() {
        Some(d) => d,
        None => return Ok(()),
    };

    let mut xmp_text = None;

    // Try to extract XMP stream text
    if let Some(Object::Reference(ref_id)) = doc.trailer.get(b"Root")
        .and_then(|root| root.as_reference())
        .and_then(|id| doc.get_object(id).ok())
        .and_then(|obj| obj.as_dict())
        .and_then(|catalog| catalog.get(b"Metadata"))
    {
        if let Some(Object::Stream(stream)) = doc.get_object(ref_id).ok() {
            xmp_text = Some(String::from_utf8_lossy(&stream.content).to_string());
        }
    }

    if let Some(xmp) = xmp_text {
        for (key, value) in info.iter() {
            if let Some(str_val) = value.as_str() {
                let tag = format!("<dc:{}>{}</dc:{}>", String::from_utf8_lossy(key), str_val, String::from_utf8_lossy(key));
                if !xmp.contains(&tag) {
                    return Err(PdfError::Validation(format!(
                        "XMP metadata missing expected tag for key '{}'.",
                        String::from_utf8_lossy(key)
                    )));
                }
            }
        }
    }

    Ok(())
}

/// Ensures that encryption permissions are applied if Encrypt dictionary exists.
fn verify_permissions_applied(doc: &PdfDocument) -> Result<()> {
    if let Some(Object::Reference(enc_id)) = doc.trailer.get(b"Encrypt") {
        let encrypt = doc.get_object(enc_id)?;
        if let Object::Dictionary(dict) = encrypt {
            if !dict.contains_key(b"P") || !dict.contains_key(b"O") || !dict.contains_key(b"U") {
                return Err(PdfError::Validation(
                    "Incomplete Encrypt dictionary.".into(),
                ));
            }
        }
    }
    Ok(())
}