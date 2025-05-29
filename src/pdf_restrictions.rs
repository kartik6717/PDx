use crate::object::{Object, Dictionary, ObjectId};
use crate::pdf_doc::PdfDocument;
use crate::error::{PdfError, Result};
use crate::xmp::XmpMetadata;

/// Provides functionality to edit PDF metadata in both DocInfo and XMP.
pub struct PdfMetadataEditor<'a> {
    pub doc: &'a mut PdfDocument,
}

impl<'a> PdfMetadataEditor<'a> {
    /// Creates a new metadata editor instance.
    pub fn new(doc: &'a mut PdfDocument) -> Self {
        Self { doc }
    }

    /// Updates or inserts a metadata field in both DocInfo and XMP metadata.
    pub fn set_metadata_field(&mut self, key: &str, value: &str) -> Result<()> {
        self.set_docinfo_field(key, value)?;
        self.set_xmp_field(key, value)?;
        Ok(())
    }

    /// Removes a metadata field from both DocInfo and XMP metadata.
    pub fn remove_metadata_field(&mut self, key: &str) -> Result<()> {
        self.remove_docinfo_field(key)?;
        self.remove_xmp_field(key)?;
        Ok(())
    }

    fn set_docinfo_field(&mut self, key: &str, value: &str) -> Result<()> {
        let docinfo_id = self
            .doc
            .trailer
            .get(b"Info")
            .and_then(Object::as_reference)
            .ok_or(PdfError::MissingInfoDict)?;

        let dict = self
            .doc
            .get_object_mut(docinfo_id)
            .and_then(Object::as_dict_mut)
            .map_err(|_| PdfError::InvalidInfoDict)?;

        dict.set(key.as_bytes(), Object::string_literal(value));
        Ok(())
    }

    fn remove_docinfo_field(&mut self, key: &str) -> Result<()> {
        let docinfo_id = self
            .doc
            .trailer
            .get(b"Info")
            .and_then(Object::as_reference)
            .ok_or(PdfError::MissingInfoDict)?;

        let dict = self
            .doc
            .get_object_mut(docinfo_id)
            .and_then(Object::as_dict_mut)
            .map_err(|_| PdfError::InvalidInfoDict)?;

        dict.remove(key.as_bytes());
        Ok(())
    }

    fn set_xmp_field(&mut self, key: &str, value: &str) -> Result<()> {
        if let Some((xmp_id, xmp_stream)) = self.get_xmp_stream_mut()? {
            let mut xmp = XmpMetadata::parse(&xmp_stream.content)?;
            xmp.set_field(key, value);
            xmp_stream.content = xmp.to_xml_string().into_bytes();
            xmp_stream
                .dict
                .set("Length", xmp_stream.content.len() as i64);
            self.doc.objects.insert(xmp_id, Object::Stream(xmp_stream.clone()));
        }
        Ok(())
    }

    fn remove_xmp_field(&mut self, key: &str) -> Result<()> {
        if let Some((xmp_id, xmp_stream)) = self.get_xmp_stream_mut()? {
            let mut xmp = XmpMetadata::parse(&xmp_stream.content)?;
            xmp.remove_field(key);
            xmp_stream.content = xmp.to_xml_string().into_bytes();
            xmp_stream
                .dict
                .set("Length", xmp_stream.content.len() as i64);
            self.doc.objects.insert(xmp_id, Object::Stream(xmp_stream.clone()));
        }
        Ok(())
    }

    fn get_xmp_stream_mut(&mut self) -> Result<Option<(ObjectId, crate::object::Stream)>> {
        for (id, object) in &self.doc.objects {
            if let Object::Stream(stream) = object {
                if stream.dict.has_type(b"Metadata") {
                    return Ok(Some((*id, stream.clone())));
                }
            }
        }
        Ok(None)
    }
}