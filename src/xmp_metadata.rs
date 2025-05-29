use crate::object::{Object, Stream};
use crate::xmp_utils::{create_blank_xmp, serialize_xmp, update_xmp_metadata};
use crate::{PdfDocument, Result};

pub fn sync_docinfo_to_xmp(doc: &mut PdfDocument) -> Result<()> {
    let catalog = doc.trailer.get(b"Root")?.as_reference()?;
    let catalog_dict = doc.get_dictionary_mut(catalog)?;
    let metadata_ref = match catalog_dict.get(b"Metadata") {
        Ok(obj) => obj.as_reference()?,
        Err(_) => {
            let stream = create_blank_xmp()?;
            let id = doc.add_object(Object::Stream(stream));
            catalog_dict.set("Metadata", Object::Reference(id));
            id
        }
    };

    let metadata_obj = doc.get_object_mut(metadata_ref)?;
    let stream = metadata_obj.as_stream_mut()?;
    update_xmp_metadata(doc, stream)?;

    Ok(())
}

pub fn extract_xmp_xml(doc: &PdfDocument) -> Result<String> {
    let catalog = doc.trailer.get(b"Root")?.as_reference()?;
    let catalog_dict = doc.get_dictionary(catalog)?;
    let metadata_ref = catalog_dict.get(b"Metadata")?.as_reference()?;
    let metadata_obj = doc.get_object(metadata_ref)?;
    let stream = metadata_obj.as_stream()?;
    let xml = std::str::from_utf8(&stream.content)?.to_string();
    Ok(xml)
}