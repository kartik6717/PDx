/// The type of xref structure used in the PDF.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum XrefType {
    /// Traditional cross-reference table.
    CrossReferenceTable,
    /// Modern cross-reference stream.
    CrossReferenceStream,
}