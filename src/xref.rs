use std::collections::BTreeMap;

/// Object identifier as (object number, generation number).
pub type ObjectId = (u32, u16);

/// Represents different types of entries in a PDF cross-reference (xref) table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XrefEntry {
    /// Object is in use and not compressed.
    Normal { offset: u32, generation: u16 },
    /// Object is compressed and stored in an object stream.
    Compressed { container: u32, index: u16 },
    /// Object is free and available for reuse.
    Free,
    /// Reserved but not usable (typically object 0).
    UnusableFree,
}

/// Represents how xref data is stored in the PDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefType {
    /// Traditional xref table + trailer format.
    CrossReferenceTable,
    /// Compressed xref stream (PDF 1.5+).
    CrossReferenceStream,
}

/// PDF cross-reference table.
#[derive(Debug, Clone)]
pub struct Xref {
    /// Mapping from object number to entry.
    pub table: BTreeMap<u32, XrefEntry>,
    /// Number of objects including free object 0.
    pub size: u32,
    /// Type of xref structure in the PDF.
    pub cross_reference_type: XrefType,
}

impl Xref {
    /// Create a new xref table with given size and type.
    pub fn new(size: u32, cross_reference_type: XrefType) -> Self {
        Xref {
            table: BTreeMap::new(),
            size,
            cross_reference_type,
        }
    }

    /// Insert an xref entry.
    pub fn insert(&mut self, id: u32, entry: XrefEntry) {
        self.table.insert(id, entry);
    }

    /// Get a reference to an xref entry.
    pub fn get(&self, id: u32) -> Option<&XrefEntry> {
        self.table.get(&id)
    }

    /// Remove an xref entry.
    pub fn remove(&mut self, id: u32) {
        self.table.remove(&id);
    }
}

/// A section of xref entries (used during serialization).
#[derive(Debug, Clone)]
pub struct XrefSection {
    pub starting_id: u32,
    pub entries: Vec<XrefEntry>,
}

impl XrefSection {
    pub fn new(starting_id: u32) -> Self {
        Self {
            starting_id,
            entries: Vec::new(),
        }
    }

    pub fn add_entry(&mut self, entry: XrefEntry) {
        self.entries.push(entry);
    }

    pub fn add_unusable_free_entry(&mut self) {
        self.entries.push(XrefEntry::UnusableFree);
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Writes the xref section as a text-format xref block.
    pub fn write_xref_section(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        use std::io::Write;
        writeln!(out, "{} {}", self.starting_id, self.entries.len())?;

        for (i, entry) in self.entries.iter().enumerate() {
            let obj_num = self.starting_id + i as u32;
            match entry {
                XrefEntry::Normal { offset, generation } => {
                    writeln!(out, "{:010} {:05} n ", offset, generation)?;
                }
                XrefEntry::Free => {
                    writeln!(out, "{:010} {:05} f ", 0, 65535)?;
                }
                XrefEntry::UnusableFree => {
                    writeln!(out, "{:010} {:05} f ", 0, 65535)?;
                }
                XrefEntry::Compressed { .. } => {
                    // Compressed entries are not written in the text format
                    writeln!(out, "{:010} {:05} f ", 0, 65535)?;
                }
            }
        }
        Ok(())
    }
}