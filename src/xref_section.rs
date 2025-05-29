use crate::xref::XrefEntry;
use std::io::{Result, Write};

/// Represents a section of Xref entries starting from a specific object ID.
#[derive(Debug)]
pub struct XrefSection {
    pub starting_id: u32,
    pub entries: Vec<XrefEntry>,
}

impl XrefSection {
    pub fn new(starting_id: u32) -> Self {
        XrefSection {
            starting_id,
            entries: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn add_entry(&mut self, entry: XrefEntry) {
        self.entries.push(entry);
    }

    pub fn add_unusable_free_entry(&mut self) {
        self.entries.push(XrefEntry::UnusableFree);
    }

    pub fn write_xref_section(&self, file: &mut dyn Write) -> Result<()> {
        writeln!(file, "{} {}", self.starting_id, self.entries.len())?;
        for entry in &self.entries {
            match entry {
                XrefEntry::Normal { offset, generation } => {
                    writeln!(file, "{:010} {:05} n ", offset, generation)?;
                }
                XrefEntry::Free => {
                    writeln!(file, "{:010} {:05} f ", 0, 65535)?;
                }
                XrefEntry::UnusableFree => {
                    writeln!(file, "{:010} {:05} f ", 0, 65535)?;
                }
                XrefEntry::Compressed { .. } => {
                    // Compressed entries are not written to the cross-reference table.
                    writeln!(file, "{:010} {:05} f ", 0, 65535)?;
                }
            }
        }
        Ok(())
    }
}