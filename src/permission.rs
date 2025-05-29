bitflags::bitflags! {
    /// PDF permission flags as per PDF spec (Section 3.5.2).
    pub struct Permissions: i32 {
        const PRINT = 0b0000_0100;
        const MODIFY = 0b0000_1000;
        const COPY = 0b0001_0000;
        const ANNOTATE = 0b0010_0000;
        const FILL_FORM = 0b0001_0000_0000;
        const EXTRACT_ACCESSIBILITY = 0b0000_0100_0000;
        const ASSEMBLE = 0b0000_1000_0000;
        const PRINT_HIGH_QUALITY = 0b0001_0000_0000;
    }
}

impl Permissions {
    pub fn allow_all() -> Self {
        Self::all()
    }

    pub fn deny_all() -> Self {
        Self::empty()
    }

    pub fn standard_restricted() -> Self {
        Self::PRINT | Self::COPY
    }
}