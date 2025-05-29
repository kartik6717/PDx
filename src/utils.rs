use chrono::{DateTime, Utc};
use crate::object::Object;

/// Returns the current time formatted as a PDF-compliant date string.
pub fn now_as_pdf_date() -> Object {
    let now: DateTime<Utc> = Utc::now();
    let formatted = format!("D:{:04}{:02}{:02}{:02}{:02}{:02}+00'00'",
        now.year(), now.month(), now.day(),
        now.hour(), now.minute(), now.second()
    );
    Object::string_literal(formatted.as_bytes())
}

/// A macro to create a PDF dictionary from key-value pairs.
#[macro_export]
macro_rules! dictionary {
    ( $( $key:expr => $val:expr ),* $(,)? ) => {{
        let mut dict = $crate::object::Dictionary::default();
        $(
            dict.set($key.to_vec(), $val);
        )*
        dict
    }};
}