use chrono::{DateTime, NaiveDateTime, Utc};

/// Format a UTC timestamp into PDF Date format: D:YYYYMMDDHHmmSSZ
pub fn format_pdf_date(datetime: DateTime<Utc>) -> String {
    format!(
        "D:{:04}{:02}{:02}{:02}{:02}{:02}Z",
        datetime.year(),
        datetime.month(),
        datetime.day(),
        datetime.hour(),
        datetime.minute(),
        datetime.second()
    )
}

/// Parse a PDF Date string (if present) to chrono DateTime.
/// Returns None if format is invalid or not a PDF Date.
pub fn parse_pdf_date(input: &str) -> Option<DateTime<Utc>> {
    let input = input.strip_prefix("D:").unwrap_or(input);
    if input.len() < 14 {
        return None;
    }

    let naive = NaiveDateTime::parse_from_str(&input[0..14], "%Y%m%d%H%M%S").ok()?;
    Some(DateTime::<Utc>::from_utc(naive, Utc))
}