use crate::types::*;
use chrono::{Datelike, Timelike};

/// Extract timestamps with exact preservation of raw string format
pub fn extract_timestamps(
    _file_data: &[u8],
    metadata: &DocumentMetadata,
    _xref_data: &XRefData,
) -> PdfResult<TimestampData> {
    let mut timestamps = TimestampData {
        creation_raw: metadata.creation_date.clone(),
        modification_raw: metadata.mod_date.clone(),
        creation_parsed: None,
        modification_parsed: None,
        format_type: TimestampFormat::PdfDate,
        timezone_info: None,
        validation_status: TimestampValidation::Valid,
    };

    // Parse timestamps if present, but preserve raw strings
    if let Some(ref creation_raw) = timestamps.creation_raw {
        if let Ok(dt) = parse_pdf_timestamp(creation_raw) {
            timestamps.creation_parsed = Some(ParsedTimestamp {
                year: dt.year(),
                month: dt.month() as u8,
                day: dt.day() as u8,
                hour: dt.hour() as u8,
                minute: dt.minute() as u8,
                second: dt.second() as u8,
                utc_offset: Some(0), // UTC
                
            });
        }
        timestamps.format_type = detect_timestamp_format(creation_raw);
        timestamps.timezone_info = extract_timezone_info(creation_raw);
    }

    if let Some(ref mod_raw) = timestamps.modification_raw {
        if let Ok(dt) = parse_pdf_timestamp(mod_raw) {
            timestamps.modification_parsed = Some(ParsedTimestamp {
                year: dt.year(),
                month: dt.month() as u8,
                day: dt.day() as u8,
                hour: dt.hour() as u8,
                minute: dt.minute() as u8,
                second: dt.second() as u8,
                utc_offset: Some(0), // UTC
            });
        }
    }

    // Search for additional timestamps in the document
    //let additional_timestamps = find_additional_timestamps(file_data, xref_data)?;
    //timestamps.source_objects = additional_timestamps;

    Ok(timestamps)
}

/// Parse PDF timestamp string to DateTime
fn parse_pdf_timestamp(timestamp_str: &str) -> PdfResult<chrono::DateTime<chrono::Utc>> {
    // PDF timestamp format: D:YYYYMMDDHHmmSSOHH'mm'
    let cleaned = timestamp_str.trim();

    // Remove D: prefix if present
    let date_part = if cleaned.starts_with("D:") {
        &cleaned[2..]
    } else {
        cleaned
    };

    // Parse different timestamp formats
    if date_part.len() >= 14 {
        // Full format: YYYYMMDDHHmmSS
        let year_str = &date_part[0..4];
        let month_str = &date_part[4..6];
        let day_str = &date_part[6..8];
        let hour_str = &date_part[8..10];
        let minute_str = &date_part[10..12];
        let second_str = &date_part[12..14];

        let year = year_str.parse::<i32>().map_err(|e| PdfError::Timestamp {
            raw_timestamp: timestamp_str.to_string(),
            message: format!("Invalid year: {}", e),
            format: "PDF".to_string(),
        })?;

        let month = month_str.parse::<u32>().map_err(|e| PdfError::Timestamp {
            raw_timestamp: timestamp_str.to_string(),
            message: format!("Invalid month: {}", e),
            format: "PDF".to_string(),
        })?;

        let day = day_str.parse::<u32>().map_err(|e| PdfError::Timestamp {
            raw_timestamp: timestamp_str.to_string(),
            message: format!("Invalid day: {}", e),
            format: "PDF".to_string(),
        })?;

        let hour = hour_str.parse::<u32>().map_err(|e| PdfError::Timestamp {
            raw_timestamp: timestamp_str.to_string(),
            message: format!("Invalid hour: {}", e),
            format: "PDF".to_string(),
        })?;

        let minute = minute_str.parse::<u32>().map_err(|e| PdfError::Timestamp {
            raw_timestamp: timestamp_str.to_string(),
            message: format!("Invalid minute: {}", e),
            format: "PDF".to_string(),
        })?;

        let second = second_str.parse::<u32>().map_err(|e| PdfError::Timestamp {
            raw_timestamp: timestamp_str.to_string(),
            message: format!("Invalid second: {}", e),
            format: "PDF".to_string(),
        })?;

        // Create naive datetime first
        let naive_dt = chrono::NaiveDate::from_ymd_opt(year, month, day)
            .and_then(|d| d.and_hms_opt(hour, minute, second))
            .ok_or_else(|| PdfError::Timestamp {
                raw_timestamp: timestamp_str.to_string(),
                message: "Invalid date/time components".to_string(),
                format: "PDF".to_string(),
            })?;

        // Handle timezone offset if present
        let offset_part = &date_part[14..];
        let dt_with_tz = if !offset_part.is_empty() {
            parse_timezone_offset(naive_dt, offset_part, timestamp_str)?
        } else {
            // Assume UTC if no timezone specified
            chrono::DateTime::from_naive_utc_and_offset(naive_dt, chrono::Utc)
        };

        Ok(dt_with_tz)
    } else {
        Err(PdfError::Timestamp {
            raw_timestamp: timestamp_str.to_string(),
            message: "Timestamp too short for PDF format".to_string(),
            format: "PDF".to_string(),
        })
    }
}

/// Parse timezone offset from PDF timestamp
fn parse_timezone_offset(
    naive_dt: chrono::NaiveDateTime,
    offset_part: &str,
    original_timestamp: &str,
) -> PdfResult<chrono::DateTime<chrono::Utc>> {
    if offset_part.starts_with('Z') {
        // UTC timezone
        Ok(chrono::DateTime::from_naive_utc_and_offset(naive_dt, chrono::Utc))
    } else if offset_part.starts_with('+') || offset_part.starts_with('-') {
        // Offset format: +HH'mm' or -HH'mm'
        let sign = if offset_part.starts_with('+') { 1 } else { -1 };
        let offset_str = &offset_part[1..];

        if offset_str.len() >= 2 {
            let hour_offset = offset_str[0..2].parse::<i32>().map_err(|e| PdfError::Timestamp {
                raw_timestamp: original_timestamp.to_string(),
                message: format!("Invalid timezone hour offset: {}", e),
                format: "PDF".to_string(),
            })?;

            let minute_offset = if offset_str.len() >= 5 && offset_str.chars().nth(2) == Some('\'') {
                offset_str[3..5].parse::<i32>().map_err(|e| PdfError::Timestamp {
                    raw_timestamp: original_timestamp.to_string(),
                    message: format!("Invalid timezone minute offset: {}", e),
                    format: "PDF".to_string(),
                })?
            } else {
                0
            };

            let total_offset_seconds = sign * (hour_offset * 3600 + minute_offset * 60);

            // Convert to UTC
            let utc_dt = naive_dt - chrono::Duration::seconds(total_offset_seconds as i64);
            Ok(chrono::DateTime::from_naive_utc_and_offset(utc_dt, chrono::Utc))
        } else {
            Err(PdfError::Timestamp {
                raw_timestamp: original_timestamp.to_string(),
                message: "Invalid timezone offset format".to_string(),
                format: "PDF".to_string(),
            })
        }
    } else {
        // Unknown timezone format, assume UTC
        Ok(chrono::DateTime::from_naive_utc_and_offset(naive_dt, chrono::Utc))
    }
}

/// Detect timestamp format used in the PDF
fn detect_timestamp_format(timestamp_str: &str) -> TimestampFormat {
    let cleaned = timestamp_str.trim();

    if cleaned.starts_with("D:") {
        TimestampFormat::PdfDate
    } else if cleaned.contains('T') && cleaned.contains('Z') {
        TimestampFormat::Iso8601
    } else if cleaned.contains('/') || cleaned.contains('-') {
        TimestampFormat::Custom("Unknown".to_string())
    } else {
        TimestampFormat::Invalid
    }
}

/// Extract timezone information from timestamp string
fn extract_timezone_info(timestamp_str: &str) -> Option<TimezoneInfo> {
    let cleaned = timestamp_str.trim();

    // Remove D: prefix if present
    let date_part = if cleaned.starts_with("D:") {
        &cleaned[2..]
    } else {
        cleaned
    };

    if date_part.len() > 14 {
        let tz_part = &date_part[14..];

        if tz_part.starts_with('Z') {
            Some(TimezoneInfo {
                utc_offset: 0,
                abbreviation: Some("UTC".to_string()),
                dst: Some(false),
            })
        } else if tz_part.starts_with('+') || tz_part.starts_with('-') {
            let sign = if tz_part.starts_with('+') { 1 } else { -1 };
            let offset_str = &tz_part[1..];

            if offset_str.len() >= 2 {
                if let Ok(hour_offset) = offset_str[0..2].parse::<i32>() {
                    let minute_offset = if offset_str.len() >= 5 && offset_str.chars().nth(2) == Some('\'') {
                        offset_str[3..5].parse::<i32>().unwrap_or(0)
                    } else {
                        0
                    };

                    Some(TimezoneInfo {
                        utc_offset: (sign * (hour_offset * 60 + minute_offset)) as i16,
                        abbreviation: determine_timezone_abbreviation((sign * (hour_offset * 60 + minute_offset)) as i16),
                        dst: detect_daylight_saving((sign * (hour_offset * 60 + minute_offset)) as i16),
                        
                    })
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    }
}

fn determine_timezone_abbreviation(utc_offset_minutes: i16) -> Option<String> {
    match utc_offset_minutes {
        0 => Some("UTC".to_string()),
        60 => Some("CET".to_string()),
        120 => Some("EET".to_string()),
        -300 => Some("EST".to_string()),
        -240 => Some("EDT".to_string()),
        -360 => Some("CST".to_string()),
        -420 => Some("MST".to_string()),
        -480 => Some("PST".to_string()),
        480 => Some("CST".to_string()), // China Standard Time
        540 => Some("JST".to_string()), // Japan Standard Time
        _ => None,
    }
}

fn detect_daylight_saving(utc_offset_minutes: i16) -> Option<bool> {
    // Common DST detection based on offset patterns
    match utc_offset_minutes {
        -240 | -420 => Some(true),  // EDT, PDT (DST active)
        -300 | -360 | -480 => Some(false), // EST, CST, PST (standard time)
        120 => Some(true),  // CEST (Central European Summer Time)
        60 => Some(false),  // CET (Central European Time)
        _ => None,
    }
}