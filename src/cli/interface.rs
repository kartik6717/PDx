use crate::types::*;
use console::style;
use console::{Term};
use indicatif::{ProgressBar, ProgressStyle};

/// Display extraction summary to user
pub fn display_extraction_summary(data: &PdfForensicData) {
    let _term = Term::stdout();

    println!("\n{}", style("=== PDF FORENSIC EXTRACTION SUMMARY ===").bold().green());
    println!("{}: {}", style("PDF Version").bold(), data.version);
    println!("{}: {} bytes", style("File Size").bold(), format_file_size(data.structure.file_size));

    // Display metadata information
    if !data.metadata.title.as_ref().unwrap_or(&String::new()).is_empty() {
        println!("{}: {}", style("Title").bold(), data.metadata.title.as_ref().unwrap());
    }
    if !data.metadata.author.as_ref().unwrap_or(&String::new()).is_empty() {
        println!("{}: {}", style("Author").bold(), data.metadata.author.as_ref().unwrap());
    }
    if !data.metadata.creator.as_ref().unwrap_or(&String::new()).is_empty() {
        println!("{}: {}", style("Creator").bold(), data.metadata.creator.as_ref().unwrap());
    }
    if !data.metadata.producer.as_ref().unwrap_or(&String::new()).is_empty() {
        println!("{}: {}", style("Producer").bold(), data.metadata.producer.as_ref().unwrap());
    }

    // Display timestamps
    if let Some(ref creation) = data.timestamps.creation_raw {
        println!("{}: {}", style("Created").bold(), creation);
    }
    if let Some(ref modified) = data.timestamps.modification_raw {
        println!("{}: {}", style("Modified").bold(), modified);
    }

    // Display structure information
    println!("\n{}", style("=== STRUCTURE ANALYSIS ===").bold().blue());
    println!("{}: {}", style("Objects").bold(), data.structure.object_count);
    let page_count = 0; // Page count not directly available from PageTreeStructure enum
    println!("{}: {}", style("Pages").bold(), page_count);

    if !data.update_chain.updates.is_empty() {
        println!("{}: {}", style("Incremental Updates").bold(), style("YES").red());
    }

    if data.linearization.is_some() {
        println!("{}: {}", style("Linearized").bold(), style("YES").green());
    }

    // Display encryption information
    if let Some(ref encryption) = data.encryption {
        println!("\n{}", style("=== ENCRYPTION DETECTED ===").bold().yellow());
        println!("{}: {}", style("Filter").bold(), encryption.filter);
        println!("{}: {}", style("Version").bold(), encryption.v);
        println!("{}: {}", style("Revision").bold(), encryption.r);
        println!("{}: {} bits", style("Key Length").bold(), encryption.length.unwrap_or(40));
    }

    // Display watermark information
    if !data.forensic_markers.watermarks.is_empty() {
        println!("\n{}", style("=== WATERMARKS DETECTED ===").bold().red());
        for (i, watermark) in data.forensic_markers.watermarks.iter().enumerate() {
            println!("{}. {}: {} (Confidence: {:.1}%)", 
                     i + 1,
                     if watermark.is_original { "Original" } else { "Third-party" },
                     watermark.watermark_type,
                     watermark.confidence * 100.0);
        }
    }

    // Display PDF ID
    if let Some(ref id_array) = data.trailer.id_array {
        println!("\n{}", style("=== PDF IDENTIFICATION ===").bold().cyan());
        for (i, id) in id_array.iter().enumerate() {
            println!("ID[{}]: {}", i, hex::encode(&id[..std::cmp::min(16, id.len())]));
        }
    }

    // Display custom metadata fields
    if !data.metadata.custom_fields.is_empty() {
        println!("\n{}", style("=== CUSTOM METADATA ===").bold().magenta());
        for (key, value) in &data.metadata.custom_fields {
            println!("{}: {}", style(key).bold(), value);
        }
    }

    println!("\n{}", style("Extraction completed successfully!").bold().green());
}

/// Display validation results
pub fn display_validation_result(result: &ValidationResult) {
    let _term = Term::stdout();

    println!("\n{}", style("=== PDF VALIDATION RESULTS ===").bold().blue());

    // Display overall status
    let status_style = if result.is_valid {
        style("VALID").bold().green()
    } else {
        style("INVALID").bold().red()
    };
    println!("{}: {}", style("Status").bold(), status_style);

    // Display errors
    if !result.errors.is_empty() {
        println!("\n{}", style("=== VALIDATION ERRORS ===").bold().red());
        for error in &result.errors {
            let severity_style = match error.severity {
                ErrorSeverity::Critical => style("CRITICAL").bold().red(),
                ErrorSeverity::Major => style("MAJOR").bold().red(),
                ErrorSeverity::Minor => style("MINOR").bold().yellow(),
                ErrorSeverity::Info => style("INFO").bold().blue(),
            };

            print!("[{}] ", severity_style);
            if let Some(ref location) = error.location {
                match location {
                    ErrorLocation::FileStructure { offset } => print!("@ offset {}: ", offset),
                    ErrorLocation::Object { object_ref, offset } => {
                        if let Some(off) = offset {
                            print!("@ object {} offset {}: ", object_ref, off);
                        } else {
                            print!("@ object {}: ", object_ref);
                        }
                    },
                    ErrorLocation::Metadata { field } => print!("@ metadata field '{}': ", field),
                    ErrorLocation::XRef { entry } => print!("@ xref entry {}: ", entry),
                    ErrorLocation::Trailer => print!("@ trailer: "),
                    ErrorLocation::Stream { stream_ref } => print!("@ stream {}: ", stream_ref),
                    ErrorLocation::Security => print!("@ security: "),
                    ErrorLocation::DocumentStructure => print!("@ document structure: "),
                    ErrorLocation::Content => print!("@ content: "),
                }
            }
            println!("{}", error.message);

            if let Some(ref fix) = error.suggested_fix {
                println!("  → {}", style(fix).dim());
            }
        }
    }

    // Display warnings
    if !result.warnings.is_empty() {
        println!("\n{}", style("=== VALIDATION WARNINGS ===").bold().yellow());
        for warning in &result.warnings {
            print!("[{}] ", style("WARNING").bold().yellow());
            if let Some(ref location) = warning.location {
                match location {
                    ErrorLocation::FileStructure { offset } => print!("@ offset {}: ", offset),
                    ErrorLocation::Object { object_ref, offset } => {
                        if let Some(off) = offset {
                            print!("@ object {} offset {}: ", object_ref, off);
                        } else {
                            print!("@ object {}: ", object_ref);
                        }
                    },
                    ErrorLocation::Metadata { field } => print!("@ metadata field '{}': ", field),
                    ErrorLocation::XRef { entry } => print!("@ xref entry {}: ", entry),
                    ErrorLocation::Trailer => print!("@ trailer: "),
                    ErrorLocation::Stream { stream_ref } => print!("@ stream {}: ", stream_ref),
                    ErrorLocation::Security => print!("@ security: "),
                    ErrorLocation::DocumentStructure => print!("@ document structure: "),
                    ErrorLocation::Content => print!("@ content: "),
                }
            }
            println!("{}", warning.message);

            if let Some(ref recommendation) = warning.recommendation {
                println!("  → {}", style(recommendation).dim());
            }
        }
    }

    if result.errors.is_empty() && result.warnings.is_empty() {
        println!("\n{}", style("No validation issues found!").bold().green());
    }

    // Display forensic match if available
    if let Some(ref forensic_match) = result.forensic_match {
        println!("\n{}", style("=== FORENSIC MATCH ===").bold().cyan());
        let match_style = if forensic_match.matches {
            style("MATCH").bold().green()
        } else {
            style("NO MATCH").bold().red()
        };
        println!("{}: {} ({:.1}% confidence)", style("Status").bold(), match_style, forensic_match.confidence * 100.0);
    }
}

/// Display comparison results
pub fn display_comparison_result(result: &ComparisonResult) {
    println!("\n{}", style("=== PDF FORENSIC COMPARISON ===").bold().blue());

    let match_style = if result.forensically_identical {
        style("IDENTICAL").bold().green()
    } else {
        style("DIFFERENT").bold().red()
    };

    println!("{}: {}", style("Forensic Match").bold(), match_style);
    println!("{}: {:.1}%", style("Similarity Score").bold(), result.similarity_score * 100.0);

    if !result.differences.is_empty() {
        println!("\n{}", style("=== DIFFERENCES FOUND ===").bold().red());

        for diff in &result.differences {
            println!("• {:?}: {}", 
                     diff.difference_type,
                     diff.description);

            if let (Some(expected), Some(actual)) = (&diff.expected, &diff.actual) {
                println!("    Expected: {}", truncate_string(expected, 50));
                println!("    Actual:   {}", truncate_string(actual, 50));
            }
        }

        println!("\n{}: {}", style("Total Differences").bold(), result.differences.len());
    } else {
        println!("\n{}", style("No differences found!").bold().green());
    }
}

/// Display match status for individual fields
fn display_match_status(field_name: &str, matches: bool) {
    let status = if matches {
        style("✓").green()
    } else {
        style("✗").red()
    };
    println!("  {} {}", status, field_name);
}

/// Create progress bar for long operations
pub fn create_progress_bar(message: &str, total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(&format!("{} {{spinner:.green}} [{{elapsed_precise}}] [{{bar:40.cyan/blue}}] {{pos}}/{{len}} ({{eta}}))", message))
            .unwrap()
            .progress_chars("#>-"),
    );
    pb
}

/// Display error message with proper formatting
pub fn display_error(error: &PdfError) {
    eprintln!("{}: {}", style("Error").bold().red(), error);

    // Provide context-specific help
    match error {
        PdfError::FileSystem { path, operation: _, error_kind } => {
            match error_kind {
                FileErrorKind::NotFound => {
                    eprintln!("  {} Check if the file path is correct: {}", 
                             style("Hint:").bold().blue(), path);
                }
                FileErrorKind::PermissionDenied => {
                    eprintln!("  {} Check file permissions or run with appropriate privileges", 
                             style("Hint:").bold().blue());
                }
                _ => {}
            }
        }
        PdfError::Parse { offset, context, .. } => {
            eprintln!("  {} Error occurred at byte offset {} in {}", 
                     style("Location:").bold().blue(), offset, context);
        }
        PdfError::Memory { requested_bytes, available_bytes, .. } => {
            eprintln!("  {} Try reducing memory usage or increasing available memory", 
                     style("Hint:").bold().blue());
            eprintln!("  Requested: {} MB, Available: {} MB",
                     requested_bytes / 1024 / 1024,
                     available_bytes / 1024 / 1024);
        }
        _ => {}
    }
}

/// Display warning message
pub fn display_warning(message: &str) {
    println!("{}: {}", style("Warning").bold().yellow(), message);
}

/// Display info message
pub fn display_info(message: &str) {
    println!("{}: {}", style("Info").bold().blue(), message);
}

/// Format file size in human readable format
fn format_file_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    const THRESHOLD: u64 = 1024;

    if bytes < THRESHOLD {
        return format!("{} B", bytes);
    }

    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= THRESHOLD as f64 && unit_index < UNITS.len() - 1 {
        size /= THRESHOLD as f64;
        unit_index += 1;
    }

    format!("{:.1} {}", size, UNITS[unit_index])
}

/// Truncate string to specified length with ellipsis
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Display progress message during operations
pub fn show_progress_message(operation: &str, current: usize, total: usize) {
    if total > 0 {
        let percentage = (current * 100) / total;
        print!("\r{}: [{:>3}%] {} of {} ", 
               style(operation).bold().blue(),
               percentage,
               current,
               total);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
    }
}

/// Clear progress line
pub fn clear_progress_line() {
    print!("\r{}\r", " ".repeat(80));
    std::io::Write::flush(&mut std::io::stdout()).unwrap();
}