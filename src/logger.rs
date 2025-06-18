use crate::types::*;
use std::fs::OpenOptions;
use std::io::Write;
use log;
use env_logger;
use chrono;

pub fn init_logger() -> PdfResult<()> {
    // Initialize environment logger with custom settings
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .format(|buf, record| {
            writeln!(buf, 
                "{} [{}] - {}", 
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
                record.level(), 
                record.args()
            )
        })
        .init();
    
    // Create log file if it doesn't exist
    let log_file_path = "pdf-forensic.log";
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file_path)
        .map_err(|e| PdfError::Io {
            message: format!("Failed to create log file: {}", e),
            code: 10,
        })?;
    
    // Write initialization entry
    writeln!(file, "{} [INFO] - PDF Forensic Tool logger initialized", 
             chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"))
        .map_err(|e| PdfError::Io {
            message: format!("Failed to write to log file: {}", e),
            code: 11,
        })?;
    
    log::info!("PDF Forensic Tool logger initialized with file logging to {}", log_file_path);
    
    // Ensure log file is properly written
    file.flush().map_err(|e| PdfError::Io {
        message: format!("Failed to flush log file: {}", e),
        code: 12,
    })?;
    
    println!("Logger initialized successfully");
    Ok(())
}

/// Log validation results with detailed information
pub fn log_validation_result(file_path: &str, result: &ValidationResult) {
    log::info!("VALIDATION: {} - Status: {}", file_path, if result.is_valid { "Valid" } else { "Invalid" });
    log::info!("VALIDATION: Issues found: {}", result.errors.len() + result.warnings.len());
    
    for error in &result.errors {
        match error.severity {
            ErrorSeverity::Critical => log::error!("VALIDATION: Critical - {}", error.message),
            ErrorSeverity::Major => log::error!("VALIDATION: Major - {}", error.message),
            ErrorSeverity::Minor => log::warn!("VALIDATION: Minor - {}", error.message),
            ErrorSeverity::Info => log::info!("VALIDATION: Info - {}", error.message),
        }
        
        if let Some(ref location) = error.location {
            match location {
                ErrorLocation::FileStructure { offset } => {
                    log::debug!("VALIDATION: Error location - File offset: {}", offset);
                }
                ErrorLocation::Object { object_ref, offset } => {
                    log::debug!("VALIDATION: Error location - Object: {}, Offset: {:?}", object_ref, offset);
                }
                ErrorLocation::Metadata { field } => {
                    log::debug!("VALIDATION: Error location - Metadata field: {}", field);
                }
                ErrorLocation::XRef { entry } => {
                    log::debug!("VALIDATION: Error location - XRef entry: {}", entry);
                }
                ErrorLocation::Trailer => {
                    log::debug!("VALIDATION: Error location - Trailer section");
                }
                ErrorLocation::Stream { stream_ref } => {
                    log::debug!("VALIDATION: Error location - Stream: {}", stream_ref);
                }
                ErrorLocation::Security => {
                    log::debug!("VALIDATION: Error location - Security section");
                }
                ErrorLocation::DocumentStructure => {
                    log::debug!("VALIDATION: Error location - Document structure");
                }
                ErrorLocation::Content => {
                    log::debug!("VALIDATION: Error location - Content");
                }
            }
        }
    }
    
    for warning in &result.warnings {
        log::warn!("VALIDATION: Warning - {}", warning.message);
        
        if let Some(ref location) = warning.location {
            match location {
                ErrorLocation::FileStructure { offset } => {
                    log::debug!("VALIDATION: Warning location - File offset: {}", offset);
                }
                ErrorLocation::Object { object_ref, offset } => {
                    log::debug!("VALIDATION: Warning location - Object: {}, Offset: {:?}", object_ref, offset);
                }
                _ => {}
            }
        }
    }
    
    // Log forensic match details if available
    if let Some(ref forensic_match) = result.forensic_match {
        log::info!("VALIDATION: Forensic match - Status: {}, Confidence: {:.2}%", 
                   if forensic_match.matches { "Match" } else { "No Match" },
                   forensic_match.confidence * 100.0);
        
        if !forensic_match.non_matching_elements.is_empty() {
            log::warn!("VALIDATION: Forensic discrepancies found: {}", forensic_match.non_matching_elements.len());
        }
    }
    
    // Log validation statistics
    log::info!("VALIDATION: Statistics - Objects: {}, Streams: {}, References: {}, Time: {}ms", 
               result.validation_stats.objects_validated,
               result.validation_stats.streams_validated,
               result.validation_stats.references_validated,
               result.validation_stats.validation_time_ms);
}

/// Log extraction phase details
pub fn log_extraction_details(file_path: &str, extracted_data: &PdfForensicData) {
    log::info!("EXTRACTION: PDF {} - Version: {}", file_path, extracted_data.version);
    log::info!("EXTRACTION: Objects: {}, Pages: {}", 
               extracted_data.structure.object_count, 
               0);
    
    if let Some(ref encryption) = extracted_data.encryption {
        log::info!("EXTRACTION: Encryption detected - Filter: {}, Version: {}", 
                   encryption.filter, encryption.v);
        log::info!("EXTRACTION: Encryption - Revision: {}, Length: {} bits", 
                   encryption.r, encryption.length.unwrap_or(40));
    }
    
    log::info!("EXTRACTION: Watermarks detected: {}", 
               extracted_data.forensic_markers.watermarks.len());
    
    if !extracted_data.forensic_markers.watermarks.is_empty() {
        for (i, watermark) in extracted_data.forensic_markers.watermarks.iter().enumerate() {
            log::info!("EXTRACTION: Watermark {} - Type: {}, Original: {}, Confidence: {:.2}%", 
                       i + 1, watermark.watermark_type, watermark.is_original, watermark.confidence * 100.0);
        }
    }
    
    // Log timestamp information
    if let Some(ref creation) = extracted_data.timestamps.creation_raw {
        log::info!("EXTRACTION: Creation timestamp: {}", creation);
    }
    
    if let Some(ref modification) = extracted_data.timestamps.modification_raw {
        log::info!("EXTRACTION: Modification timestamp: {}", modification);
    }
    
    // Log trailer information
    log::info!("EXTRACTION: Trailer - Size: {}, Root: {}", 
               extracted_data.trailer.size,
               extracted_data.trailer.root_ref);
    
    if let Some(ref id_array) = extracted_data.trailer.id_array {
        log::info!("EXTRACTION: PDF ID array found with {} entries", id_array.len());
        for (i, id) in id_array.iter().enumerate() {
            log::debug!("EXTRACTION: PDF ID[{}]: {}", i, &id[..std::cmp::min(32, id.len())]);
        }
    }
    
    // Log processing statistics
    log::info!("EXTRACTION: Processing time: {}ms, Memory usage: {} bytes", 
               extracted_data.processing_stats.duration_ms,
               extracted_data.processing_stats.memory_usage.peak_usage);
}

/// Count non-empty metadata fields
pub fn count_metadata_fields(metadata: &DocumentMetadata) -> usize {
    let mut count = 0;
    
    if metadata.title.is_some() { count += 1; }
    if metadata.author.is_some() { count += 1; }
    if metadata.subject.is_some() { count += 1; }
    if metadata.keywords.is_some() { count += 1; }
    if metadata.creator.is_some() { count += 1; }
    if metadata.producer.is_some() { count += 1; }
    if metadata.creation_date.is_some() { count += 1; }
    if metadata.mod_date.is_some() { count += 1; }
    
    count += metadata.custom_fields.len();
    
    count
}

/// Log injection operation details
pub fn log_injection_details(target_path: &str, source_data: &PdfForensicData, output_path: &str) {
    log::info!("INJECTION: Target: {} -> Output: {}", target_path, output_path);
    log::info!("INJECTION: Source PDF version: {}", source_data.version);
    
    let metadata_fields = count_metadata_fields(&source_data.metadata);
    log::info!("INJECTION: Injecting {} metadata fields", metadata_fields);
    
    if source_data.encryption.is_some() {
        log::info!("INJECTION: Encryption data will be injected");
    }
    
    if !source_data.forensic_markers.watermarks.is_empty() {
        log::info!("INJECTION: {} watermarks found in source data", 
                   source_data.forensic_markers.watermarks.len());
    }
    
    if let Some(ref id_array) = source_data.trailer.id_array {
        log::info!("INJECTION: PDF ID array with {} entries will be injected", id_array.len());
    }
}

/// Log memory and performance statistics
pub fn log_performance_stats(stats: &ProcessingStatistics) {
    log::info!("PERFORMANCE: Duration: {}ms", stats.duration_ms);
    log::info!("PERFORMANCE: Peak memory: {} MB", stats.memory_usage.peak_usage / 1024 / 1024);
    log::info!("PERFORMANCE: Average CPU: {:.1}%", stats.cpu_usage.average_cpu_percent);
    log::info!("PERFORMANCE: I/O - Read: {} bytes, Write: {} bytes", 
               stats.io_stats.bytes_read, stats.io_stats.bytes_written);
}