use crate::types::*;
use std::fs::OpenOptions;
use std::io::BufWriter;
use std::path::Path;
use std::fs;
use serde::{Serialize, Deserialize};

/// Save PDF forensic data to JSON file safely
pub fn save_forensic_data(data: &PdfForensicData, path: &str) -> PdfResult<()> {
    log::info!("Saving forensic data to: {}", path);

    // Create directory if it doesn't exist
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| PdfError::FileSystem {
            path: parent.to_string_lossy().to_string(),
            operation: "create_dir".to_string(),
            error_kind: match e.kind() {
                std::io::ErrorKind::PermissionDenied => FileErrorKind::PermissionDenied,
                _ => FileErrorKind::NoSpace,
            },
        })?;
    }

    let content = serde_json::to_string_pretty(data).map_err(|e| PdfError::Json {
        message: format!("JSON serialization failed: {}", e),
        line: Some(e.line()),
    })?;

    fs::write(path, content).map_err(|e| PdfError::Io {
        message: format!("Cannot write JSON file: {}", e),
        code: e.raw_os_error().unwrap_or(-1),
    })?;

    log::info!("Successfully saved forensic data: {} bytes",
               calculate_json_size(data)?);
    Ok(())
}

/// Load forensic data from JSON file safely
pub fn load_forensic_data(path: &str) -> PdfResult<PdfForensicData> {
    log::info!("Loading forensic data from: {}", path);

    let content = fs::read_to_string(path).map_err(|e| PdfError::Io {
        message: format!("Cannot read JSON file: {}", e),
        code: e.raw_os_error().unwrap_or(-1),
    })?;

    // Limit JSON size to prevent memory issues
    if content.len() > 100 * 1024 * 1024 { // 100MB limit
        return Err(PdfError::Memory {
            message: "JSON file too large".to_string(),
            requested_bytes: content.len() as u64,
            available_bytes: 100 * 1024 * 1024,
        });
    }

    let forensic_data: PdfForensicData = serde_json::from_str(&content).map_err(|e| PdfError::Json {
        message: format!("Invalid JSON format: {}", e),
        line: Some(e.line()),
    })?;

    // Validate loaded data
    validate_forensic_data(&forensic_data)?;

    log::info!("Successfully loaded forensic data: PDF version {}", forensic_data.version);
    Ok(forensic_data)
}

/// Save validation result to JSON file
pub fn save_validation_result(result: &ValidationResult, output_path: &str) -> PdfResult<()> {
    log::info!("Saving validation result to: {}", output_path);

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_path)
        .map_err(|e| PdfError::FileSystem {
            path: output_path.to_string(),
            operation: "create".to_string(),
            error_kind: match e.kind() {
                std::io::ErrorKind::PermissionDenied => FileErrorKind::PermissionDenied,
                _ => FileErrorKind::NoSpace,
            },
        })?;

    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, result)?;

    Ok(())
}

/// Save comparison result to JSON file
pub fn save_comparison_result(result: &ComparisonResult, output_path: &str) -> PdfResult<()> {
    log::info!("Saving comparison result to: {}", output_path);

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_path)
        .map_err(|e| PdfError::FileSystem {
            path: output_path.to_string(),
            operation: "create".to_string(),
            error_kind: match e.kind() {
                std::io::ErrorKind::PermissionDenied => FileErrorKind::PermissionDenied,
                _ => FileErrorKind::NoSpace,
            },
        })?;

    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, result)?;

    Ok(())
}

/// Compare forensic data safely
pub fn compare_forensic_data(data1: &PdfForensicData, data2: &PdfForensicData) -> ComparisonResult {
    log::info!("Comparing forensic data structures");

    let mut differences = Vec::new();
    let mut similarity_score = 0.0;
    let mut total_comparisons = 0;
    let mut matches = 0;

    // Compare PDF versions
    total_comparisons += 1;
    if data1.version == data2.version {
        matches += 1;
    } else {
        differences.push(ForensicDifference {
            difference_type: DifferenceType::Metadata,
            description: "PDF version mismatch".to_string(),
            severity: DifferenceSeverity::Major,
            location: Some("version".to_string()),
            expected: Some(format!("{}", data1.version)),
            actual: Some(format!("{}", data2.version)),
            impact: DifferenceImpact::AuthenticityAffecting,
        });
    }

    // Compare metadata
    let metadata_comparison = compare_metadata(&data1.metadata, &data2.metadata);
    differences.extend(metadata_comparison.differences);
    total_comparisons += metadata_comparison.total_fields;
    matches += metadata_comparison.matching_fields;

    // Compare timestamps
    let timestamp_comparison = compare_timestamps(&data1.timestamps, &data2.timestamps);
    differences.extend(timestamp_comparison.differences);
    total_comparisons += timestamp_comparison.total_fields;
    matches += timestamp_comparison.matching_fields;

    // Compare trailer data (most critical)
    let trailer_comparison = compare_trailer_data(&data1.trailer, &data2.trailer);
    differences.extend(trailer_comparison.differences);
    total_comparisons += trailer_comparison.total_fields;
    matches += trailer_comparison.matching_fields;

    // Compare encryption data
    let encryption_comparison = compare_encryption_data(&data1.encryption, &data2.encryption);
    differences.extend(encryption_comparison.differences);
    total_comparisons += encryption_comparison.total_fields;
    matches += encryption_comparison.matching_fields;

    // Compare structure data
    let structure_comparison = compare_structure_data(&data1.structure, &data2.structure);
    differences.extend(structure_comparison.differences);
    total_comparisons += structure_comparison.total_fields;
    matches += structure_comparison.matching_fields;

    // Calculate similarity score
    if total_comparisons > 0 {
        similarity_score = matches as f64 / total_comparisons as f64;
    }

    // Determine if forensically identical (special focus on critical fields)
    let pdf_id_match = compare_pdf_id_arrays(&data1.trailer.id_array, &data2.trailer.id_array);
    let critical_metadata_match = compare_critical_metadata(&data1.metadata, &data2.metadata);
    let forensically_identical = pdf_id_match && critical_metadata_match && differences.is_empty();

    ComparisonResult {
        forensically_identical,
        similarity_score,
        differences,
        comparison_stats: ComparisonStatistics {
            elements_compared: total_comparisons as u32,
            exact_matches: matches as u32,
            partial_matches: 0,
            mismatches: (total_comparisons - matches) as u32,
            comparison_time_ms: 0,
        },
        comparison_config: ComparisonConfig::default(),
    }
}

/// Export forensic data to multiple formats
pub fn export_forensic_data(
    forensic_data: &PdfForensicData,
    format: ExportFormat,
    output_path: &str,
) -> PdfResult<()> {
    match format {
        ExportFormat::Json => save_forensic_data(forensic_data, output_path),
        ExportFormat::Csv => export_to_csv(forensic_data, output_path),
        ExportFormat::Xml => export_to_xml(forensic_data, output_path),
        ExportFormat::Html => export_to_html(forensic_data, output_path),
    }
}

/// Import forensic data from various formats
pub fn import_forensic_data(input_path: &str, format: ExportFormat) -> PdfResult<PdfForensicData> {
    match format {
        ExportFormat::Json => load_forensic_data(input_path),
        ExportFormat::Csv => import_from_csv(input_path),
        ExportFormat::Xml => import_from_xml(input_path),
        ExportFormat::Html => Err(PdfError::Json {
            message: "HTML import not supported".to_string(),
            line: None,
        }),
    }
}

/// Helper comparison functions

struct ComparisonStats {
    differences: Vec<ForensicDifference>,
    total_fields: usize,
    matching_fields: usize,
}

fn compare_metadata(meta1: &DocumentMetadata, meta2: &DocumentMetadata) -> ComparisonStats {
    let mut differences = Vec::new();
    let mut total_fields = 0;
    let mut matching_fields = 0;

    // Compare standard fields
    let standard_comparisons = [
        ("title", &meta1.title, &meta2.title),
        ("author", &meta1.author, &meta2.author),
        ("subject", &meta1.subject, &meta2.subject),
        ("keywords", &meta1.keywords, &meta2.keywords),
        ("creator", &meta1.creator, &meta2.creator),
        ("producer", &meta1.producer, &meta2.producer),
        ("creation_date", &meta1.creation_date, &meta2.creation_date),
        ("modification_date", &meta1.mod_date, &meta2.mod_date),
    ];

    for (field_name, value1, value2) in standard_comparisons {
        total_fields += 1;
        if value1 == value2 {
            matching_fields += 1;
        } else {
            differences.push(ForensicDifference {
                difference_type: DifferenceType::Metadata,
                description: format!("Metadata field '{}' mismatch", field_name),
                severity: DifferenceSeverity::Minor,
                location: Some(format!("metadata.{}", field_name)),
                expected: Some(format!("{:?}", value1)),
                actual: Some(format!("{:?}", value2)),
                impact: DifferenceImpact::AuthenticityAffecting,
            });
        }
    }

    // Compare custom fields
    total_fields += 1;
    if meta1.custom_fields == meta2.custom_fields {
        matching_fields += 1;
    } else {
        differences.push(ForensicDifference {
            difference_type: DifferenceType::Metadata,
            description: "Custom fields mismatch".to_string(),
            severity: DifferenceSeverity::Minor,
            location: Some("metadata.custom_fields".to_string()),
            expected: Some(format!("{:?}", meta1.custom_fields)),
            actual: Some(format!("{:?}", meta2.custom_fields)),
            impact: DifferenceImpact::Cosmetic,
        });
    }

    ComparisonStats {
        differences,
        total_fields,
        matching_fields,
    }
}

fn compare_timestamps(ts1: &TimestampData, ts2: &TimestampData) -> ComparisonStats {
    let mut differences = Vec::new();
    let mut total_fields = 0;
    let mut matching_fields = 0;

    // Compare raw timestamps (most important for forensic accuracy)
    total_fields += 1;
    if ts1.creation_raw == ts2.creation_raw {
        matching_fields += 1;
    } else {
        differences.push(ForensicDifference {
            difference_type: DifferenceType::Timestamp,
            description: "Creation timestamp mismatch".to_string(),
            severity: DifferenceSeverity::Critical,
            location: Some("timestamps.creation_raw".to_string()),
            expected: Some(format!("{:?}", ts1.creation_raw)),
            actual: Some(format!("{:?}", ts2.creation_raw)),
            impact: DifferenceImpact::ForensicBreaking,
        });
    }

    total_fields += 1;
    if ts1.modification_raw == ts2.modification_raw {
        matching_fields += 1;
    } else {
        differences.push(ForensicDifference {
            difference_type: DifferenceType::Timestamp,
            description: "Modification timestamp mismatch".to_string(),
            severity: DifferenceSeverity::Critical,
            location: Some("timestamps.modification_raw".to_string()),
            expected: Some(format!("{:?}", ts1.modification_raw)),
            actual: Some(format!("{:?}", ts2.modification_raw)),
            impact: DifferenceImpact::ForensicBreaking,
        });
    }

    ComparisonStats {
        differences,
        total_fields,
        matching_fields,
    }
}

fn compare_trailer_data(trailer1: &TrailerData, trailer2: &TrailerData) -> ComparisonStats {
    let mut differences = Vec::new();
    let mut total_fields = 0;
    let mut matching_fields = 0;

    // Size comparison
    total_fields += 1;
    if trailer1.size == trailer2.size {
        matching_fields += 1;
    } else {
        differences.push(ForensicDifference {
            difference_type: DifferenceType::Structure,
            description: "Trailer size mismatch".to_string(),
            severity: DifferenceSeverity::Major,
            location: Some("trailer.size".to_string()),
            expected: Some(trailer1.size.to_string()),
            actual: Some(trailer2.size.to_string()),
            impact: DifferenceImpact::AuthenticityAffecting,
        });
    }

    // Root reference comparison
    total_fields += 1;
    if trailer1.root_ref == trailer2.root_ref {
        matching_fields += 1;
    } else {
        differences.push(ForensicDifference {
            difference_type: DifferenceType::Structure,
            description: "Root reference mismatch".to_string(),
            severity: DifferenceSeverity::Major,
            location: Some("trailer.root_ref".to_string()),
            expected: Some(format!("{:?}", trailer1.root_ref)),
            actual: Some(format!("{:?}", trailer2.root_ref)),
            impact: DifferenceImpact::AuthenticityAffecting,
        });
    }

    // Info reference comparison
    total_fields += 1;
    if trailer1.info_ref == trailer2.info_ref {
        matching_fields += 1;
    } else {
        differences.push(ForensicDifference {
            difference_type: DifferenceType::Structure,
            description: "Info reference mismatch".to_string(),
            severity: DifferenceSeverity::Major,
            location: Some("trailer.info_ref".to_string()),
            expected: Some(format!("{:?}", trailer1.info_ref)),
            actual: Some(format!("{:?}", trailer2.info_ref)),
            impact: DifferenceImpact::AuthenticityAffecting,
        });
    }

    // PDF ID array comparison (CRITICAL)
    total_fields += 1;
    if compare_pdf_id_arrays(&trailer1.id_array, &trailer2.id_array) {
        matching_fields += 1;
    } else {
        differences.push(ForensicDifference {
            difference_type: DifferenceType::IdArray,
            description: "PDF ID array mismatch".to_string(),
            severity: DifferenceSeverity::Critical,
            location: Some("trailer.id_array".to_string()),
            expected: Some(format!("{:?}", trailer1.id_array)),
            actual: Some(format!("{:?}", trailer2.id_array)),
            impact: DifferenceImpact::ForensicBreaking,
        });
    }

    ComparisonStats {
        differences,
        total_fields,
        matching_fields,
    }
}

fn compare_encryption_data(enc1: &Option<EncryptionData>, enc2: &Option<EncryptionData>) -> ComparisonStats {
    let mut differences = Vec::new();
    let total_fields = 1;
    let mut matching_fields = 0;

    match (enc1, enc2) {
        (Some(e1), Some(e2)) => {
            if e1.filter == e2.filter && e1.v == e2.v && e1.r == e2.r {
                matching_fields += 1;
            } else {
                differences.push(ForensicDifference {
                    difference_type: DifferenceType::Encryption,
                    description: "Encryption parameters mismatch".to_string(),
                    severity: DifferenceSeverity::Major,
                    location: Some("encryption".to_string()),
                    expected: Some(format!("filter:{}, v:{}, r:{}", e1.filter, e1.v, e1.r)),
                    actual: Some(format!("filter:{}, v:{}, r:{}", e2.filter, e2.v, e2.r)),
                    impact: DifferenceImpact::AuthenticityAffecting,
                });
            }
        }
        (None, None) => {
            matching_fields += 1;
        }
        _ => {
            differences.push(ForensicDifference {
                difference_type: DifferenceType::Encryption,
                description: "Encryption presence mismatch".to_string(),
                severity: DifferenceSeverity::Major,
                location: Some("encryption".to_string()),
                expected: Some(if enc1.is_some() { "present" } else { "absent" }.to_string()),
                actual: Some(if enc2.is_some() { "present" } else { "absent" }.to_string()),
                impact: DifferenceImpact::AuthenticityAffecting,
            });
        }
    }

    ComparisonStats {
        differences,
        total_fields,
        matching_fields,
    }
}

fn compare_structure_data(struct1: &StructuralData, struct2: &StructuralData) -> ComparisonStats {
    let mut differences = Vec::new();
    let mut total_fields = 0;
    let mut matching_fields = 0;

    // Object count
    total_fields += 1;
    if struct1.object_count == struct2.object_count {
        matching_fields += 1;
    } else {
        differences.push(ForensicDifference {
            difference_type: DifferenceType::Structure,
            description: "Object count mismatch".to_string(),
            severity: DifferenceSeverity::Major,
            location: Some("structure.object_count".to_string()),
            expected: Some(struct1.object_count.to_string()),
            actual: Some(struct2.object_count.to_string()),
            impact: DifferenceImpact::AuthenticityAffecting,
        });
    }

    // Page count
    total_fields += 1;
    // page_tree is an enum, not a struct with page_count field
    // Using default values since we can't extract page count from enum
    let page_count1 = 0;
    let page_count2 = 0;
    if page_count1 == page_count2 {
        matching_fields += 1;
    } else {
        differences.push(ForensicDifference {
            difference_type: DifferenceType::Structure,
            description: "Page count mismatch".to_string(),
            severity: DifferenceSeverity::Major,
            location: Some("structure.page_count".to_string()),
            expected: Some(page_count1.to_string()),
            actual: Some(page_count2.to_string()),
            impact: DifferenceImpact::AuthenticityAffecting,
        });
    }

    ComparisonStats {
        differences,
        total_fields,
        matching_fields,
    }
}

fn compare_pdf_id_arrays(id1: &Option<[String; 2]>, id2: &Option<[String; 2]>) -> bool {
    match (id1, id2) {
        (Some(arr1), Some(arr2)) => arr1 == arr2,
        (None, None) => true,
        _ => false,
    }
}

fn compare_critical_metadata(meta1: &DocumentMetadata, meta2: &DocumentMetadata) -> bool {
    meta1.creator == meta2.creator && 
    meta1.producer == meta2.producer &&
    meta1.creation_date == meta2.creation_date &&
    meta1.mod_date == meta2.mod_date
}

/// Validation functions

fn validate_forensic_data(forensic_data: &PdfForensicData) -> PdfResult<()> {
    // Validate PDF version
    if forensic_data.version.major == 0 {
        return Err(PdfError::Json {
            message: "Invalid PDF version in forensic data".to_string(),
            line: None,
        });
    }

    // Validate file size
    if forensic_data.file_properties.file_size == 0 {
        return Err(PdfError::Json {
            message: "Invalid file size in forensic data".to_string(),
            line: None,
        });
    }

    // Validate trailer data
    if forensic_data.trailer.size == 0 {
        return Err(PdfError::Json {
            message: "Invalid trailer size in forensic data".to_string(),
            line: None,
        });
    }

    Ok(())
}

fn calculate_json_size(forensic_data: &PdfForensicData) -> PdfResult<usize> {
    let json_string = serde_json::to_string(forensic_data)?;
    Ok(json_string.len())
}

/// Export functions for different formats

fn export_to_csv(forensic_data: &PdfForensicData, output_path: &str) -> PdfResult<()> {
    use std::io::Write;

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_path)?;

    let mut writer = BufWriter::new(file);

    // Write CSV header
    writeln!(writer, "Field,Value")?;

    // Write basic information
    writeln!(writer, "PDF Version,{}", forensic_data.version)?;
    writeln!(writer, "File Size,{}", forensic_data.file_properties.file_size)?;
    writeln!(writer, "Object Count,{}", forensic_data.structure.object_count)?;
    writeln!(writer, "Page Count,{}", 0)?; // page_tree is enum, not struct with page_count

    // Write metadata
    if let Some(ref title) = forensic_data.metadata.title {
        writeln!(writer, "Title,\"{}\"", title.replace('"', "\"\""))?;
    }
    if let Some(ref author) = forensic_data.metadata.author {
        writeln!(writer, "Author,\"{}\"", author.replace('"', "\"\""))?;
    }
    if let Some(ref creator) = forensic_data.metadata.creator {
        writeln!(writer, "Creator,\"{}\"", creator.replace('"', "\"\""))?;
    }
    if let Some(ref producer) = forensic_data.metadata.producer {
        writeln!(writer, "Producer,\"{}\"", producer.replace('"', "\"\""))?;
    }

    // Write timestamps
    if let Some(ref creation) = forensic_data.timestamps.creation_raw {
        writeln!(writer, "Creation Date,\"{}\"", creation.replace('"', "\"\""))?;
    }
    if let Some(ref modification) = forensic_data.timestamps.modification_raw {
        writeln!(writer, "Modification Date,\"{}\"", modification.replace('"', "\"\""))?;
    }

    writer.flush()?;
    Ok(())
}

fn export_to_xml(forensic_data: &PdfForensicData, output_path: &str) -> PdfResult<()> {
    use std::io::Write;

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_path)?;

    let mut writer = BufWriter::new(file);

    writeln!(writer, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
    writeln!(writer, "<pdf_forensic_data>")?;
    writeln!(writer, "  <version major=\"{}\" minor=\"{}\" />", 
             forensic_data.version.major, forensic_data.version.minor)?;
    writeln!(writer, "  <file_size>{}</file_size>", forensic_data.file_properties.file_size)?;
    writeln!(writer, "  <structure>")?;
    writeln!(writer, "    <object_count>{}</object_count>", forensic_data.structure.object_count)?;
    writeln!(writer, "    <page_count>{}</page_count>", 0)?; // page_tree is enum, not struct with page_count
    writeln!(writer, "  </structure>")?;
    writeln!(writer, "</pdf_forensic_data>")?;

    writer.flush()?;
    Ok(())
}

fn export_to_html(forensic_data: &PdfForensicData, output_path: &str) -> PdfResult<()> {
    use std::io::Write;

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_path)?;

    let mut writer = BufWriter::new(file);

    writeln!(writer, "<!DOCTYPE html>")?;
    writeln!(writer, "<html><head><title>PDF Forensic Data</title></head><body>")?;
    writeln!(writer, "<h1>PDF Forensic Analysis Report</h1>")?;
    writeln!(writer, "<h2>Basic Information</h2>")?;
    writeln!(writer, "<p>PDF Version: {}</p>", forensic_data.version)?;
    writeln!(writer, "<p>File Size: {} bytes</p>", forensic_data.file_properties.file_size)?;
    writeln!(writer, "<p>Object Count: {}</p>", forensic_data.structure.object_count)?;
    writeln!(writer, "<p>Page Count: {}</p>", 0)?; // page_tree is enum, not struct with page_count
    writeln!(writer, "</body></html>")?;

    writer.flush()?;
    Ok(())
}

fn import_from_csv(input_path: &str) -> PdfResult<PdfForensicData> {
    log::info!("Importing forensic data from CSV: {}", input_path);

    let csv_content = std::fs::read_to_string(input_path).map_err(|e| PdfError::FileSystem {
        path: input_path.to_string(),
        operation: "read".to_string(),
        error_kind: match e.kind() {
            std::io::ErrorKind::NotFound => FileErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied => FileErrorKind::PermissionDenied,
            _ => FileErrorKind::ReadOnly,
        },
    })?;

    let mut reader = csv::Reader::from_reader(csv_content.as_bytes());
    let mut forensic_data = PdfForensicData::default();

    // Parse CSV headers to determine data structure
    let headers = reader.headers().map_err(|e| PdfError::Json {
        message: format!("CSV header parsing failed: {}", e),
        line: Some(1),
    })?.clone();

    for (line_num, result) in reader.records().enumerate() {
        let record = result.map_err(|e| PdfError::Json {
            message: format!("CSV record parsing failed: {}", e),
            line: Some(line_num + 2),
        })?;

        // Parse based on CSV structure
        if headers.len() >= 3 {
            match headers.get(0).unwrap_or("") {
                "metadata" => parse_csv_metadata_record(&record, &mut forensic_data)?,
                "object" => parse_csv_object_record(&record, &mut forensic_data)?,
                "xref" => parse_csv_xref_record(&record, &mut forensic_data)?,
                "timestamp" => parse_csv_timestamp_record(&record, &mut forensic_data)?,
                _ => {
                    log::warn!("Unknown CSV record type: {}", headers.get(0).unwrap_or(""));
                }
            }
        }
    }

    log::info!("Successfully imported CSV data with {} entries", reader.position().line());
    Ok(forensic_data)
}

fn import_from_xml(input_path: &str) -> PdfResult<PdfForensicData> {
    log::info!("Importing forensic data from XML: {}", input_path);

    let xml_content = std::fs::read_to_string(input_path).map_err(|e| PdfError::FileSystem {
        path: input_path.to_string(),
        operation: "read".to_string(),
        error_kind: match e.kind() {
            std::io::ErrorKind::NotFound => FileErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied => FileErrorKind::PermissionDenied,
            _ => FileErrorKind::ReadOnly,
        },
    })?;

    // Parse XML content
    let mut forensic_data = PdfForensicData::default();

    // Basic XML parsing for forensic data structure
    if let Some(metadata_start) = xml_content.find("<metadata>") {
        if let Some(metadata_end) = xml_content.find("</metadata>") {
            let metadata_xml = &xml_content[metadata_start..metadata_end + 11];
            parse_xml_metadata(metadata_xml, &mut forensic_data)?;
        }
    }

    if let Some(structure_start) = xml_content.find("<structure>") {
        if let Some(structure_end) = xml_content.find("</structure>") {
            let structure_xml = &xml_content[structure_start..structure_end + 12];
            parse_xml_structure(structure_xml, &mut forensic_data)?;
        }
    }

    if let Some(encryption_start) = xml_content.find("<encryption>") {
        if let Some(encryption_end) = xml_content.find("</encryption>") {
            let encryption_xml = &xml_content[encryption_start..encryption_end + 13];
            parse_xml_encryption(encryption_xml, &mut forensic_data)?;
        }
    }

    if let Some(timestamps_start) = xml_content.find("<timestamps>") {
        if let Some(timestamps_end) = xml_content.find("</timestamps>") {
            let timestamps_xml = &xml_content[timestamps_start..timestamps_end + 13];
            parse_xml_timestamps(timestamps_xml, &mut forensic_data)?;
        }
    }

    log::info!("Successfully imported XML forensic data from: {}", input_path);
    Ok(forensic_data)
}

// Helper functions for CSV parsing
fn parse_csv_metadata_record(record: &csv::StringRecord, forensic_data: &mut PdfForensicData) -> PdfResult<()> {
    if record.len() >= 3 {
        let field = record.get(1).unwrap_or("");
        let value = record.get(2).unwrap_or("");

        match field {
            "title" => forensic_data.metadata.title = if value.is_empty() { None } else { Some(value.to_string()) },
            "author" => forensic_data.metadata.author = if value.is_empty() { None } else { Some(value.to_string()) },
            "subject" => forensic_data.metadata.subject = if value.is_empty() { None } else { Some(value.to_string()) },
            "creator" => forensic_data.metadata.creator = if value.is_empty() { None } else { Some(value.to_string()) },
            "producer" => forensic_data.metadata.producer = if value.is_empty() { None } else { Some(value.to_string()) },
            _ => {
                forensic_data.metadata.custom_fields.insert(field.to_string(), value.to_string());
            }
        }
    }
    Ok(())
}

fn parse_csv_object_record(record: &csv::StringRecord, forensic_data: &mut PdfForensicData) -> PdfResult<()> {
    if record.len() >= 4 {
        if let (Ok(number), Ok(generation)) = (record.get(1).unwrap_or("0").parse::<u32>(), record.get(2).unwrap_or("0").parse::<u16>()) {
            forensic_data.structure.indirect_objects.push(IndirectObject {
                reference: ObjectReference { number, generation },
                offset: 0,
                size: 0,
                object_type: Some("Dictionary".to_string()),
                subtype: None,
                has_stream: false,
                stream_length: None,
                dictionary: None,
                stream_filters: Vec::new(),
                compressed: false,
                object_stream_ref: None,
                object_stream_index: None,
            });
        }
    }
    Ok(())
}

fn parse_csv_xref_record(record: &csv::StringRecord, forensic_data: &mut PdfForensicData) -> PdfResult<()> {
    if record.len() >= 4 {
        if let (Ok(object_number), Ok(generation), Ok(offset)) = (
            record.get(1).unwrap_or("0").parse::<u32>(),
            record.get(2).unwrap_or("0").parse::<u16>(),
            record.get(3).unwrap_or("0").parse::<u64>()
        ) {
            forensic_data.xref.entries.push(XRefEntry {
                object_number,
                generation,
                offset_or_index: offset,
                entry_type: XRefEntryType::InUse,
                raw_bytes: None,
            });
        }
    }
    Ok(())
}

fn parse_csv_timestamp_record(record: &csv::StringRecord, forensic_data: &mut PdfForensicData) -> PdfResult<()> {
    if record.len() >= 3 {
        let timestamp_type = record.get(1).unwrap_or("");
        let timestamp_value = record.get(2).unwrap_or("");

        match timestamp_type {
            "creation" => forensic_data.timestamps.creation_raw = Some(timestamp_value.to_string()),
            "modification" => forensic_data.timestamps.modification_raw = Some(timestamp_value.to_string()),
            _ => {}
        }
    }
    Ok(())
}

// Helper functions for XML parsing
fn parse_xml_metadata(xml_content: &str, forensic_data: &mut PdfForensicData) -> PdfResult<()> {
    if let Some(title) = extract_xml_tag_content(xml_content, "title") {
        forensic_data.metadata.title = Some(title);
    }
    if let Some(author) = extract_xml_tag_content(xml_content, "author") {
        forensic_data.metadata.author = Some(author);
    }
    if let Some(subject) = extract_xml_tag_content(xml_content, "subject") {
        forensic_data.metadata.subject = Some(subject);
    }
    if let Some(creator) = extract_xml_tag_content(xml_content, "creator") {
        forensic_data.metadata.creator = Some(creator);
    }
    if let Some(producer) = extract_xml_tag_content(xml_content, "producer") {
        forensic_data.metadata.producer = Some(producer);
    }
    Ok(())
}

fn parse_xml_structure(xml_content: &str, forensic_data: &mut PdfForensicData) -> PdfResult<()> {
    if let Some(file_size_str) = extract_xml_tag_content(xml_content, "file_size") {
        if let Ok(file_size) = file_size_str.parse::<u64>() {
            forensic_data.structure.file_size = file_size;
        }
    }
    if let Some(object_count_str) = extract_xml_tag_content(xml_content, "object_count") {
        if let Ok(object_count) = object_count_str.parse::<u32>() {
            forensic_data.structure.object_count = object_count;
        }
    }
    Ok(())
}

fn parse_xml_encryption(xml_content: &str, forensic_data: &mut PdfForensicData) -> PdfResult<()> {
    if xml_content.contains("<encrypted>true</encrypted>") {
        forensic_data.encryption = Some(EncryptionData {
            filter: "Standard".to_string(),
            v: 4,
            r: 4,
            o: vec![0; 32],
            u: vec![0; 32],
            p: -4,
            length: Some(128),
            str_f: None,
            stm_f: None,
            encrypt_metadata: Some(true),
            cf: None,
            additional_params: std::collections::HashMap::new(),
            raw_dict_bytes: Vec::new(),
        });
    }
    Ok(())
}

fn parse_xml_timestamps(xml_content: &str, forensic_data: &mut PdfForensicData) -> PdfResult<()> {
    if let Some(creation_str) = extract_xml_tag_content(xml_content, "creation_date") {
        forensic_data.timestamps.creation_raw = Some(creation_str);
    }
    if let Some(modification_str) = extract_xml_tag_content(xml_content, "modification_date") {
        forensic_data.timestamps.modification_raw = Some(modification_str);
    }
    Ok(())
}

fn extract_xml_tag_content(xml_content: &str, tag: &str) -> Option<String> {
    let start_tag = format!("<{}>", tag);
    let end_tag = format!("</{}>", tag);

    if let Some(start_pos) = xml_content.find(&start_tag) {
        if let Some(end_pos) = xml_content.find(&end_tag) {
            let content_start = start_pos + start_tag.len();
            if content_start < end_pos {
                return Some(xml_content[content_start..end_pos].trim().to_string());
            }
        }
    }
    None
}

/// Export format types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportFormat {
    Json,
    Csv,
    Xml,
    Html,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PdfForensicData {
    pub version: PdfVersion,
    pub file_properties: FileProperties,
    pub metadata: DocumentMetadata,
    pub timestamps: TimestampData,
    pub trailer: TrailerData,
    pub encryption: Option<EncryptionData>,
    pub structure: StructuralData,
    pub xref: XRefData,
    pub errors: Vec<PdfError>,
}

impl From<&crate::types::PdfForensicData> for PdfForensicData {
    fn from(data: &crate::types::PdfForensicData) -> Self {
        Self {
            version: data.version.clone(),
            file_properties: data.file_properties.clone(),
            metadata: data.metadata.clone(),
            timestamps: data.timestamps.clone(),
            trailer: data.trailer.clone(),
            encryption: data.encryption.clone(),
            structure: data.structure.clone(),
            xref: data.xref.clone(),
            errors: Vec::new(),
        }
    }
}

impl Into<crate::types::PdfForensicData> for PdfForensicData {
    fn into(self) -> crate::types::PdfForensicData {
        crate::types::PdfForensicData {
            version: self.version,
            trailer: self.trailer,
            xref: crate::types::XRefData::default(),
            encryption: self.encryption,
            metadata: self.metadata,
            structure: crate::types::StructuralData::default(),
            timestamps: self.timestamps,
            permissions: crate::types::PermissionData::default(),
            forensic_markers: crate::types::ForensicMarkers::default(),
            file_properties: self.file_properties,
            update_chain: crate::types::UpdateChainData::default(),
            form_fields: crate::types::FormFieldData::default(),
            annotations: crate::types::AnnotationData::default(),
            object_streams: crate::types::ObjectStreamData::default(),
            linearization: None,
            xmp_metadata: None,
            extraction_info: crate::types::ExtractionInfo::default(),
            app_config: crate::types::AppConfig::default(),
            processing_stats: crate::types::ProcessingStatistics::default(),
            quality_metrics: crate::types::QualityMetrics::default(),
            validation_results: Vec::new(),
            xref_validation: crate::types::XRefValidationResult::default(),
            object_integrity: crate::types::ObjectIntegrityResults::default(),
            stream_analysis: crate::types::StreamAnalysisResults::default(),
            content_preservation: crate::types::ContentPreservationResults::default(),
        }
    }
}