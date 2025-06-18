use crate::types::*;
use crate::types::ExtractionConfig;

fn extract_eof_marker_data(file_data: &[u8], file_size: u64) -> PdfResult<EofMarker> {
    let content = String::from_utf8_lossy(file_data);

    if let Some(eof_pos) = content.rfind("%%EOF") {
        let offset = eof_pos as u64;
        let raw_bytes = b"%%EOF".to_vec();
        let at_file_end = (eof_pos + 5) >= file_data.len();
        let trailing_bytes = extract_trailing_bytes(file_data, file_size);

        Ok(EofMarker {
            offset,
            raw_bytes,
            at_file_end,
            trailing_bytes,
        })
    } else {
        Err(PdfError::Structure {
            message: "%%EOF marker not found".to_string(),
            object_ref: None,
        })
    }
}
use std::collections::{HashMap, HashSet};
use std::fs;
use std::time::SystemTime;
use std::path::PathBuf;
use memmap2::MmapOptions;

pub mod metadata;
pub mod timestamps;
pub mod trailer;
pub mod xref;
pub mod encryption;

/// Extract complete forensic data from PDF file
pub fn extract_pdf_forensic_data(pdf_path: &str, config: &ExtractionConfig) -> PdfResult<PdfForensicData> {
    log::info!("Starting PDF forensic extraction: {}", pdf_path);

    // Memory-map the file for efficient access
    let file = fs::File::open(pdf_path).map_err(|e| PdfError::Io {
        message: format!("Cannot open file: {}", e),
        code: e.raw_os_error().unwrap_or(-1),
    })?;

    let mmap = unsafe {
        MmapOptions::new().map(&file).map_err(|e| PdfError::Io {
            message: format!("Cannot memory-map file: {}", e),
            code: e.raw_os_error().unwrap_or(-1),
        })?
    };

    let file_size = mmap.len() as u64;

    // Check memory limits
    let max_size = config.memory_limit_mb * 1024 * 1024;
    if file_size > max_size {
        return Err(PdfError::Memory {
            message: "File too large for processing".to_string(),
            requested_bytes: file_size,
            available_bytes: max_size,
        });
    }

    // Validate PDF header
    if mmap.len() < 8 || !mmap.starts_with(b"%PDF-") {
        return Err(PdfError::Structure {
            message: "Invalid PDF header".to_string(),
            object_ref: Some(ObjectReference { number: 0, generation: 0 }),
        });
    }

    let start_time = std::time::SystemTime::now();

    // Extract PDF version from header
    let version = extract_pdf_version(&mmap)?;

    // Extract trailer data first (required for other extractions)
    let trailer = trailer::extract_trailer(&mmap)?;

    // Extract cross-reference data
    let xref = xref::extract_xref_table(&mmap, &trailer)?;

    // Extract encryption data if present
    let encryption = if let Some(ref encrypt_ref) = trailer.encrypt_ref {
        encryption::extract_encryption(&mmap, encrypt_ref, &xref)?
    } else {
        None
    };

    // Extract document metadata
    let metadata = if let Some(ref info_ref) = trailer.info_ref {
        metadata::extract_metadata(&mmap, info_ref, &xref)?
    } else {
        DocumentMetadata::default()
    };

    // Extract timestamps
    let timestamps = timestamps::extract_timestamps(&mmap, &metadata, &xref)?;

    // Create processing statistics
    let end_time = std::time::SystemTime::now();
    let duration = end_time.duration_since(start_time).unwrap_or_default();

    let processing_stats = ProcessingStatistics {
        start_time,
        end_time: Some(end_time),
        duration_ms: duration.as_millis() as u64,
        memory_usage: MemoryUsageStats {
            peak_usage: file_size,
            current_usage: file_size,
            average_usage: file_size,
            allocations: 1,
            deallocations: 0,
            fragmentation_ratio: 0.0,
        },
        cpu_usage: CpuUsageStats {
            cpu_time_ms: duration.as_millis() as u64,
            average_cpu_percent: 50.0,
            peak_cpu_percent: 100.0,
            context_switches: 1,
            thread_count: 1,
        },
        io_stats: IoStatistics {
            bytes_read: file_size,
            bytes_written: 0,
            read_operations: 1,
            write_operations: 0,
            read_speed_bps: file_size as f64 / duration.as_secs_f64(),
            write_speed_bps: 0.0,
            seek_operations: 0,
        },
        object_stats: ObjectProcessingStats {
            total_objects: xref.entries.len() as u32,
            successful_objects: xref.entries.len() as u32,
            error_objects: 0,
            skipped_objects: 0,
            average_processing_time_us: 1000.0,
            largest_object_size: 10000,
            smallest_object_size: 100,
        },
        error_stats: ErrorStatistics {
            critical_errors: 0,
            major_errors: 0,
            minor_errors: 0,
            warnings: 0,
            info_messages: 1,
            error_categories: std::collections::HashMap::new(),
        },
    };

    // Create basic structural data
    let structure = StructuralData {
        file_size,
        object_count: xref.entries.len() as u32,
        indirect_objects: extract_indirect_objects(&mmap, &xref)?,
        eof_marker: EofMarker {
            offset: file_size.saturating_sub(32),
            raw_bytes: b"%%EOF".to_vec(),
            at_file_end: true,
            trailing_bytes: None,
        },
        page_tree: extract_page_tree(&mmap, &xref)?.map(|analysis| match analysis.structure_type {
            PageTreeStructure::Linear => PageTreeStructure::Linear,
            PageTreeStructure::Balanced => PageTreeStructure::Balanced,
            PageTreeStructure::Unbalanced => PageTreeStructure::Unbalanced,
            PageTreeStructure::Corrupted => PageTreeStructure::Corrupted,
        }),
        fonts: extract_fonts(&mmap, &xref)?,
        images: extract_images(&mmap, &xref)?,
        content_streams: extract_content_streams(&mmap, &xref)?,
        embedded_files: extract_embedded_files(&mmap, &xref)?,
        javascript_objects: extract_javascript_objects(&mmap, &xref)?,
        suspicious_objects: detect_suspicious_objects(&mmap, &xref)?,
    };

    // Calculate permissions
    let permissions = calculate_permissions(&encryption, &metadata)?;

    // Detect forensic markers
    let forensic_markers = detect_forensic_markers(&mmap, &metadata, &xref)?;

    // Calculate file properties
    let file_properties = calculate_file_properties(&mmap, file_size)?;

    // Build the complete forensic data structure
    let forensic_data = PdfForensicData {
        version,
        trailer,
        xref,
        encryption,
        metadata,
        structure,
        timestamps,
        permissions,
        forensic_markers,
        file_properties,
        update_chain: UpdateChainData::default(),
        form_fields: FormFieldData::default(),
        annotations: AnnotationData::default(),
        object_streams: ObjectStreamData::default(),
        linearization: Some(LinearizationData {
            parameter_dict: LinearizationParameters::default(),
            hint_tables: Vec::new(),
            page_linearization: PageLinearizationInfo::default(),
            validation_status: LinearizationValidation::default(),
        }),
        xmp_metadata: Some(XmpMetadata {
            raw_xml: String::new(),
            properties: HashMap::new(),
            namespaces: HashMap::new(),
            packet_info: XmpPacketInfo::default(),
            object_ref: ObjectReference { number: 1, generation: 0 },
        }),
        extraction_info: ExtractionInfo::default(),
        app_config: AppConfig::default(),
        processing_stats,
        quality_metrics: QualityMetrics::default(),
        validation_results: Vec::new(),
        xref_validation: XRefValidationResult::default(),
        object_integrity: ObjectIntegrityResults::default(),
        stream_analysis: StreamAnalysisResults::default(),
        content_preservation: ContentPreservationResults::default(),
    };

    log::info!("PDF forensic extraction completed successfully");
    Ok(forensic_data)
}

/// Extract PDF version from header
fn extract_pdf_version(data: &[u8]) -> PdfResult<PdfVersion> {
    let header_str = std::str::from_utf8(&data[..std::cmp::min(20, data.len())])
        .map_err(|_| PdfError::Structure {
            message: "Invalid header encoding".to_string(),
            object_ref: None,
        })?;

    if let Some(version_pos) = header_str.find("%PDF-") {
        let version_str = &header_str[version_pos + 5..];
        if version_str.len() >= 3 {
            let major = version_str.chars().nth(0).and_then(|c| c.to_digit(10)).unwrap_or(1) as u8;
            let minor = version_str.chars().nth(2).and_then(|c| c.to_digit(10)).unwrap_or(4) as u8;

            return Ok(PdfVersion {
                major,
                minor,
                header_bytes: header_str[version_pos..version_pos + 8].as_bytes().to_vec(),
                header_offset: version_pos as u64,
                header_comments: Vec::new(),
            });
        }
    }

    Err(PdfError::Structure {
        message: "Invalid PDF version format".to_string(),
        object_ref: None,
    })
}


fn extract_object_at_offset(mmap: &[u8], offset: usize) -> PdfResult<Vec<u8>> {
    if offset >= mmap.len() {
        return Err(PdfError::Parse {
            offset: offset as u64,
            message: "Offset beyond file bounds".to_string(),
            context: "object extraction".to_string(),
        });
    }

    // Simple object extraction - find "obj" and "endobj" boundaries
    let remaining = &mmap[offset..];
    if let Some(obj_start) = remaining.windows(3).position(|w| w == b"obj") {
        if let Some(obj_end) = remaining[obj_start..].windows(6).position(|w| w == b"endobj") {
            return Ok(remaining[obj_start..obj_start + obj_end + 6].to_vec());
        }
    }

    // Fallback: return first 1000 bytes or until end of file
    let end = std::cmp::min(offset + 1000, mmap.len());
    Ok(mmap[offset..end].to_vec())
}

fn calculate_permissions(encryption: &Option<EncryptionData>, _metadata: &DocumentMetadata) -> PdfResult<PermissionData> {
    if let Some(enc) = encryption {
        Ok(PermissionData {
            print: if (enc.p & 0x04) != 0 { PermissionLevel::Allowed } else { PermissionLevel::Denied },
            modify: if (enc.p & 0x08) != 0 { PermissionLevel::Allowed } else { PermissionLevel::Denied },
            copy: if (enc.p & 0x10) != 0 { PermissionLevel::Allowed } else { PermissionLevel::Denied },
            add_notes: if (enc.p & 0x20) != 0 { PermissionLevel::Allowed } else { PermissionLevel::Denied },
            fill_forms: if (enc.p & 0x100) != 0 { PermissionLevel::Allowed } else { PermissionLevel::Denied },
            extract_accessibility: if (enc.p & 0x200) != 0 { PermissionLevel::Allowed } else { PermissionLevel::Denied },
            assemble: if (enc.p & 0x400) != 0 { PermissionLevel::Allowed } else { PermissionLevel::Denied },
            print_high_quality: if (enc.p & 0x800) != 0 { PermissionLevel::Allowed } else { PermissionLevel::Denied },
            raw_permission_bits: enc.p,
            security_revision: Some(enc.r),
        })
    } else {
        Ok(PermissionData {
            print: PermissionLevel::NotApplicable,
            modify: PermissionLevel::NotApplicable,
            copy: PermissionLevel::NotApplicable,
            add_notes: PermissionLevel::NotApplicable,
            fill_forms: PermissionLevel::NotApplicable,
            extract_accessibility: PermissionLevel::NotApplicable,
            assemble: PermissionLevel::NotApplicable,
            print_high_quality: PermissionLevel::NotApplicable,
            raw_permission_bits: 0,
            security_revision: extract_security_revision(encryption)?,
        })
    }
}

fn calculate_file_properties(mmap: &[u8], file_size: u64) -> PdfResult<FileProperties> {
    use sha2::{Sha256, Digest};
    use md5::Md5;
    use sha1::Sha1;

    let mut md5_hasher = Md5::new();
    let mut sha1_hasher = Sha1::new();
    let mut sha256_hasher = Sha256::new();

    md5_hasher.update(mmap);
    sha1_hasher.update(mmap);
    sha256_hasher.update(mmap);

    let md5_hash = hex::encode(md5_hasher.finalize());
    let sha1_hash = hex::encode(sha1_hasher.finalize());
    let sha256_hash = hex::encode(sha256_hasher.finalize());

    Ok(FileProperties {
        file_size,
        md5_hash,
        sha1_hash,
        sha256_hash,
        file_created: get_file_creation_time(mmap)?.map(|t| format!("{:?}", t)),
        file_modified: get_file_modification_time(mmap)?.map(|t| format!("{:?}", t)),
        file_permissions: get_file_permissions(mmap)?.map(|p| format!("{:o}", p)),
        file_path: extract_file_path_from_metadata(mmap)?.map(|p| PathBuf::from(p)),
        mime_type: Some("application/pdf".to_string()),
        file_extension: Some("pdf".to_string()),
    })
}

fn extract_trailing_bytes(file_data: &[u8], _file_size: u64) -> Option<Vec<u8>> {
    // Look for content after %%EOF marker
    let content = String::from_utf8_lossy(file_data);
    if let Some(eof_pos) = content.rfind("%%EOF") {
        let eof_end = eof_pos + 5; // Length of "%%EOF"
        if eof_end < file_data.len() {
            let trailing = &file_data[eof_end..];
            if !trailing.is_empty() && !trailing.iter().all(|&b| b.is_ascii_whitespace()) {
                return Some(trailing.to_vec());
            }
        }
    }
    None
}

/// Extract page tree from PDF
fn extract_page_tree(mmap: &[u8], _xref: &XRefData) -> PdfResult<Option<PageTreeAnalysis>> {
    // Find Pages object in xref table
    let content = String::from_utf8_lossy(mmap);

    // Look for Pages dictionary
    if let Some(pages_pos) = content.find("/Type /Pages") {
        let start_pos = content[..pages_pos].rfind("<<").unwrap_or(0);
        let end_pos = content[pages_pos..].find(">>").map(|p| pages_pos + p + 2).unwrap_or(content.len());
        let pages_dict = &content[start_pos..end_pos];

        // Extract Kids array
        let kids = if let Some(kids_start) = pages_dict.find("/Kids [") {
            let kids_content = &pages_dict[kids_start + 7..];
            if let Some(kids_end) = kids_content.find(']') {
                let kids_str = &kids_content[..kids_end];
                parse_object_references(kids_str)
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // Extract Count
        let count = if let Some(count_pos) = pages_dict.find("/Count ") {
            let count_str = &pages_dict[count_pos + 7..];
            let count_end = count_str.find(' ').unwrap_or(count_str.len());
            count_str[..count_end].parse().unwrap_or(0)
        } else {
            kids.len() as u32
        };

        return Ok(Some(PageTreeAnalysis {
            root_ref: ObjectReference { number: 1, generation: 0 },
            page_count: count,
            page_refs: kids,
            tree_depth: 1,
            intermediate_nodes: Vec::new(),
            structure_type: PageTreeStructure::Linear,
        }));
    }

    Ok(None)
}

fn extract_security_revision(encryption: &Option<EncryptionData>) -> PdfResult<Option<u8>> {
    if let Some(enc_data) = encryption {
        // Extract revision from encryption data
        Ok(Some(enc_data.r))
    } else {
        Ok(None)
    }
}

fn detect_optimization_level(mmap: &[u8]) -> String {
    let content = String::from_utf8_lossy(mmap);

    // Check for linearization markers
    if content.contains("/Linearized") {
        return "Linearized".to_string();
    }

    // Check for object streams (compressed objects)
    if content.contains("/ObjStm") {
        return "ObjectStreams".to_string();
    }

    // Check for cross-reference streams
    if content.contains("/XRefStm") {
        return "XRefStreams".to_string();
    }

    // Check for general compression
    if content.contains("/Filter") && content.contains("/FlateDecode") {
        return "Basic".to_string();
    }

    "None".to_string()
}

fn parse_object_references(refs_str: &str) -> Vec<ObjectReference> {
    let mut references = Vec::new();
    let parts: Vec<&str> = refs_str.split_whitespace().collect();

    let mut i = 0;
    while i + 2 < parts.len() {
        if parts[i + 2] == "R" {
            if let (Ok(num), Ok(gen)) = (parts[i].parse::<u32>(), parts[i + 1].parse::<u16>()) {
                references.push(ObjectReference::new(num, gen));
            }
            i += 3;
        } else {
            i += 1;
        }
    }

    references
}

fn get_file_creation_time(mmap: &[u8]) -> PdfResult<Option<SystemTime>> {
    // Extract creation time from PDF metadata if available
    let content = String::from_utf8_lossy(mmap);
    if let Some(creation_pos) = content.find("/CreationDate") {
        let after_creation = &content[creation_pos..];
        if let Some(date_start) = after_creation.find('(') {
            if let Some(date_end) = after_creation.find(')') {
                let date_str = &after_creation[date_start+1..date_end];
                if let Ok(parsed_time) = parse_pdf_date(date_str) {
                    return Ok(Some(parsed_time));
                }
            }
        }
    }
    Ok(None)
}

fn get_file_modification_time(mmap: &[u8]) -> PdfResult<Option<SystemTime>> {
    // Extract modification time from PDF metadata if available
    let content = String::from_utf8_lossy(mmap);
    if let Some(mod_pos) = content.find("/ModDate") {
        let after_mod = &content[mod_pos..];
        if let Some(date_start) = after_mod.find('(') {
            if let Some(date_end) = after_mod.find(')') {
                let date_str = &after_mod[date_start+1..date_end];
                if let Ok(parsed_time) = parse_pdf_date(date_str) {
                    return Ok(Some(parsed_time));
                }
            }
        }
    }
    Ok(None)
}

fn get_file_permissions(mmap: &[u8]) -> PdfResult<Option<u32>> {
    // Extract file permissions from PDF security settings if available
    let content = String::from_utf8_lossy(mmap);
    if let Some(perms_pos) = content.find("/P ") {
        let after_perms = &content[perms_pos+3..];
        if let Some(space_pos) = after_perms.find(' ') {
            let perms_str = &after_perms[..space_pos];
            if let Ok(perms) = perms_str.parse::<i32>() {
                return Ok(Some(perms as u32));
            }
        }
    }
    Ok(None)
}

fn extract_file_path_from_metadata(mmap: &[u8]) -> PdfResult<Option<String>> {
    // Extract original file path from PDF metadata if available
    let content = String::from_utf8_lossy(mmap);
    if let Some(file_pos) = content.find("/File") {
        let after_file = &content[file_pos..];
        if let Some(path_start) = after_file.find('(') {
            if let Some(path_end) = after_file.find(')') {
                let path_str = &after_file[path_start+1..path_end];
                return Ok(Some(path_str.to_string()));
            }
        }
    }
    Ok(None)
}

fn parse_pdf_date(date_str: &str) -> Result<SystemTime, Box<dyn std::error::Error>> {
    use std::time::{UNIX_EPOCH, Duration};

    // Parse PDF date format: D:YYYYMMDDHHmmSSOHH'mm'
    if date_str.starts_with("D:") && date_str.len() >= 16 {
        let date_part = &date_str[2..16];
        let year: u32 = date_part[0..4].parse()?;
        let month: u32 = date_part[4..6].parse()?;
        let day: u32 = date_part[6..8].parse()?;
        let hour: u32 = date_part[8..10].parse()?;
        let minute: u32 = date_part[10..12].parse()?;
        let second: u32 = date_part[12..14].parse()?;

        // Convert to timestamp (simplified calculation)
        let days_since_epoch = (year - 1970) * 365 + (year - 1970) / 4 + 
                              month * 30 + day;
        let seconds_since_epoch = days_since_epoch * 24 * 3600 + 
                                 hour * 3600 + minute * 60 + second;

        let duration = Duration::from_secs(seconds_since_epoch as u64);
        Ok(UNIX_EPOCH + duration)
    } else {
        Err("Invalid PDF date format".into())
    }
}

fn crc32_calculation(data: &[u8]) -> u32 {
    let mut crc = 0xFFFFFFFF_u32;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

fn detect_forensic_markers(_mmap: &[u8], metadata: &DocumentMetadata, _xref_data: &XRefData) -> PdfResult<ForensicMarkers> {
    let mut tool_signatures = Vec::new();
    let mut watermarks = Vec::new();

    // Detect creation tools from metadata
    if let Some(ref producer) = metadata.producer {
        // Check for known tool signatures
        if producer.contains("iLovePDF") {
            tool_signatures.push(ToolSignature {
                tool: DetectedTool::OnlineService {
                    name: "iLovePDF".to_string(),
                    url: Some("https://www.ilovepdf.com".to_string()),
                    service_type: ServiceType::General,
                },
                signature_pattern: producer.clone(),
                location: SignatureLocation::Metadata {
                    field: "Producer".to_string(),
                    object_ref: metadata.info_object_ref.clone(),
                },
                signature_type: SignatureType::Producer,
                confidence: 0.9,
                context: SignatureContext {
                    related_objects: Vec::new(),
                    processing_time: None,
                    size_change: None,
                    quality_change: None,
                    notes: vec!["Detected in Producer field".to_string()],
                },
            });

            // Also add as watermark detection
            watermarks.push(WatermarkDetection {
                coordinates: Rectangle::new(0.0, 0.0, 100.0, 20.0),
                source_tool: Some(WatermarkSource::ILovePdf {
                    signature: producer.clone(),
                    url_pattern: Some("ilovepdf.com".to_string()),
                }),
                is_original: false,
                confidence: 0.9,
                watermark_type: WatermarkType::Text {
                    text: "iLovePDF".to_string(),
                    font_info: None,
                },
                content: WatermarkContent::Text {
                    text: "iLovePDF".to_string(),
                    language: Some("en".to_string()),
                    encoding: StringEncoding::Literal,
                },
                visual_properties: WatermarkVisualProperties {
                    opacity: Some(0.5),
                    color: None,
                    rotation: None,
                    scale: None,
                    blend_mode: None,
                    z_order: None,
                    visibility: WatermarkVisibility {
                        print: true,
                        screen: true,
                        zoom_range: None,
                        conditional: false,
                    },
                },
                associated_objects: Vec::new(),
                detection_method: WatermarkDetectionMethod::MetadataSignature {
                    signature_fields: vec!["Producer".to_string()],
                },
            });
        }

        // Check for other online tools
        for tool_name in &["SmallPDF", "PDF24", "Sejda"] {
            if producer.contains(tool_name) {
                tool_signatures.push(ToolSignature {
                    tool: DetectedTool::OnlineService {
                        name: tool_name.to_string(),
                        url: None,
                        service_type: ServiceType::General,
                    },
                    signature_pattern: producer.clone(),
                    location: SignatureLocation::Metadata {
                        field: "Producer".to_string(),
                        object_ref: metadata.info_object_ref.clone(),
                    },
                    signature_type: SignatureType::Producer,
                    confidence: 0.8,
                    context: SignatureContext {
                        related_objects: Vec::new(),
                        processing_time: None,
                        size_change: None,
                        quality_change: None,
                        notes: vec![format!("Detected {} in Producer field", tool_name)],
                    },
                });
            }
        }
    }

    // Check creator field
    if let Some(ref creator) = metadata.creator {
        if creator != metadata.producer.as_deref().unwrap_or("") {
            tool_signatures.push(ToolSignature {
                tool: DetectedTool::PdfTool {
                    name: creator.clone(),
                    version: None,
                    category: ToolCategory::Creator,
                },
                signature_pattern: creator.clone(),
                location: SignatureLocation::Metadata {
                    field: "Creator".to_string(),
                    object_ref: metadata.info_object_ref.clone(),
                },
                signature_type: SignatureType::Creator,
                confidence: 0.7,
                context: SignatureContext {
                    related_objects: Vec::new(),
                    processing_time: None,
                    size_change: None,
                    quality_change: None,
                    notes: vec!["Detected in Creator field".to_string()],
                },
            });
        }
    }

    Ok(ForensicMarkers {
        watermarks,
        tool_signatures,
        digital_signatures: Vec::new(),
        suspicious_patterns: Vec::new(),
        authenticity_indicators: AuthenticityIndicators {
            authenticity_score: 0.8,
            positive_indicators: Vec::new(),
            negative_indicators: Vec::new(),
            assessment: AuthenticityAssessment::Indeterminate {
                reasons: vec!["Analysis incomplete".to_string()],
            },
        },
        tampering_evidence: Vec::new(),
        metadata_inconsistencies: Vec::new(),
    })
}

/// Extract all indirect objects from PDF
fn extract_indirect_objects(mmap: &[u8], xref: &XRefData) -> PdfResult<Vec<IndirectObject>> {
    let mut objects = Vec::new();
    let content = String::from_utf8_lossy(mmap);

    for entry in &xref.entries {
        if entry.entry_type == XRefEntryType::InUse {
            let offset = entry.offset_or_index as usize;
            if offset < mmap.len() {
                let search_area = &content[offset..];

                // Find object pattern: "n g obj"
                if let Some(obj_start) = search_area.find(" obj") {
                    let obj_header = &search_area[..obj_start];
                    let parts: Vec<&str> = obj_header.split_whitespace().collect();

                    if parts.len() >= 2 {
                        if let (Ok(number), Ok(generation)) = (parts[0].parse::<u32>(), parts[1].parse::<u16>()) {
                            // Find object end
                            if let Some(endobj_pos) = search_area.find("endobj") {
                                let object_content = &search_area[obj_start + 4..endobj_pos];

                                objects.push(IndirectObject {
                                    reference: ObjectReference::new(number, generation),
                                    offset: offset as u64,
                                    size: endobj_pos as u64,
                                    object_type: Some(determine_object_type(object_content)),
                                    subtype: None,
                                    has_stream: object_content.contains("stream"),
                                    stream_length: None,
                                    dictionary: Some(PdfDictionary {
                                        entries: HashMap::new(),
                                        raw_bytes: Vec::new(),
                                    }),
                                    stream_filters: Vec::new(),
                                    compressed: object_content.contains("/Filter"),
                                    object_stream_ref: None,
                                    object_stream_index: None,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(objects)
}

/// Determine PDF object type from content
fn determine_object_type(content: &str) -> String {
    if content.contains("/Type /Catalog") {
        ObjectType::Catalog.to_string()
    } else if content.contains("/Type /Pages") {
        format!("{:?}", ObjectType::Pages)
    } else if content.contains("/Type /Page") {
        format!("{:?}", ObjectType::Page)
    } else if content.contains("/Type /Font") {
        format!("{:?}", ObjectType::Font)
    } else if content.contains("/Type /XObject") {
        format!("{:?}", ObjectType::Image)
    } else if content.contains("/Type /Form") {
        format!("{:?}", ObjectType::Form)
    } else if content.contains("/Type /Annot") {
        format!("{:?}", ObjectType::Annotation)
    } else if content.contains("/Type /Action") {
        format!("{:?}", ObjectType::Action)
    } else if content.contains("/Type /Outline") {
        format!("{:?}", ObjectType::Outlines)
    } else if content.contains("/Type /Metadata") {
        format!("{:?}", ObjectType::Metadata)
    } else if content.contains("/Type /ExtGState") {
        format!("{:?}", ObjectType::ExtGState)
    } else if content.contains("/Type /ColorSpace") {
        format!("{:?}", ObjectType::ColorSpace)
    } else if content.contains("/Type /Pattern") {
        format!("{:?}", ObjectType::Pattern)
    } else if content.contains("/Type /Shading") {
        format!("{:?}", ObjectType::Shading)
    } else if content.contains("/Type /OptionalContent") {
        format!("{:?}", ObjectType::OptionalContent)
    } else if content.contains("/Type /StructureElement") {
        format!("{:?}", ObjectType::StructureElement)
    } else if content.contains("/Type /FileSpec") {
        format!("{:?}", ObjectType::FileSpecification)
    } else if content.contains("/Type /EmbeddedFile") {
        format!("{:?}", ObjectType::EmbeddedFile)
    } else if content.contains("stream") {
        format!("{:?}", ObjectType::Stream)
    } else {
        format!("{:?}", ObjectType::Dictionary)
    }
}

/// Extract stream data from object content
fn extract_stream_data(content: &str) -> Option<PdfStream> {
    if let Some(stream_start) = content.find("stream") {
        if let Some(stream_end) = content.find("endstream") {
            let stream_content = &content[stream_start + 6..stream_end];

            // Extract Length parameter
            let _length = if let Some(length_pos) = content.find("/Length ") {
                let length_str = &content[length_pos + 8..];
                let length_end = length_str.find([' ', '\n', '\r', '/']).unwrap_or(length_str.len());
                length_str[..length_end].trim().parse::<u32>().unwrap_or(stream_content.len() as u32)
            } else {
                stream_content.len() as u32
            };

            // Extract filters
            let filters = if let Some(filter_pos) = content.find("/Filter ") {
                let filter_str = &content[filter_pos + 8..];
                if filter_str.starts_with('[') {
                    // Array of filters
                    if let Some(end_bracket) = filter_str.find(']') {
                        let filter_array = &filter_str[1..end_bracket];
                        filter_array.split_whitespace()
                            .filter(|s| s.starts_with('/'))
                            .map(|s| s[1..].to_string())
                            .collect()
                    } else {
                        Vec::new()
                    }
                } else {
                    // Single filter
                    let filter_end = filter_str.find([' ', '\n', '\r', '/']).unwrap_or(filter_str.len());
                    let filter_name = &filter_str[..filter_end].trim();
                    if filter_name.starts_with('/') {
                        vec![filter_name[1..].to_string()]
                    } else {
                        vec![filter_name.to_string()]
                    }
                }
            } else {
                Vec::new()
            };

             let _decode_params = if let Some(_decode_pos) = content.find("/DecodeParms ") {
                    Some(PdfDictionary::new())
             } else {
                 None
             };

            return Some(PdfStream {
                dictionary: PdfDictionary::new(),
                raw_data: stream_content.as_bytes().to_vec(),
                decoded_data: None,
                filters: filters.into_iter().map(|_s| StreamFilter::FlateDecode {
                    predictor: None,
                    colors: None,
                    bits_per_component: None,
                    columns: None,
                }).collect(),
            });
        }
    }
    None
}

/// Extract object references from content
fn extract_object_references(content: &str) -> Vec<ObjectReference> {
    let mut references = Vec::new();
    let words: Vec<&str> = content.split_whitespace().collect();

    let mut i = 0;
    while i + 2 < words.len() {
        if words[i + 2] == "R" {
            if let (Ok(num), Ok(gen)) = (words[i].parse::<u32>(), words[i + 1].parse::<u16>()) {
                references.push(ObjectReference::new(num, gen));
            }
        }
        i += 1;
    }

    references
}

/// Extract font objects from PDF content
fn extract_fonts(mmap: &[u8], xref: &XRefData) -> PdfResult<Vec<FontInfo>> {
    let mut fonts = Vec::new();
    let content = String::from_utf8_lossy(mmap);

    for entry in &xref.entries {
        if entry.entry_type == XRefEntryType::InUse {
            let offset = entry.offset_or_index as usize;
            if offset < mmap.len() {
                let search_area = &content[offset..];

                if search_area.contains("/Type /Font") {
                    if let Some(obj_start) = search_area.find(" obj") {
                        if let Some(endobj_pos) = search_area.find("endobj") {
                            let object_content = &search_area[obj_start + 4..endobj_pos];

                            let font_name = extract_font_name(object_content);
                            let font_type = extract_font_type(object_content);
                            let encoding = extract_font_encoding(object_content);
                            let embedded = object_content.contains("/FontFile") || 
                                         object_content.contains("/FontFile2") || 
                                         object_content.contains("/FontFile3");

                            fonts.push(FontInfo {
                                object_ref: ObjectReference::new(entry.object_number, entry.generation),
                                font_type: font_type.to_string(),
                                base_font: font_name,
                                encoding,
                                embedded,
                                font_descriptor: None,
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(fonts)
}

fn extract_font_name(content: &str) -> Option<String> {
    if let Some(name_pos) = content.find("/BaseFont /") {
        let name_str = &content[name_pos + 11..];
        let name_end = name_str.find([' ', '\n', '\r', '/']).unwrap_or(name_str.len());
        Some(name_str[..name_end].trim().to_string())
    } else if let Some(name_pos) = content.find("/FontName /") {
        let name_str = &content[name_pos + 11..];
        let name_end = name_str.find([' ', '\n', '\r', '/']).unwrap_or(name_str.len());
        Some(name_str[..name_end].trim().to_string())
    } else {
        None
    }
}

fn extract_font_type(content: &str) -> String {
    if content.contains("/Subtype /Type1") {
        "Type1".to_string()
    } else if content.contains("/Subtype /TrueType") {
        "TrueType".to_string()
    } else if content.contains("/Subtype /Type0") {
        "Type0".to_string()
    } else if content.contains("/Subtype /Type3") {
        "Type3".to_string()
    } else if content.contains("/Subtype /CIDFontType0") {
        "CIDFontType0".to_string()
    } else if content.contains("/Subtype /CIDFontType2") {
        "CIDFontType2".to_string()
    } else {
        "Unknown".to_string()
    }
}

fn extract_font_encoding(content: &str) -> Option<String> {
    if let Some(enc_pos) = content.find("/Encoding /") {
        let enc_str = &content[enc_pos + 11..];
        let enc_end = enc_str.find([' ', '\n', '\r', '/']).unwrap_or(enc_str.len());
        Some(enc_str[..enc_end].trim().to_string())
    } else {
        None
    }
}



/// Extract image objects from PDF content
fn extract_images(mmap: &[u8], xref: &XRefData) -> PdfResult<Vec<ImageInfo>> {
    let mut images = Vec::new();
    let content = String::from_utf8_lossy(mmap);

    for entry in &xref.entries {
        if entry.entry_type == XRefEntryType::InUse {
            let offset = entry.offset_or_index as usize;
            if offset < mmap.len() {
                let search_area = &content[offset..];

                if search_area.contains("/Type /XObject") && search_area.contains("/Subtype /Image") {
                    if let Some(obj_start) = search_area.find(" obj") {
                        if let Some(endobj_pos) = search_area.find("endobj") {
                            let object_content = &search_area[obj_start + 4..endobj_pos];

                            let width = extract_image_dimension(object_content, "/Width");
                            let height = extract_image_dimension(object_content, "/Height");
                            let bits_per_component = extract_image_dimension(object_content, "/BitsPerComponent");
                            let color_space = extract_image_colorspace(object_content);
                            let _filter = extract_image_filter(object_content);

                            images.push(ImageInfo {
                                object_ref: ObjectReference::new(entry.object_number, entry.generation),
                                width: width.unwrap_or(0),
                                height: height.unwrap_or(0),
                                bits_per_component: bits_per_component.unwrap_or(8) as u8,
                                color_space: color_space.unwrap_or_else(|| "DeviceRGB".to_string()),
                                filters: Vec::new(),
                                has_alpha: false,
                                data_size: 0,
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(images)
}

fn extract_image_dimension(content: &str, field: &str) -> Option<u32> {
    if let Some(pos) = content.find(field) {
        let value_str = &content[pos + field.len()..];
        let value_end = value_str.find([' ', '\n', '\r', '/']).unwrap_or(value_str.len());
        value_str[..value_end].trim().parse().ok()
    } else {
        None
    }
}

fn extract_image_colorspace(content: &str) -> Option<String> {
    if let Some(cs_pos) = content.find("/ColorSpace /") {
        let cs_str = &content[cs_pos + 12..];
        let cs_end = cs_str.find([' ', '\n', '\r', '/']).unwrap_or(cs_str.len());
        Some(cs_str[..cs_end].trim().to_string())
    } else {
        None
    }
}

fn extract_image_filter(content: &str) -> Option<Vec<String>> {
    if let Some(filter_pos) = content.find("/Filter ") {
        let filter_str = &content[filter_pos + 8..];
        if filter_str.starts_with('[') {
            if let Some(end_bracket) = filter_str.find(']') {
                let filter_array = &filter_str[1..end_bracket];
                Some(filter_array.split_whitespace()
                    .filter(|s| s.starts_with('/'))
                    .map(|s| s[1..].to_string())
                    .collect())
            } else {
                None
            }
        } else {
            let filter_end = filter_str.find([' ', '\n', '\r', '/']).unwrap_or(filter_str.len());
            let filter_name = &filter_str[..filter_end].trim();
            if filter_name.starts_with('/') {
                Some(vec![filter_name[1..].to_string()])
            } else {
                Some(vec![filter_name.to_string()])
            }
        }
    } else {
        None
    }
}

fn extract_image_mask(content: &str) -> Option<ObjectReference> {
    if let Some(mask_pos) = content.find("/Mask ") {
        let mask_str = &content[mask_pos + 6..];
        let parts: Vec<&str> = mask_str.split_whitespace().take(3).collect();
        if parts.len() >= 3 && parts[2] == "R" {
            if let (Ok(num), Ok(gen)) = (parts[0].parse::<u32>(), parts[1].parse::<u16>()) {
                return Some(ObjectReference::new(num, gen));
            }
        }
    }
    None
}

fn extract_rendering_intent(content: &str) -> Option<String> {
    if let Some(intent_pos) = content.find("/Intent /") {
        let intent_str = &content[intent_pos + 9..];
        let intent_end = intent_str.find([' ', '\n', '\r', '/']).unwrap_or(intent_str.len());
        Some(intent_str[..intent_end].trim().to_string())
    } else {
        None
    }
}

/// Extract content streams from PDF
fn extract_content_streams(mmap: &[u8], xref: &XRefData) -> PdfResult<Vec<ContentStreamInfo>> {
    let mut streams: Vec<ContentStreamInfo> = Vec::new();
    let content = String::from_utf8_lossy(mmap);

    for entry in &xref.entries {
        if entry.entry_type == XRefEntryType::InUse {
            let offset = entry.offset_or_index as usize;
            if offset < mmap.len() {
                let search_area = &content[offset..];

                if search_area.contains("stream") && search_area.contains("endstream") {
                    if let Some(obj_start) = search_area.find(" obj") {
                        if let Some(endobj_pos) = search_area.find("endobj") {
                            let object_content = &search_area[obj_start + 4..endobj_pos];
                             // Extract object reference
                            let obj_header = &search_area[..obj_start];
                            let parts: Vec<&str> = obj_header.split_whitespace().collect();
                            let obj_ref = if parts.len() >= 2 {
                                let number = parts[0].parse::<u32>().unwrap_or(0);
                                let generation = parts[1].parse::<u16>().unwrap_or(0);
                                ObjectReference::new(number, generation)
                            } else {
                                ObjectReference::new(0, 0)
                            };


                            if let Some(stream_data) = extract_stream_data(object_content) {
                                streams.push(ContentStreamInfo {
                                    object_ref: ObjectReference { number: obj_ref.number, generation: obj_ref.generation },
                                    page_ref: None,
                                    length: stream_data.raw_data.len() as u64,
                                    filters: stream_data.filters,
                                    operators: HashSet::new(),
                                    resources: Vec::new(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(streams)
}

fn extract_bounding_box(content: &str) -> Option<Rectangle> {
    if let Some(bbox_pos) = content.find("/BBox [") {
        let bbox_str = &content[bbox_pos + 7..];
        if let Some(end_bracket) = bbox_str.find(']') {
            let coords_str = &bbox_str[..end_bracket];
            let coords: Vec<f64> = coords_str.split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            if coords.len() >= 4 {
                return Some(Rectangle::new(coords[0], coords[1], coords[2], coords[3]));
            }
        }
    }
    None
}

fn extract_transformation_matrix(content: &str) -> Option<TransformationMatrix> {
    if let Some(matrix_pos) = content.find("/Matrix [") {
        let matrix_str = &content[matrix_pos + 9..];
        if let Some(end_bracket) = matrix_str.find(']') {
            let values_str = &matrix_str[..end_bracket];
            let values: Vec<f64> = values_str.split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            if values.len() >= 6 {
                return Some(TransformationMatrix {
                    elements: [values[0], values[1], values[2], values[3], values[4], values[5]],
                });
            }
        }
    }
    None
}

/// Extract embedded files from PDF
fn extract_embedded_files(mmap: &[u8], xref: &XRefData) -> PdfResult<Vec<EmbeddedFileInfo>> {
    let mut embedded_files = Vec::new();
    let content = String::from_utf8_lossy(mmap);

    for entry in &xref.entries {
        if entry.entry_type == XRefEntryType::InUse {
            let offset = entry.offset_or_index as usize;
            if offset < mmap.len() {
                let search_area = &content[offset..];

                if search_area.contains("/Type /Filespec") || search_area.contains("/Type /EmbeddedFile") {
                    if let Some(obj_start) = search_area.find(" obj") {
                        if let Some(endobj_pos) = search_area.find("endobj") {
                            let object_content = &search_area[obj_start + 4..endobj_pos];

                            let filename = extract_filename(object_content);
                            let size = extract_file_size(object_content);
                            let creation_date = extract_file_creation_date(object_content);
                            let modification_date = extract_file_modification_date(object_content);
                            let checksum = extract_file_checksum(object_content);

                            embedded_files.push(EmbeddedFileInfo {
                                object_ref: ObjectReference::new(entry.object_number, entry.generation),
                                filename,
                                size,
                                mime_type: extract_mime_type(object_content),
                                creation_date,
                                modification_date,
                                checksum,
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(embedded_files)
}

fn extract_filename(content: &str) -> Option<String> {
    if let Some(f_pos) = content.find("/F (") {
        let f_str = &content[f_pos + 4..];
        if let Some(end_paren) = f_str.find(')') {
            return Some(f_str[..end_paren].to_string());
        }
    }
    None
}

fn extract_file_size(content: &str) -> Option<u64> {
    if let Some(size_pos) = content.find("/Size ") {
        let size_str = &content[size_pos + 6..];
        let size_end = size_str.find([' ', '\n', '\r', '/']).unwrap_or(size_str.len());
        size_str[..size_end].trim().parse().ok()
    } else {
        None
    }
}

fn extract_file_creation_date(content: &str) -> Option<String> {
    if let Some(date_pos) = content.find("/CreationDate (") {
        let date_str = &content[date_pos + 15..];
        if let Some(end_paren) = date_str.find(')') {
            return Some(date_str[..end_paren].to_string());
        }
    }
    None
}

fn extract_file_modification_date(content: &str) -> Option<String> {
    if let Some(date_pos) = content.find("/ModDate (") {
        let date_str = &content[date_pos + 10..];
        if let Some(end_paren) = date_str.find(')') {
            return Some(date_str[..end_paren].to_string());
        }
    }
    None
}

fn extract_file_checksum(content: &str) -> Option<String> {
    if let Some(checksum_pos) = content.find("/CheckSum <") {
        let checksum_str = &content[checksum_pos + 11..];
        if let Some(end_bracket) = checksum_str.find('>') {
            return Some(checksum_str[..end_bracket].to_string());
        }
    }
    None
}

fn extract_mime_type(content: &str) -> Option<String> {
    if let Some(mime_pos) = content.find("/Subtype /") {
        let mime_str = &content[mime_pos + 10..];
        let mime_end = mime_str.find([' ', '\n', '\r', '/']).unwrap_or(mime_str.len());
        Some(mime_str[..mime_end].trim().to_string())
    } else {
        None
    }
}

fn extract_file_description(content: &str) -> Option<String> {
    if let Some(desc_pos) = content.find("/Desc (") {
        let desc_str = &content[desc_pos + 7..];
        if let Some(end_paren) = desc_str.find(')') {
            return Some(desc_str[..end_paren].to_string());
        }
    }
    None
}

fn extract_file_data_reference(content: &str) -> Option<ObjectReference> {
    if let Some(ef_pos) = content.find("/EF ") {
        let ef_str = &content[ef_pos + 4..];
        let parts: Vec<&str> = ef_str.split_whitespace().take(3).collect();
        if parts.len() >= 3 && parts[2] == "R" {
            if let (Ok(num), Ok(gen)) = (parts[0].parse::<u32>(), parts[1].parse::<u16>()) {
                return Some(ObjectReference::new(num, gen));
            }
        }
    }
    None
}

fn detect_javascript_patterns(content: &str) -> Vec<String> {
    let mut patterns = Vec::new();

    if content.contains("eval(") {
        patterns.push("eval() function".to_string());
    }
    if content.contains("unescape(") {
        patterns.push("unescape() function".to_string());
    }
    if content.contains("String.fromCharCode(") {
        patterns.push("String.fromCharCode() function".to_string());
    }
    if content.chars().filter(|&c| c == '\\').count() > 10 {
        patterns.push("Excessive backslashes".to_string());
    }

    patterns
}

/// Extract JavaScript objects from PDF
fn extract_javascript_objects(mmap: &[u8], xref: &XRefData) -> PdfResult<Vec<JavaScriptInfo>> {
    let mut js_objects = Vec::new();
    let content = String::from_utf8_lossy(mmap);

    for entry in &xref.entries {
        if entry.entry_type == XRefEntryType::InUse {
            let offset = entry.offset_or_index as usize;
            if offset < mmap.len() {
                let search_area = &content[offset..];

                if search_area.contains("/S /JavaScript") || search_area.contains("/JS ") {
                    if let Some(obj_start) = search_area.find(" obj") {
                        if let Some(endobj_pos) = search_area.find("endobj") {
                             let obj_header = &search_area[..obj_start];
                            let parts: Vec<&str> = obj_header.split_whitespace().collect();

                            let obj_num = if parts.len() >= 2 {
                                parts[0].parse::<u32>().unwrap_or(0)
                            } else {
                                0
                            };
                            let object_content = &search_area[obj_start + 4..endobj_pos];

                            let js_code = extract_javascript_code(object_content);
                            let trigger = extract_javascript_trigger(object_content);

                            js_objects.push(JavaScriptInfo {
                                object_ref: ObjectReference { number: obj_num, generation: 0 },
                                code_snippet: js_code.unwrap_or_else(|| "// JavaScript code not extractable".to_string()),
                                code_size: object_content.len() as u64,
                                suspicious_patterns: detect_javascript_patterns(object_content),
                                trigger: trigger.map(|t| format!("{:?}", t)),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(js_objects)
}

fn extract_javascript_code(content: &str) -> Option<String> {
    if let Some(js_pos) = content.find("/JS (") {
        let js_str = &content[js_pos + 5..];
        if let Some(end_paren) = js_str.find(')') {
            return Some(js_str[..end_paren].to_string());
        }
    }
    None
}

fn extract_javascript_trigger(content: &str) -> Option<ScriptTrigger> {
    if content.contains("/PageOpen") {
        Some(ScriptTrigger::Focus)
    } else if content.contains("/PageClose") {
        Some(ScriptTrigger::Blur)
    } else if content.contains("/Focus") {
        Some(ScriptTrigger::Focus)
    } else if content.contains("/Blur") {
        Some(ScriptTrigger::Blur)
    } else if content.contains("/DocumentOpen") {
        Some(ScriptTrigger::Focus)
    } else {
        None
    }
}

fn extract_associated_form_field(content: &str) -> Option<String> {
    if let Some(field_pos) = content.find("/T (") {
        let field_str = &content[field_pos + 4..];
        if let Some(end_paren) = field_str.find(')') {
            return Some(field_str[..end_paren].to_string());
        }
    }
    None
}

fn determine_action_type(content: &str) -> ActionType {
    if content.contains("/S /JavaScript") {
        ActionType::JavaScript
    } else if content.contains("/S /GoTo") {
        ActionType::GoTo
    } else if content.contains("/S /URI") {
        ActionType::URI
    } else if content.contains("/S /Launch") {
        ActionType::Launch
    } else {
        ActionType::JavaScript
    }
}

fn detect_javascript_obfuscation(content: &str) -> bool {
    content.contains("eval(") || 
    content.contains("unescape(") || 
    content.contains("String.fromCharCode(") ||
    content.chars().filter(|&c| c == '\\').count() > 10
}

fn extract_external_references(content: &str) -> Vec<String> {
    let mut refs = Vec::new();

    // Look for URL patterns
    if let Some(url_pos) = content.find("http") {
        let url_str = &content[url_pos..];
        let url_end = url_str.find([' ', ')', '"', '\'']).unwrap_or(url_str.len());
        refs.push(url_str[..url_end].to_string());
    }

    refs
}

/// Detect suspicious objects in PDF
fn detect_suspicious_objects(mmap: &[u8], xref: &XRefData) -> PdfResult<Vec<SuspiciousObjectInfo>> {
    let mut suspicious = Vec::new();
    let content = String::from_utf8_lossy(mmap);

    for entry in &xref.entries {
        if entry.entry_type == XRefEntryType::InUse {
            let offset = entry.offset_or_index as usize;
            if offset < mmap.len() {
                let search_area = &content[offset..];

                if let Some(obj_start) = search_area.find(" obj") {
                    if let Some(endobj_pos) = search_area.find("endobj") {
                        let object_content = &search_area[obj_start + 4..endobj_pos];

                        let mut suspicion_reasons = Vec::new();
                        let mut risk_level = RiskLevel::Low;

                        // Check for JavaScript
                        if object_content.contains("/S /JavaScript") {
                            suspicion_reasons.push("Contains JavaScript code".to_string());
                            risk_level = RiskLevel::Medium;
                        }

                        // Check for external launches
                        if object_content.contains("/S /Launch") {
                            suspicion_reasons.push("Contains launch actions".to_string());
                            risk_level = RiskLevel::High;
                        }

                        // Check for embedded files
                        if object_content.contains("/EmbeddedFile") {
                            suspicion_reasons.push("Contains embedded files".to_string());
                            risk_level = RiskLevel::Medium;
                        }

                        // Check for form fields
                        if object_content.contains("/FT /") {
                            suspicion_reasons.push("Contains form fields".to_string());
                            risk_level = RiskLevel::Low;
                        }

                        // Check for suspicious filters
                        if object_content.contains("/ASCIIHexDecode") || object_content.contains("/ASCII85Decode") {
                            suspicion_reasons.push("Uses encoding filters".to_string());
                            risk_level = RiskLevel::Medium;
                        }

                        // Check for obfuscated content
                        let special_char_count = object_content.chars().filter(|&c| !c.is_ascii_alphanumeric() && !c.is_whitespace()).count();
                        if special_char_count > object_content.len() / 4 {
                            suspicion_reasons.push("High concentration of special characters".to_string());
                            risk_level = RiskLevel::Medium;
                        }

                        if !suspicion_reasons.is_empty() {
                            suspicious.push(SuspiciousObjectInfo {
                                object_ref: ObjectReference::new(entry.object_number, entry.generation),
                                suspicion_reasons,
                                risk_level,
                                recommended_action: RecommendedAction::Investigate,
                                context: "Automated content analysis".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(suspicious)
}

/// Extract streams from PDF
fn extract_streams(mmap: &[u8], xref: &XRefData) -> PdfResult<Vec<PdfStream>> {
    let mut streams: Vec<PdfStream> = Vec::new();
    let content = String::from_utf8_lossy(mmap);

    for entry in &xref.entries {
        if entry.entry_type == XRefEntryType::InUse {
            let offset = entry.offset_or_index as usize;
            if offset < mmap.len() {
                let search_area = &content[offset..];

                if search_area.contains("stream") && search_area.contains("endstream") {
                    if let Some(obj_start) = search_area.find(" obj") {
                        if let Some(endobj_pos) = search_area.find("endobj") {
                            let object_content = &search_area[obj_start + 4..endobj_pos];

                            if let Some(stream_data) = extract_stream_data(object_content) {
                                streams.push(stream_data);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(streams)
}