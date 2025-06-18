use std::process;
use types::*;

mod types;
mod cli;
mod config;
mod extractor;
mod injector;
mod io;
mod logger;
mod validator;

fn main() {
    if let Err(e) = logger::init_logger() {
        eprintln!("Logger initialization failed: {}", e);
        process::exit(1);
    }
    
    let cli = cli::args::build_cli();
    let matches = cli.get_matches();
    
    let result = match matches.subcommand() {
        Some(("extract", sub_matches)) => {
            let args = cli::args::parse_extract_args(sub_matches);
            execute_extract(args)
        }
        Some(("inject", sub_matches)) => {
            let args = cli::args::parse_inject_args(sub_matches);
            execute_inject(args)
        }
        Some(("validate", sub_matches)) => {
            let input = sub_matches.get_one::<String>("input").unwrap();
            execute_validate(input)
        }
        Some(("compare", sub_matches)) => {
            let pdf1 = sub_matches.get_one::<String>("pdf1").unwrap();
            let pdf2 = sub_matches.get_one::<String>("pdf2").unwrap();
            execute_compare(pdf1, pdf2)
        }
        _ => {
            eprintln!("No valid command provided. Use --help for usage information.");
            process::exit(1);
        }
    };
    
    if let Err(e) = result {
        cli::interface::display_error(&e);
        process::exit(1);
    }
}

fn execute_extract(args: cli::args::ExtractArgs) -> PdfResult<()> {
    log::info!("Starting extraction from: {}", args.input);
    
    // Validate input file exists and is readable
    if !std::path::Path::new(&args.input).exists() {
        return Err(PdfError::NotFound {
            resource_type: "PDF file".to_string(),
            identifier: args.input.clone(),
        });
    }
    
    // Check file size
    let metadata = std::fs::metadata(&args.input).map_err(|e| PdfError::FileSystem {
        path: args.input.clone(),
        operation: "metadata".to_string(),
        error_kind: FileErrorKind::ReadOnly,
    })?;
    
    let file_size = metadata.len();
    log::info!("Processing file of size: {} bytes", file_size);
    
    let config = ExtractionConfig {
        extract_xmp: true,
        extract_forms: true,
        extract_annotations: true,
        detect_watermarks: args.detect_watermarks,
        detect_third_party: true,
        extract_object_streams: true,
        analyze_incremental_updates: true,
        extract_linearization: true,
        security_analysis: true,
        extract_embedded_files: true,
        analyze_javascript: true,
        validate_structure: true,
        deep_content_analysis: args.include_content,
        forensic_analysis: true,
        memory_limit: args.memory_limit.map(|mb| mb * 1024 * 1024),
        timeout: args.timeout,
        extract_metadata: true,
        extract_structure: true,
        extract_timestamps: true,
        extract_forensic_markers: true,
        extract_encryption_info: true,
        deep_analysis: args.deep_analysis,
        memory_limit_mb: args.memory_limit.unwrap_or(512),
        timeout_seconds: args.timeout.unwrap_or(300),
    };
    
    let start_time = std::time::SystemTime::now();
    let pdf_data = match extractor::extract_pdf_forensic_data(&args.input, &config) {
        Ok(data) => data,
        Err(e) => {
            log::error!("Extraction failed: {}", e);
            return Err(e);
        }
    };
    
    let processing_time = start_time.elapsed().unwrap_or_default();
    log::info!("Processing time: {:?}", processing_time);
    
    // Log detailed extraction statistics
    log::info!("Extraction completed - Objects: {}, Size: {} bytes, Duration: {}ms", 
               pdf_data.structure.object_count,
               file_size,
               processing_time.as_millis());
    
    // Validate extracted data integrity
    if pdf_data.structure.object_count == 0 {
        return Err(PdfError::Structure {
            message: "No PDF objects found during extraction".to_string(),
            object_ref: None,
        });
    }
    
    if pdf_data.version.major == 0 && pdf_data.version.minor == 0 {
        log::warn!("PDF version not detected during extraction");
    }
    
    if pdf_data.metadata.title.is_none() && pdf_data.metadata.author.is_none() {
        log::info!("No metadata found in PDF");
    }
    
    let json_data = io::json::PdfForensicData::from(&pdf_data);
    io::json::save_forensic_data(&json_data, &args.output)?;
    
    if args.verbose {
        cli::interface::display_extraction_summary(&pdf_data);
    }
    
    // Verify the output file was created successfully
    if !std::path::Path::new(&args.output).exists() {
        return Err(PdfError::Io {
            message: "Output file was not created".to_string(),
            code: 1,
        });
    }
    
    // Validate output file size is reasonable
    let output_metadata = std::fs::metadata(&args.output).map_err(|e| PdfError::Io {
        message: format!("Failed to read output file metadata: {}", e),
        code: 2,
    })?;
    
    if output_metadata.len() == 0 {
        return Err(PdfError::Io {
            message: "Output file is empty".to_string(),
            code: 3,
        });
    }
    
    log::info!("Extraction completed successfully: {}", args.output);
    Ok(())
}

fn execute_inject(args: cli::args::InjectArgs) -> PdfResult<()> {
    log::info!("Starting injection: {} -> {}", args.input, args.output);
    
    // Validate input files exist
    if !std::path::Path::new(&args.input).exists() {
        return Err(PdfError::NotFound {
            resource_type: "Target PDF file".to_string(),
            identifier: args.input.clone(),
        });
    }
    
    if !std::path::Path::new(&args.fingerprint).exists() {
        return Err(PdfError::NotFound {
            resource_type: "Fingerprint JSON file".to_string(),
            identifier: args.fingerprint.clone(),
        });
    }
    
    // Create backup if requested
    if args.create_backup {
        let backup_path = format!("{}.backup", args.input);
        std::fs::copy(&args.input, &backup_path).map_err(|e| PdfError::FileSystem {
            path: backup_path,
            operation: "backup".to_string(),
            error_kind: FileErrorKind::PermissionDenied,
        })?;
        log::info!("Backup created: {}.backup", args.input);
    }
    
    // Load forensic data from fingerprint file
    let json_forensic_data = io::json::load_forensic_data(&args.fingerprint)?;
    let forensic_data: crate::types::PdfForensicData = json_forensic_data.into();
    
    // Perform injection
    let start_time = std::time::SystemTime::now();
    injector::inject_forensic_data(&args.input, &forensic_data, &args.output, args.strip_watermarks)?;
    let processing_time = start_time.elapsed().unwrap_or_default();
    
    log::info!("Injection completed in {:?}", processing_time);
    
    // Validate after injection if requested
    if args.validate_after {
        log::info!("Validating injected PDF...");
        let validation_result = validator::validate_pdf_file(&args.output)?;
        
        if !validation_result.is_valid {
            log::warn!("Validation found issues in injected PDF");
            if args.verbose {
                cli::interface::display_validation_result(&validation_result);
            }
        } else {
            log::info!("Validation passed - injected PDF is valid");
        }
    }
    
    log::info!("Injection completed successfully: {}", args.output);
    Ok(())
}

fn execute_validate(input: &str) -> PdfResult<()> {
    log::info!("Starting validation: {}", input);
    
    if !std::path::Path::new(input).exists() {
        return Err(PdfError::NotFound {
            resource_type: "PDF file".to_string(),
            identifier: input.to_string(),
        });
    }
    
    let start_time = std::time::SystemTime::now();
    let validation_result = validator::validate_pdf_file(input)?;
    let processing_time = start_time.elapsed().unwrap_or_default();
    
    log::info!("Validation completed in {:?}", processing_time);
    
    cli::interface::display_validation_result(&validation_result);
    
    // Log validation results
    logger::log_validation_result(input, &validation_result);
    
    if !validation_result.is_valid {
        log::warn!("PDF validation failed with {} errors", validation_result.errors.len());
        return Err(PdfError::Validation {
            message: "PDF validation failed".to_string(),
            severity: ValidationSeverity::Critical,
        });
    }
    
    log::info!("PDF validation passed");
    Ok(())
}

fn execute_compare(pdf1: &str, pdf2: &str) -> PdfResult<()> {
    log::info!("Starting comparison: {} vs {}", pdf1, pdf2);
    
    // Validate both files exist
    if !std::path::Path::new(pdf1).exists() {
        return Err(PdfError::NotFound {
            resource_type: "PDF file".to_string(),
            identifier: pdf1.to_string(),
        });
    }
    
    if !std::path::Path::new(pdf2).exists() {
        return Err(PdfError::NotFound {
            resource_type: "PDF file".to_string(),
            identifier: pdf2.to_string(),
        });
    }
    
    let config = ExtractionConfig::default();
    
    let start_time = std::time::SystemTime::now();
    
    // Extract forensic data from both PDFs
    let data1 = extractor::extract_pdf_forensic_data(pdf1, &config)?;
    let data2 = extractor::extract_pdf_forensic_data(pdf2, &config)?;
    
    // Compare the forensic data
    let json_data1 = io::json::PdfForensicData::from(&data1);
    let json_data2 = io::json::PdfForensicData::from(&data2);
    let comparison_result = io::json::compare_forensic_data(&json_data1, &json_data2);
    
    let processing_time = start_time.elapsed().unwrap_or_default();
    log::info!("Comparison completed in {:?}", processing_time);
    
    cli::interface::display_comparison_result(&comparison_result);
    
    if !comparison_result.forensically_identical {
        log::info!("PDFs are forensically different");
        return Err(PdfError::Validation {
            message: "PDFs are not forensically identical".to_string(),
            severity: ValidationSeverity::Info,
        });
    }
    
    log::info!("PDFs are forensically identical");
    Ok(())
}