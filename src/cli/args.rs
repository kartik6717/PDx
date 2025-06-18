
use clap::{Arg, ArgMatches, Command};

/// Build the complete CLI command structure
pub fn build_cli() -> Command {
    Command::new("pdf-forensic")
        .version(env!("CARGO_PKG_VERSION"))
        .author("PDF Forensic Tool Team")
        .about("PDF Forensic Clone Tool - Extract and inject PDF metadata for forensic analysis")
        .long_about("A comprehensive tool for PDF forensic metadata extraction and injection. \
                     Designed for forensic analysts to clone invisible metadata between PDF documents \
                     while preserving byte-level accuracy.")
        .arg(Arg::new("config")
            .long("config")
            .short('c')
            .value_name("FILE")
            .help("Custom configuration file path")
            .global(true))
        .arg(Arg::new("verbose")
            .long("verbose")
            .short('v')
            .action(clap::ArgAction::SetTrue)
            .help("Enable verbose output")
            .global(true))
        .arg(Arg::new("quiet")
            .long("quiet")
            .short('q')
            .action(clap::ArgAction::SetTrue)
            .help("Suppress all output except errors")
            .global(true))
        .subcommand(
            Command::new("extract")
                .about("Extract forensic metadata from PDF")
                .long_about("Extract complete forensic metadata fingerprint from a PDF document. \
                            This includes invisible metadata, PDF ID arrays, timestamps, \
                            encryption data, and structural information.")
                .arg(Arg::new("input")
                    .help("Input PDF file to extract metadata from")
                    .required(true)
                    .value_name("PDF_FILE"))
                .arg(Arg::new("output")
                    .short('o')
                    .long("output")
                    .help("Output JSON file for extracted metadata")
                    .required(true)
                    .value_name("JSON_FILE"))
                .arg(Arg::new("detect-watermarks")
                    .long("detect-watermarks")
                    .action(clap::ArgAction::SetTrue)
                    .help("Detect and catalog watermarks in the PDF"))
                .arg(Arg::new("deep-analysis")
                    .long("deep-analysis")
                    .action(clap::ArgAction::SetTrue)
                    .help("Perform deep structural analysis (slower but more thorough)"))
                .arg(Arg::new("include-content")
                    .long("include-content")
                    .action(clap::ArgAction::SetTrue)
                    .help("Include content analysis in extraction (not recommended for large files)"))
                .arg(Arg::new("memory-limit")
                    .long("memory-limit")
                    .value_name("MB")
                    .help("Memory limit in megabytes (default: 512)")
                    .value_parser(clap::value_parser!(u64)))
                .arg(Arg::new("timeout")
                    .long("timeout")
                    .value_name("SECONDS")
                    .help("Processing timeout in seconds (default: 300)")
                    .value_parser(clap::value_parser!(u64)))
        )
        .subcommand(
            Command::new("inject")
                .about("Inject metadata into target PDF")
                .long_about("Inject forensic metadata from a fingerprint file into a target PDF. \
                            This operation preserves all visible content while replacing invisible \
                            metadata to create forensically identical documents.")
                .arg(Arg::new("input")
                    .help("Target PDF file to inject metadata into")
                    .required(true)
                    .value_name("PDF_FILE"))
                .arg(Arg::new("fingerprint")
                    .long("fingerprint")
                    .short('f')
                    .help("Source fingerprint JSON file")
                    .required(true)
                    .value_name("JSON_FILE"))
                .arg(Arg::new("output")
                    .short('o')
                    .long("output")
                    .help("Output PDF file")
                    .required(true)
                    .value_name("PDF_FILE"))
                .arg(Arg::new("strip-watermarks")
                    .long("strip-watermarks")
                    .action(clap::ArgAction::SetTrue)
                    .help("Remove third-party watermarks during injection"))
                .arg(Arg::new("preserve-encryption")
                    .long("preserve-encryption")
                    .action(clap::ArgAction::SetTrue)
                    .help("Preserve target's encryption settings instead of source"))
                .arg(Arg::new("force")
                    .long("force")
                    .action(clap::ArgAction::SetTrue)
                    .help("Force injection even if compatibility issues are detected"))
                .arg(Arg::new("create-backup")
                    .long("create-backup")
                    .action(clap::ArgAction::SetTrue)
                    .help("Create backup of target file before injection"))
                .arg(Arg::new("validate-after")
                    .long("validate-after")
                    .action(clap::ArgAction::SetTrue)
                    .help("Validate output file after injection"))
        )
        .subcommand(
            Command::new("validate")
                .about("Validate PDF structure and integrity")
                .long_about("Perform comprehensive validation of PDF structure, forensic integrity, \
                            and detect potential security issues or malformation.")
                .arg(Arg::new("input")
                    .help("PDF file to validate")
                    .required(true)
                    .value_name("PDF_FILE"))
                .arg(Arg::new("strict")
                    .long("strict")
                    .action(clap::ArgAction::SetTrue)
                    .help("Enable strict validation mode"))
                .arg(Arg::new("check-signatures")
                    .long("check-signatures")
                    .action(clap::ArgAction::SetTrue)
                    .help("Validate digital signatures"))
                .arg(Arg::new("security-scan")
                    .long("security-scan")
                    .action(clap::ArgAction::SetTrue)
                    .help("Perform security vulnerability scan"))
                .arg(Arg::new("output-report")
                    .long("output-report")
                    .short('r')
                    .value_name("FILE")
                    .help("Save detailed validation report to file"))
        )
        .subcommand(
            Command::new("compare")
                .about("Compare forensic signatures of two PDFs")
                .long_about("Compare the forensic metadata signatures of two PDF documents \
                            to determine if they are forensically identical.")
                .arg(Arg::new("pdf1")
                    .help("First PDF file")
                    .required(true)
                    .value_name("PDF_FILE1"))
                .arg(Arg::new("pdf2")
                    .help("Second PDF file")
                    .required(true)
                    .value_name("PDF_FILE2"))
                .arg(Arg::new("detailed")
                    .long("detailed")
                    .action(clap::ArgAction::SetTrue)
                    .help("Show detailed comparison results"))
                .arg(Arg::new("ignore-timestamps")
                    .long("ignore-timestamps")
                    .action(clap::ArgAction::SetTrue)
                    .help("Ignore timestamp differences in comparison"))
                .arg(Arg::new("output-diff")
                    .long("output-diff")
                    .short('d')
                    .value_name("FILE")
                    .help("Save comparison differences to file"))
        )
        .subcommand(
            Command::new("batch")
                .about("Process multiple PDFs in batch mode")
                .long_about("Process multiple PDF files in batch mode for extraction or injection operations.")
                .arg(Arg::new("operation")
                    .help("Operation to perform: extract or inject")
                    .required(true)
                    .value_parser(["extract", "inject"]))
                .arg(Arg::new("input-dir")
                    .long("input-dir")
                    .short('i')
                    .help("Input directory containing PDF files")
                    .required(true)
                    .value_name("DIRECTORY"))
                .arg(Arg::new("output-dir")
                    .long("output-dir")
                    .short('o')
                    .help("Output directory for processed files")
                    .required(true)
                    .value_name("DIRECTORY"))
                .arg(Arg::new("fingerprint-dir")
                    .long("fingerprint-dir")
                    .short('f')
                    .help("Directory containing fingerprint files (for inject operation)")
                    .value_name("DIRECTORY"))
                .arg(Arg::new("parallel")
                    .long("parallel")
                    .short('p')
                    .value_name("THREADS")
                    .help("Number of parallel processing threads")
                    .value_parser(clap::value_parser!(u32)))
                .arg(Arg::new("continue-on-error")
                    .long("continue-on-error")
                    .action(clap::ArgAction::SetTrue)
                    .help("Continue processing other files if one fails"))
        )
}

/// Parse extraction command arguments
pub fn parse_extract_args(matches: &ArgMatches) -> ExtractArgs {
    ExtractArgs {
        input: matches.get_one::<String>("input").unwrap().clone(),
        output: matches.get_one::<String>("output").unwrap().clone(),
        detect_watermarks: matches.get_flag("detect-watermarks"),
        deep_analysis: matches.get_flag("deep-analysis"),
        include_content: matches.get_flag("include-content"),
        verbose: matches.get_flag("verbose"),
        memory_limit: matches.get_one::<u64>("memory-limit").copied(),
        timeout: matches.get_one::<u64>("timeout").copied(),
    }
}

/// Parse injection command arguments
pub fn parse_inject_args(matches: &ArgMatches) -> InjectArgs {
    InjectArgs {
        input: matches.get_one::<String>("input").unwrap().clone(),
        fingerprint: matches.get_one::<String>("fingerprint").unwrap().clone(),
        output: matches.get_one::<String>("output").unwrap().clone(),
        strip_watermarks: matches.get_flag("strip-watermarks"),
        preserve_encryption: matches.get_flag("preserve-encryption"),
        force: matches.get_flag("force"),
        create_backup: matches.get_flag("create-backup"),
        validate_after: matches.get_flag("validate-after"),
        verbose: matches.get_flag("verbose"),
    }
}

/// Parse validation command arguments
pub fn parse_validate_args(matches: &ArgMatches) -> ValidateArgs {
    ValidateArgs {
        input: matches.get_one::<String>("input").unwrap().clone(),
        strict: matches.get_flag("strict"),
        check_signatures: matches.get_flag("check-signatures"),
        security_scan: matches.get_flag("security-scan"),
        output_report: matches.get_one::<String>("output-report").cloned(),
        verbose: matches.get_flag("verbose"),
    }
}

/// Parse comparison command arguments
pub fn parse_compare_args(matches: &ArgMatches) -> CompareArgs {
    CompareArgs {
        pdf1: matches.get_one::<String>("pdf1").unwrap().clone(),
        pdf2: matches.get_one::<String>("pdf2").unwrap().clone(),
        detailed: matches.get_flag("detailed"),
        ignore_timestamps: matches.get_flag("ignore-timestamps"),
        output_diff: matches.get_one::<String>("output-diff").cloned(),
        verbose: matches.get_flag("verbose"),
    }
}

/// Extract command arguments
#[derive(Debug, Clone)]
pub struct ExtractArgs {
    pub input: String,
    pub output: String,
    pub detect_watermarks: bool,
    pub deep_analysis: bool,
    pub include_content: bool,
    pub verbose: bool,
    pub memory_limit: Option<u64>,
    pub timeout: Option<u64>,
}

/// Inject command arguments
#[derive(Debug, Clone)]
pub struct InjectArgs {
    pub input: String,
    pub fingerprint: String,
    pub output: String,
    pub strip_watermarks: bool,
    pub preserve_encryption: bool,
    pub force: bool,
    pub create_backup: bool,
    pub validate_after: bool,
    pub verbose: bool,
}

/// Validate command arguments
#[derive(Debug, Clone)]
pub struct ValidateArgs {
    pub input: String,
    pub strict: bool,
    pub check_signatures: bool,
    pub security_scan: bool,
    pub output_report: Option<String>,
    pub verbose: bool,
}

/// Compare command arguments
#[derive(Debug, Clone)]
pub struct CompareArgs {
    pub pdf1: String,
    pub pdf2: String,
    pub detailed: bool,
    pub ignore_timestamps: bool,
    pub output_diff: Option<String>,
    pub verbose: bool,
}