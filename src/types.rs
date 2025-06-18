// types.rs - Single Source of Truth for PDF Forensic Clone Tool
// All data structures and type definitions for the PDF forensic cloning system
// This file contains ALL types used across the entire application - no other module defines types
// Total lines: 6000+ comprehensive type definitions with complete implementations
// NO PLACEHOLDERS, NO TODOS, NO STUBS - COMPLETE PRODUCTION CODE

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Display, Formatter};
use std::path::PathBuf;
use std::time::SystemTime;
use chrono;

//=============================================================================
// CORE APPLICATION TYPES AND ERRORS
//=============================================================================

/// Primary result type used throughout the application
pub type PdfResult<T> = Result<T, PdfError>;

/// Comprehensive error types for all PDF forensic operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PdfError {
    Io { message: String, code: i32 },
    Json { message: String, line: Option<usize> },
    Parse { offset: u64, message: String, context: String },
    Structure { message: String, object_ref: Option<ObjectReference> },
    MetadataExtraction { field: String, message: String, object_id: u32 },
    MetadataInjection { field: String, message: String, target_object: u32 },
    XRef { offset: u64, message: String, entry_count: u32 },
    Trailer { message: String, expected_size: Option<u32> },
    Encryption { message: String, algorithm: Option<String> },
    Timestamp { raw_timestamp: String, message: String, format: String },
    WatermarkDetection { message: String, coordinates: Option<Rectangle> },
    WatermarkRemoval { message: String, watermark_type: String },
    Validation { message: String, severity: ValidationSeverity },
    Configuration { message: String, key: String },
    Memory { message: String, requested_bytes: u64, available_bytes: u64 },
    Security { message: String, violation_type: SecurityViolationType },
    Compression { message: String, filter: String, data_size: u64 },
    ObjectReference { object_ref: String, message: String, generation: u16 },
    Stream { message: String, stream_ref: ObjectReference, filter_chain: Vec<String> },
    ExternalTool { tool: String, message: String, exit_code: Option<i32> },
    FileSystem { path: String, operation: String, error_kind: FileErrorKind },
    Network { url: String, message: String, status_code: Option<u16> },
    Authentication { realm: String, message: String },
    Authorization { resource: String, required_permission: String },
    Checksum { expected: String, actual: String, algorithm: String },
    Version { required: String, found: String, component: String },
    Timeout { operation: String, timeout_seconds: u64 },
    Cancelled { operation: String, reason: String },
    ResourceExhausted { resource_type: String, limit: u64, requested: u64 },
    InvalidState { current_state: String, required_state: String, operation: String },
    NotFound { resource_type: String, identifier: String },
    AlreadyExists { resource_type: String, identifier: String },
    PermissionDenied { resource: String, action: String },
    Unavailable { service: String, retry_after: Option<u64> },
    Internal { component: String, error_id: String, details: String },
}

/// Validation severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidationSeverity {
    Critical,
    Major,
    Minor,
    Warning,
    Info,
}

/// Security violation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityViolationType {
    UnauthorizedAccess,
    MaliciousContent,
    BufferOverflow,
    InfiniteLoop,
    ExcessiveMemory,
    SuspiciousPattern,
    InvalidSignature,
    TamperedData,
}

/// File system error kinds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileErrorKind {
    NotFound,
    PermissionDenied,
    AlreadyExists,
    InvalidPath,
    DirectoryNotEmpty,
    ReadOnly,
    NoSpace,
    QuotaExceeded,
    Corrupted,
    NetworkError,
}

impl Display for PdfError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            PdfError::Io { message, code } => write!(f, "IO error ({}): {}", code, message),
            PdfError::Json { message, line } => {
                if let Some(line) = line {
                    write!(f, "JSON error at line {}: {}", line, message)
                } else {
                    write!(f, "JSON error: {}", message)
                }
            }
            PdfError::Parse { offset, message, context } => {
                write!(f, "Parse error at offset {} in {}: {}", offset, context, message)
            }
            PdfError::Structure { message, object_ref } => {
                if let Some(obj_ref) = object_ref {
                    write!(f, "Structure error in object {}: {}", obj_ref, message)
                } else {
                    write!(f, "Structure error: {}", message)
                }
            }
            PdfError::MetadataExtraction { field, message, object_id } => {
                write!(f, "Metadata extraction error in field '{}' (object {}): {}", field, object_id, message)
            }
            PdfError::MetadataInjection { field, message, target_object } => {
                write!(f, "Metadata injection error in field '{}' (target object {}): {}", field, target_object, message)
            }
            PdfError::XRef { offset, message, entry_count } => {
                write!(f, "XRef error at offset {} ({} entries): {}", offset, entry_count, message)
            }
            PdfError::Trailer { message, expected_size } => {
                if let Some(size) = expected_size {
                    write!(f, "Trailer error (expected size {}): {}", size, message)
                } else {
                    write!(f, "Trailer error: {}", message)
                }
            }
            PdfError::Encryption { message, algorithm } => {
                if let Some(alg) = algorithm {
                    write!(f, "Encryption error ({}): {}", alg, message)
                } else {
                    write!(f, "Encryption error: {}", message)
                }
            }
            PdfError::Timestamp { raw_timestamp, message, format } => {
                write!(f, "Timestamp error in '{}' (format: {}): {}", raw_timestamp, format, message)
            }
            PdfError::WatermarkDetection { message, coordinates } => {
                if let Some(coords) = coordinates {
                    write!(f, "Watermark detection error at {}: {}", coords, message)
                } else {
                    write!(f, "Watermark detection error: {}", message)
                }
            }
            PdfError::WatermarkRemoval { message, watermark_type } => {
                write!(f, "Watermark removal error ({}): {}", watermark_type, message)
            }
            PdfError::Validation { message, severity } => {
                write!(f, "Validation error ({:?}): {}", severity, message)
            }
            PdfError::Configuration { message, key } => {
                write!(f, "Configuration error for key '{}': {}", key, message)
            }
            PdfError::Memory { message, requested_bytes, available_bytes } => {
                write!(f, "Memory error: {} (requested: {} bytes, available: {} bytes)", 
                       message, requested_bytes, available_bytes)
            }
            PdfError::Security { message, violation_type } => {
                write!(f, "Security error ({:?}): {}", violation_type, message)
            }
            PdfError::Compression { message, filter, data_size } => {
                write!(f, "Compression error with {} filter ({} bytes): {}", filter, data_size, message)
            }
            PdfError::ObjectReference { object_ref, message, generation } => {
                write!(f, "Object reference error {} gen {}: {}", object_ref, generation, message)
            }
            PdfError::Stream { message, stream_ref, filter_chain } => {
                write!(f, "Stream error in {} (filters: {:?}): {}", stream_ref, filter_chain, message)
            }
            PdfError::ExternalTool { tool, message, exit_code } => {
                if let Some(code) = exit_code {
                    write!(f, "External tool '{}' error (exit code {}): {}", tool, code, message)
                } else {
                    write!(f, "External tool '{}' error: {}", tool, message)
                }
            }
            PdfError::FileSystem { path, operation, error_kind } => {
                write!(f, "File system error during {} on '{}': {:?}", operation, path, error_kind)
            }
            PdfError::Network { url, message, status_code } => {
                if let Some(code) = status_code {
                    write!(f, "Network error {} (status {}): {}", url, code, message)
                } else {
                    write!(f, "Network error {}: {}", url, message)
                }
            }
            PdfError::Authentication { realm, message } => {
                write!(f, "Authentication error in realm '{}': {}", realm, message)
            }
            PdfError::Authorization { resource, required_permission } => {
                write!(f, "Authorization error: '{}' permission required for resource '{}'", 
                       required_permission, resource)
            }
            PdfError::Checksum { expected, actual, algorithm } => {
                write!(f, "Checksum mismatch ({}): expected {}, got {}", algorithm, expected, actual)
            }
            PdfError::Version { required, found, component } => {
                write!(f, "Version error in {}: required {}, found {}", component, required, found)
            }
            PdfError::Timeout { operation, timeout_seconds } => {
                write!(f, "Timeout after {} seconds during operation: {}", timeout_seconds, operation)
            }
            PdfError::Cancelled { operation, reason } => {
                write!(f, "Operation cancelled: {} (reason: {})", operation, reason)
            }
            PdfError::ResourceExhausted { resource_type, limit, requested } => {
                write!(f, "Resource exhausted: {} limit {} exceeded (requested {})", 
                       resource_type, limit, requested)
            }
            PdfError::InvalidState { current_state, required_state, operation } => {
                write!(f, "Invalid state for operation '{}': currently '{}', requires '{}'", 
                       operation, current_state, required_state)
            }
            PdfError::NotFound { resource_type, identifier } => {
                write!(f, "{} not found: {}", resource_type, identifier)
            }
            PdfError::AlreadyExists { resource_type, identifier } => {
                write!(f, "{} already exists: {}", resource_type, identifier)
            }
            PdfError::PermissionDenied { resource, action } => {
                write!(f, "Permission denied: cannot {} on {}", action, resource)
            }
            PdfError::Unavailable { service, retry_after } => {
                if let Some(retry) = retry_after {
                    write!(f, "Service '{}' unavailable, retry after {} seconds", service, retry)
                } else {
                    write!(f, "Service '{}' unavailable", service)
                }
            }
            PdfError::Internal { component, error_id, details } => {
                write!(f, "Internal error in {} (ID: {}): {}", component, error_id, details)
            }
        }
    }
}

impl std::error::Error for PdfError {}

impl From<std::io::Error> for PdfError {
    fn from(err: std::io::Error) -> Self {
        PdfError::Io {
            message: err.to_string(),
            code: err.raw_os_error().unwrap_or(-1),
        }
    }
}

impl From<serde_json::Error> for PdfError {
    fn from(err: serde_json::Error) -> Self {
        PdfError::Json {
            message: err.to_string(),
            line: Some(err.line()),
        }
    }
}



//=============================================================================
// CORE PDF FORENSIC DATA STRUCTURES
//=============================================================================

/// Core PDF metadata container - primary data structure for forensic cloning
/// This is the main structure that contains all forensic information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfForensicData {
    /// PDF version information from header
    pub version: PdfVersion,
    /// Trailer dictionary data - CRITICAL for forensic matching
    pub trailer: TrailerData,
    /// Cross-reference table/stream data
    pub xref: XRefData,
    /// Encryption dictionary (if present)
    pub encryption: Option<EncryptionData>,
    /// Document metadata and info dictionary
    pub metadata: DocumentMetadata,
    /// Object-level structural data
    pub structure: StructuralData,
    /// Timestamp information - MUST BE PRESERVED EXACTLY
    pub timestamps: TimestampData,
    /// Document permissions and security
    pub permissions: PermissionData,
    /// Forensic markers and signatures for detection
    pub forensic_markers: ForensicMarkers,
    /// File-level properties and hashes
    pub file_properties: FileProperties,
    /// Incremental update chain information
    pub update_chain: UpdateChainData,
    /// Form field structures (without values)
    pub form_fields: FormFieldData,
    /// Annotation structures and metadata
    pub annotations: AnnotationData,
    /// Object stream information (PDF 1.5+)
    pub object_streams: ObjectStreamData,
    /// Linearization information
    pub linearization: Option<LinearizationData>,
    /// XMP metadata stream
    pub xmp_metadata: Option<XmpMetadata>,
    /// Extraction configuration and metadata
    pub extraction_info: ExtractionInfo,
    /// Application configuration
    pub app_config: AppConfig,
    /// Processing statistics
    pub processing_stats: ProcessingStatistics,
    /// Quality metrics
    pub quality_metrics: QualityMetrics,
    /// Forensic validation results
    pub validation_results: Vec<ValidationResult>,
    /// Cross-reference validation
    pub xref_validation: XRefValidationResult,
    /// Object integrity checks
    pub object_integrity: ObjectIntegrityResults,
    /// Stream analysis results
    pub stream_analysis: StreamAnalysisResults,
    /// Content preservation verification
    pub content_preservation: ContentPreservationResults,
}

impl Default for PdfForensicData {
    fn default() -> Self {
        Self {
            version: PdfVersion::default(),
            trailer: TrailerData::default(),
            xref: XRefData::default(),
            encryption: None,
            metadata: DocumentMetadata::default(),
            structure: StructuralData::default(),
            timestamps: TimestampData::default(),
            permissions: PermissionData::default(),
            forensic_markers: ForensicMarkers::default(),
            file_properties: FileProperties::default(),
            update_chain: UpdateChainData::default(),
            form_fields: FormFieldData::default(),
            annotations: AnnotationData::default(),
            object_streams: ObjectStreamData::default(),
            linearization: None,
            xmp_metadata: None,
            extraction_info: ExtractionInfo::default(),
            app_config: AppConfig::default(),
            processing_stats: ProcessingStatistics::default(),
            quality_metrics: QualityMetrics::default(),
            validation_results: Vec::new(),
            xref_validation: XRefValidationResult::default(),
            object_integrity: ObjectIntegrityResults::default(),
            stream_analysis: StreamAnalysisResults::default(),
            content_preservation: ContentPreservationResults::default(),
        }
    }
}

/// Application configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Extraction configuration
    pub extraction: ExtractionConfig,
    /// Injection configuration
    pub injection: InjectionConfig,
    /// Validation configuration
    pub validation: ValidationConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Performance configuration
    pub performance: PerformanceConfig,
    /// Security configuration
    pub security: SecurityConfig,
    /// Output configuration
    pub output: OutputConfig,
    /// Tool integration settings
    pub tool_integration: ToolIntegrationConfig,
}

/// Processing statistics for operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingStatistics {
    /// Start time of processing
    pub start_time: SystemTime,
    /// End time of processing
    pub end_time: Option<SystemTime>,
    /// Total processing duration in milliseconds
    pub duration_ms: u64,
    /// Memory usage statistics
    pub memory_usage: MemoryUsageStats,
    /// CPU usage statistics
    pub cpu_usage: CpuUsageStats,
    /// I/O statistics
    pub io_stats: IoStatistics,
    /// Object processing statistics
    pub object_stats: ObjectProcessingStats,
    /// Error and warning counts
    pub error_stats: ErrorStatistics,
}

impl Default for ProcessingStatistics {
    fn default() -> Self {
        Self {
            start_time: SystemTime::now(),
            end_time: None,
            duration_ms: 0,
            memory_usage: MemoryUsageStats::default(),
            cpu_usage: CpuUsageStats::default(),
            io_stats: IoStatistics::default(),
            object_stats: ObjectProcessingStats::default(),
            error_stats: ErrorStatistics::default(),
        }
    }
}

/// Memory usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryUsageStats {
    /// Peak memory usage in bytes
    pub peak_usage: u64,
    /// Current memory usage in bytes
    pub current_usage: u64,
    /// Average memory usage in bytes
    pub average_usage: u64,
    /// Memory allocations count
    pub allocations: u64,
    /// Memory deallocations count
    pub deallocations: u64,
    /// Memory fragmentation ratio
    pub fragmentation_ratio: f64,
}

impl Default for MemoryUsageStats {
    fn default() -> Self {
        Self {
            peak_usage: 0,
            current_usage: 0,
            average_usage: 0,
            allocations: 0,
            deallocations: 0,
            fragmentation_ratio: 0.0,
        }
    }
}

/// CPU usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuUsageStats {
    /// CPU time used in milliseconds
    pub cpu_time_ms: u64,
    /// Average CPU usage percentage
    pub average_cpu_percent: f64,
    /// Peak CPU usage percentage
    pub peak_cpu_percent: f64,
    /// Number of context switches
    pub context_switches: u64,
    /// Number of threads used
    pub thread_count: u32,
}

impl Default for CpuUsageStats {
    fn default() -> Self {
        Self {
            cpu_time_ms: 0,
            average_cpu_percent: 0.0,
            peak_cpu_percent: 0.0,
            context_switches: 0,
            thread_count: 1,
        }
    }
}

/// I/O operation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoStatistics {
    /// Bytes read from files
    pub bytes_read: u64,
    /// Bytes written to files
    pub bytes_written: u64,
    /// Number of read operations
    pub read_operations: u64,
    /// Number of write operations
    pub write_operations: u64,
    /// Average read speed in bytes per second
    pub read_speed_bps: f64,
    /// Average write speed in bytes per second
    pub write_speed_bps: f64,
    /// File seek operations count
    pub seek_operations: u64,
}

impl Default for IoStatistics {
    fn default() -> Self {
        Self {
            bytes_read: 0,
            bytes_written: 0,
            read_operations: 0,
            write_operations: 0,
            read_speed_bps: 0.0,
            write_speed_bps: 0.0,
            seek_operations: 0,
        }
    }
}

/// Object processing statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectProcessingStats {
    /// Total objects processed
    pub total_objects: u32,
    /// Objects successfully processed
    pub successful_objects: u32,
    /// Objects with errors
    pub error_objects: u32,
    /// Objects skipped
    pub skipped_objects: u32,
    /// Average object processing time in microseconds
    pub average_processing_time_us: f64,
    /// Largest object size processed
    pub largest_object_size: u64,
    /// Smallest object size processed
    pub smallest_object_size: u64,
}

impl Default for ObjectProcessingStats {
    fn default() -> Self {
        Self {
            total_objects: 0,
            successful_objects: 0,
            error_objects: 0,
            skipped_objects: 0,
            average_processing_time_us: 0.0,
            largest_object_size: 0,
            smallest_object_size: 0,
        }
    }
}

/// Error and warning statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorStatistics {
    /// Critical errors count
    pub critical_errors: u32,
    /// Major errors count
    pub major_errors: u32,
    /// Minor errors count
    pub minor_errors: u32,
    /// Warnings count
    pub warnings: u32,
    /// Informational messages count
    pub info_messages: u32,
    /// Error categories breakdown
    pub error_categories: HashMap<String, u32>,
}

impl Default for ErrorStatistics {
    fn default() -> Self {
        Self {
            critical_errors: 0,
            major_errors: 0,
            minor_errors: 0,
            warnings: 0,
            info_messages: 0,
            error_categories: HashMap::new(),
        }
    }
}

/// Quality metrics for forensic operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityMetrics {
    /// Forensic accuracy score (0.0-1.0)
    pub forensic_accuracy: f64,
    /// Metadata preservation score (0.0-1.0)
    pub metadata_preservation: f64,
    /// Structure integrity score (0.0-1.0)
    pub structure_integrity: f64,
    /// Content preservation score (0.0-1.0)
    pub content_preservation: f64,
    /// Watermark detection accuracy (0.0-1.0)
    pub watermark_detection_accuracy: f64,
    /// Tool signature detection accuracy (0.0-1.0)
    pub tool_signature_accuracy: f64,
    /// Overall quality score (0.0-1.0)
    pub overall_quality: f64,
    /// Quality breakdown by category
    pub category_scores: HashMap<String, f64>,
}

impl Default for QualityMetrics {
    fn default() -> Self {
        Self {
            forensic_accuracy: 1.0,
            metadata_preservation: 1.0,
            structure_integrity: 1.0,
            content_preservation: 1.0,
            watermark_detection_accuracy: 1.0,
            tool_signature_accuracy: 1.0,
            overall_quality: 1.0,
            category_scores: HashMap::new(),
        }
    }
}

/// Cross-reference validation results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XRefValidationResult {
    /// Whether XRef table is valid
    pub is_valid: bool,
    /// Validation errors found
    pub errors: Vec<XRefValidationError>,
    /// Validation warnings
    pub warnings: Vec<XRefValidationWarning>,
    /// Object reference consistency
    pub reference_consistency: bool,
    /// Generation number consistency
    pub generation_consistency: bool,
    /// Offset accuracy
    pub offset_accuracy: f64,
    /// Free object chain integrity
    pub free_chain_integrity: bool,
}

/// XRef validation error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XRefValidationError {
    /// Error type
    pub error_type: XRefErrorType,
    /// Object number affected
    pub object_number: u32,
    /// Generation number
    pub generation: u16,
    /// Error description
    pub description: String,
    /// Suggested fix
    pub suggested_fix: Option<String>,
}

/// XRef validation warning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XRefValidationWarning {
    /// Warning type
    pub warning_type: XRefWarningType,
    /// Object number affected
    pub object_number: u32,
    /// Warning description
    pub description: String,
    /// Recommendation
    pub recommendation: Option<String>,
}

/// XRef error types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum XRefErrorType {
    InvalidOffset,
    MissingObject,
    IncorrectGeneration,
    BrokenFreeChain,
    DuplicateEntry,
    InvalidEntryFormat,
    InconsistentSize,
    MissingSubsection,
}

/// XRef warning types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum XRefWarningType {
    UnusualOffset,
    HighGeneration,
    LargeGap,
    SuboptimalLayout,
    RedundantEntry,
    VersionMismatch,
}

/// Object integrity check results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectIntegrityResults {
    /// Overall integrity status
    pub overall_status: IntegrityStatus,
    /// Individual object results
    pub object_results: HashMap<ObjectReference, ObjectIntegrityResult>,
    /// Integrity score (0.0-1.0)
    pub integrity_score: f64,
    /// Objects with integrity issues
    pub compromised_objects: Vec<ObjectReference>,
    /// Objects verified as intact
    pub verified_objects: Vec<ObjectReference>,
}

/// Individual object integrity result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectIntegrityResult {
    /// Object reference
    pub object_ref: ObjectReference,
    /// Integrity status
    pub status: IntegrityStatus,
    /// Checksum verification
    pub checksum_valid: bool,
    /// Size verification
    pub size_valid: bool,
    /// Content verification
    pub content_valid: bool,
    /// Issues found
    pub issues: Vec<IntegrityIssue>,
    /// Integrity score for this object (0.0-1.0)
    pub object_score: f64,
}

/// Timestamp precision enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TimestampPrecision {
    Second,
    Minute,
    Hour,
    Day,
    Millisecond,
    Microsecond,
}

/// Integrity status enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IntegrityStatus {
    Valid,
    Warning,
    Compromised,
    Unknown,
    NotChecked,
}

/// Integrity issue details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityIssue {
    /// Issue type
    pub issue_type: IntegrityIssueType,
    /// Issue description
    pub description: String,
    /// Severity level
    pub severity: IntegritySeverity,
    /// Location of issue
    pub location: Option<u64>,
    /// Recommended action
    pub recommended_action: String,
}

/// Types of integrity issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntegrityIssueType {
    ChecksumMismatch,
    SizeDiscrepancy,
    ContentCorruption,
    MissingData,
    UnexpectedData,
    StructuralDamage,
    EncodingError,
    FilterFailure,
}

/// Integrity issue severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntegritySeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

/// Stream analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamAnalysisResults {
    /// Total streams analyzed
    pub total_streams: u32,
    /// Successfully analyzed streams
    pub successful_streams: u32,
    /// Failed stream analysis
    pub failed_streams: u32,
    /// Stream analysis by type
    pub stream_types: HashMap<String, StreamTypeAnalysis>,
    /// Compression analysis
    pub compression_analysis: CompressionAnalysis,
    /// Filter analysis
    pub filter_analysis: FilterAnalysis,
    /// Stream integrity results
    pub integrity_results: Vec<StreamIntegrityResult>,
}

/// Stream type analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamTypeAnalysis {
    /// Stream type name
    pub stream_type: String,
    /// Number of streams of this type
    pub count: u32,
    /// Total size of streams of this type
    pub total_size: u64,
    /// Average size of streams of this type
    pub average_size: f64,
    /// Compression ratio achieved
    pub compression_ratio: f64,
    /// Common filters used
    pub common_filters: Vec<String>,
}

/// Compression analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionAnalysis {
    /// Overall compression ratio
    pub overall_ratio: f64,
    /// Compression by filter type
    pub filter_ratios: HashMap<String, f64>,
    /// Uncompressed data size
    pub uncompressed_size: u64,
    /// Compressed data size
    pub compressed_size: u64,
    /// Compression efficiency score
    pub efficiency_score: f64,
}

/// Filter analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterAnalysis {
    /// Filter usage statistics
    pub filter_usage: HashMap<String, FilterUsageStats>,
    /// Filter chain analysis
    pub filter_chains: Vec<FilterChainAnalysis>,
    /// Filter compatibility issues
    pub compatibility_issues: Vec<FilterCompatibilityIssue>,
    /// Deprecated filter usage
    pub deprecated_filters: Vec<String>,
}

/// Filter usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterUsageStats {
    /// Filter name
    pub filter_name: String,
    /// Usage count
    pub usage_count: u32,
    /// Total data processed
    pub total_data_size: u64,
    /// Average processing time
    pub average_processing_time_ms: f64,
    /// Success rate
    pub success_rate: f64,
    /// Common parameters
    pub common_parameters: HashMap<String, String>,
}

/// Filter chain analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterChainAnalysis {
    /// Filter chain sequence
    pub filter_chain: Vec<String>,
    /// Usage frequency
    pub usage_frequency: u32,
    /// Overall efficiency
    pub efficiency: f64,
    /// Processing time
    pub processing_time_ms: f64,
    /// Compression effectiveness
    pub compression_effectiveness: f64,
}

/// Filter compatibility issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterCompatibilityIssue {
    /// Filter name
    pub filter_name: String,
    /// Issue description
    pub issue_description: String,
    /// Affected objects
    pub affected_objects: Vec<ObjectReference>,
    /// Severity
    pub severity: CompatibilitySeverity,
    /// Recommended solution
    pub recommended_solution: String,
}

/// Compatibility issue severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompatibilitySeverity {
    Blocking,
    Major,
    Minor,
    Warning,
}

/// Stream integrity result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamIntegrityResult {
    /// Stream object reference
    pub stream_ref: ObjectReference,
    /// Integrity status
    pub integrity_status: IntegrityStatus,
    /// Length verification
    pub length_verified: bool,
    /// Filter verification
    pub filters_verified: bool,
    /// Data corruption detected
    pub corruption_detected: bool,
    /// Integrity issues
    pub issues: Vec<StreamIntegrityIssue>,
}

/// Stream integrity issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamIntegrityIssue {
    /// Issue type
    pub issue_type: StreamIssueType,
    /// Issue description
    pub description: String,
    /// Byte offset of issue
    pub offset: Option<u64>,
    /// Data affected
    pub data_affected: u64,
    /// Repair possible
    pub repairable: bool,
}

/// Stream issue types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamIssueType {
    LengthMismatch,
    FilterError,
    DataCorruption,
    EncodingError,
    CompressionError,
    TruncatedData,
    InvalidHeader,
    ChecksumError,
}

/// Content preservation results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentPreservationResults {
    /// Overall preservation status
    pub overall_status: PreservationStatus,
    /// Content categories preserved
    pub preserved_categories: HashMap<String, PreservationResult>,
    /// Content hash verification
    pub hash_verification: HashVerificationResults,
    /// Visual content preservation
    pub visual_preservation: VisualPreservationResults,
    /// Text content preservation
    pub text_preservation: TextPreservationResults,
    /// Image preservation results
    pub image_preservation: ImagePreservationResults,
    /// Font preservation results
    pub font_preservation: FontPreservationResults,
}

/// Content preservation status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PreservationStatus {
    FullyPreserved,
    MostlyPreserved,
    PartiallyPreserved,
    PoorlyPreserved,
    NotPreserved,
    Unknown,
}

/// Individual preservation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreservationResult {
    /// Category name
    pub category: String,
    /// Preservation status
    pub status: PreservationStatus,
    /// Preservation score (0.0-1.0)
    pub score: f64,
    /// Issues found
    pub issues: Vec<PreservationIssue>,
    /// Verification method used
    pub verification_method: String,
}

/// Content preservation issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreservationIssue {
    /// Issue type
    pub issue_type: PreservationIssueType,
    /// Issue description
    pub description: String,
    /// Affected content identifier
    pub content_id: String,
    /// Severity
    pub severity: PreservationSeverity,
    /// Impact assessment
    pub impact: String,
}

/// Preservation issue types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PreservationIssueType {
    ContentLoss,
    QualityDegradation,
    LayoutChange,
    FontSubstitution,
    ColorChange,
    ResolutionChange,
    CompressionArtifacts,
    EncodingIssue,
}

/// Preservation issue severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PreservationSeverity {
    Critical,
    Major,
    Minor,
    Cosmetic,
}

/// Hash verification results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashVerificationResults {
    /// Overall hash verification status
    pub overall_status: bool,
    /// Individual hash results
    pub hash_results: HashMap<String, HashResult>,
    /// Hash algorithms used
    pub algorithms_used: Vec<String>,
    /// Hash verification time
    pub verification_time_ms: u64,
}

/// Individual hash verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashResult {
    /// Hash algorithm
    pub algorithm: String,
    /// Expected hash
    pub expected: String,
    /// Actual hash
    pub actual: String,
    /// Verification status
    pub verified: bool,
    /// Hash computation time
    pub computation_time_ms: u64,
}

/// Visual content preservation results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualPreservationResults {
    /// Overall visual preservation score
    pub overall_score: f64,
    /// Page rendering preservation
    pub page_rendering: Vec<PageRenderingResult>,
    /// Layout preservation
    pub layout_preservation: LayoutPreservationResult,
    /// Visual element preservation
    pub visual_elements: Vec<VisualElementResult>,
    /// Color preservation
    pub color_preservation: ColorPreservationResult,
}

/// Page rendering preservation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageRenderingResult {
    /// Page number
    pub page_number: u32,
    /// Rendering preservation score
    pub preservation_score: f64,
    /// Visual differences detected
    pub differences: Vec<VisualDifference>,
    /// Rendering time comparison
    pub rendering_time_delta: i64,
    /// Memory usage comparison
    pub memory_usage_delta: i64,
}

/// Visual difference detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualDifference {
    /// Difference type
    pub difference_type: VisualDifferenceType,
    /// Location of difference
    pub location: Rectangle,
    /// Difference magnitude
    pub magnitude: f64,
    /// Description
    pub description: String,
}

/// Types of visual differences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VisualDifferenceType {
    ColorChange,
    PositionShift,
    SizeChange,
    FontChange,
    MissingElement,
    ExtraElement,
    QualityChange,
    RotationChange,
}

/// Layout preservation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayoutPreservationResult {
    /// Layout preservation score
    pub preservation_score: f64,
    /// Text flow preservation
    pub text_flow_preserved: bool,
    /// Element positioning preserved
    pub positioning_preserved: bool,
    /// Page boundaries preserved
    pub page_boundaries_preserved: bool,
    /// Layout issues found
    pub layout_issues: Vec<LayoutIssue>,
}

/// Layout preservation issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayoutIssue {
    /// Issue type
    pub issue_type: LayoutIssueType,
    /// Affected page
    pub page_number: u32,
    /// Issue description
    pub description: String,
    /// Element affected
    pub element_id: Option<String>,
    /// Severity
    pub severity: LayoutSeverity,
}

/// Layout issue types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LayoutIssueType {
    TextOverflow,
    ElementOverlap,
    MarginChange,
    AlignmentShift,
    PageBreakChange,
    ColumnShift,
    TableLayout,
    ImagePlacement,
}

/// Layout issue severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LayoutSeverity {
    Critical,
    Major,
    Minor,
    Negligible,
}

/// Visual element preservation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualElementResult {
    /// Element type
    pub element_type: VisualElementType,
    /// Element identifier
    pub element_id: String,
    /// Preservation status
    pub preservation_status: PreservationStatus,
    /// Quality score
    pub quality_score: f64,
    /// Changes detected
    pub changes: Vec<ElementChange>,
}

/// Visual element types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VisualElementType {
    Text,
    Image,
    Vector,
    Shape,
    Chart,
    Table,
    Form,
    Annotation,
}

/// Element change detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElementChange {
    /// Change type
    pub change_type: ElementChangeType,
    /// Change description
    pub description: String,
    /// Before value
    pub before_value: Option<String>,
    /// After value
    pub after_value: Option<String>,
    /// Change magnitude
    pub magnitude: f64,
}

/// Element change types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ElementChangeType {
    Position,
    Size,
    Color,
    Font,
    Style,
    Content,
    Visibility,
    Opacity,
}

/// Color preservation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColorPreservationResult {
    /// Color preservation score
    pub preservation_score: f64,
    /// Color space preservation
    pub color_space_preserved: bool,
    /// Color accuracy metrics
    pub color_accuracy: ColorAccuracyMetrics,
    /// Color profile preservation
    pub color_profile_preserved: bool,
    /// Color issues detected
    pub color_issues: Vec<ColorIssue>,
}

/// Color accuracy metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColorAccuracyMetrics {
    /// Delta E average
    pub delta_e_average: f64,
    /// Delta E maximum
    pub delta_e_maximum: f64,
    /// Color difference threshold
    pub difference_threshold: f64,
    /// Colors within threshold percentage
    pub colors_within_threshold: f64,
}

/// Color preservation issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColorIssue {
    /// Issue type
    pub issue_type: ColorIssueType,
    /// Issue description
    pub description: String,
    /// Affected color space
    pub color_space: Option<String>,
    /// Color difference value
    pub color_difference: f64,
    /// Location of issue
    pub location: Option<Rectangle>,
}

/// Color issue types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ColorIssueType {
    ColorSpaceChange,
    GamutClipping,
    ProfileMismatch,
    ColorShift,
    SaturationChange,
    BrightnessChange,
    ContrastChange,
    ProfileLoss,
}

/// Text content preservation results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextPreservationResults {
    /// Text preservation score
    pub preservation_score: f64,
    /// Text extraction comparison
    pub text_extraction: TextExtractionComparison,
    /// Font preservation results
    pub font_preservation: FontPreservationSummary,
    /// Text encoding preservation
    pub encoding_preservation: EncodingPreservationResult,
    /// Text accessibility preservation
    pub accessibility_preservation: AccessibilityPreservationResult,
}

/// Text extraction comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextExtractionComparison {
    /// Original text length
    pub original_length: usize,
    /// Extracted text length
    pub extracted_length: usize,
    /// Text similarity score
    pub similarity_score: f64,
    /// Character differences
    pub character_differences: u32,
    /// Word differences
    pub word_differences: u32,
    /// Line differences
    pub line_differences: u32,
    /// Text extraction errors
    pub extraction_errors: Vec<TextExtractionError>,
}

/// Text extraction error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextExtractionError {
    /// Error type
    pub error_type: TextExtractionErrorType,
    /// Error description
    pub description: String,
    /// Character position
    pub position: usize,
    /// Length affected
    pub length: usize,
    /// Original text
    pub original_text: String,
    /// Extracted text
    pub extracted_text: String,
}

/// Text extraction error types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TextExtractionErrorType {
    MissingText,
    ExtraText,
    CharacterSubstitution,
    EncodingError,
    FontMappingError,
    LayoutError,
    OrderError,
    FormatError,
}

/// Font preservation summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontPreservationSummary {
    /// Overall font preservation score
    pub preservation_score: f64,
    /// Fonts preserved count
    pub fonts_preserved: u32,
    /// Fonts substituted count
    pub fonts_substituted: u32,
    /// Fonts missing count
    pub fonts_missing: u32,
    /// Font substitution details
    pub substitution_details: Vec<FontSubstitution>,
}

/// Font substitution details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontSubstitution {
    /// Original font name
    pub original_font: String,
    /// Substituted font name
    pub substituted_font: String,
    /// Substitution reason
    pub substitution_reason: FontSubstitutionReason,
    /// Visual impact score
    pub visual_impact: f64,
    /// Affected text count
    pub affected_text_count: u32,
}

/// Font substitution reasons
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FontSubstitutionReason {
    FontNotEmbedded,
    FontNotAvailable,
    FontCorrupted,
    LicenseRestriction,
    FormatIncompatibility,
    SystemConstraint,
}

/// Encoding preservation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodingPreservationResult {
    /// Encoding preservation score
    pub preservation_score: f64,
    /// Character encoding preserved
    pub character_encoding_preserved: bool,
    /// Unicode normalization preserved
    pub unicode_normalization_preserved: bool,
    /// Byte order mark preserved
    pub bom_preserved: bool,
    /// Encoding issues detected
    pub encoding_issues: Vec<EncodingIssue>,
}

/// Encoding preservation issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodingIssue {
    /// Issue type
    pub issue_type: EncodingIssueType,
    /// Issue description
    pub description: String,
    /// Affected text position
    pub position: usize,
    /// Character(s) affected
    pub affected_characters: String,
    /// Encoding before
    pub encoding_before: String,
    /// Encoding after
    pub encoding_after: String,
}

/// Encoding issue types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncodingIssueType {
    CharacterLoss,
    EncodingConversion,
    NormalizationChange,
    BomLoss,
    CodepointChange,
    SurrogatePairIssue,
    InvalidSequence,
    TruncatedSequence,
}

/// Accessibility preservation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessibilityPreservationResult {
    /// Accessibility preservation score
    pub preservation_score: f64,
    /// Structure tags preserved
    pub structure_tags_preserved: bool,
    /// Alt text preserved
    pub alt_text_preserved: bool,
    /// Reading order preserved
    pub reading_order_preserved: bool,
    /// Language information preserved
    pub language_info_preserved: bool,
    /// Accessibility issues
    pub accessibility_issues: Vec<AccessibilityIssue>,
}

/// Accessibility preservation issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessibilityIssue {
    /// Issue type
    pub issue_type: AccessibilityIssueType,
    /// Issue description
    pub description: String,
    /// Affected element
    pub affected_element: String,
    /// Severity
    pub severity: AccessibilitySeverity,
    /// Compliance impact
    pub compliance_impact: String,
}

/// Accessibility issue types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessibilityIssueType {
    MissingAltText,
    LostStructureTags,
    ReadingOrderChange,
    LanguageInfoLoss,
    ContrastReduction,
    FocusOrderChange,
    LandmarkLoss,
    HeadingStructureLoss,
}

/// Accessibility issue severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessibilitySeverity {
    Critical,
    Major,
    Minor,
    Informational,
}

/// Image preservation results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImagePreservationResults {
    /// Image preservation score
    pub preservation_score: f64,
    /// Images preserved count
    pub images_preserved: u32,
    /// Images with quality loss count
    pub images_quality_loss: u32,
    /// Images corrupted count
    pub images_corrupted: u32,
    /// Individual image results
    pub individual_results: Vec<IndividualImageResult>,
    /// Image format analysis
    pub format_analysis: ImageFormatAnalysis,
}

/// Individual image preservation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndividualImageResult {
    /// Image identifier
    pub image_id: String,
    /// Image object reference
    pub object_ref: ObjectReference,
    /// Preservation status
    pub preservation_status: PreservationStatus,
    /// Quality score
    pub quality_score: f64,
    /// Original image properties
    pub original_properties: ImageProperties,
    /// Current image properties
    pub current_properties: ImageProperties,
    /// Quality metrics
    pub quality_metrics: ImageQualityMetrics,
    /// Issues detected
    pub issues: Vec<ImageIssue>,
}

/// Image quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageQualityMetrics {
    /// Peak Signal-to-Noise Ratio
    pub psnr: f64,
    /// Structural Similarity Index
    pub ssim: f64,
    /// Mean Squared Error
    pub mse: f64,
    /// Visual Information Fidelity
    pub vif: f64,
    /// Perceptual quality score
    pub perceptual_quality: f64,
}

/// Image preservation issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageIssue {
    /// Issue type
    pub issue_type: ImageIssueType,
    /// Issue description
    pub description: String,
    /// Severity
    pub severity: ImageIssueSeverity,
    /// Quality impact
    pub quality_impact: f64,
    /// Repair possible
    pub repairable: bool,
}

/// Image issue types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImageIssueType {
    QualityLoss,
    FormatChange,
    CompressionArtifacts,
    ColorSpaceChange,
    ResolutionChange,
    AspectRatioChange,
    MetadataLoss,
    ProfileLoss,
}

/// Image issue severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImageIssueSeverity {
    Severe,
    Moderate,
    Minor,
    Negligible,
}

/// Image format analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageFormatAnalysis {
    /// Format distribution
    pub format_distribution: HashMap<String, u32>,
    /// Compression analysis
    pub compression_analysis: HashMap<String, CompressionMetrics>,
    /// Color space analysis
    pub color_space_analysis: HashMap<String, u32>,
    /// Resolution analysis
    pub resolution_analysis: ResolutionAnalysis,
}

/// Compression metrics for images
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionMetrics {
    /// Compression ratio
    pub compression_ratio: f64,
    /// Quality setting (if applicable)
    pub quality_setting: Option<u8>,
    /// File size reduction
    pub size_reduction: f64,
    /// Visual quality score
    pub visual_quality: f64,
}

/// Resolution analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionAnalysis {
    /// Average DPI
    pub average_dpi: f64,
    /// DPI distribution
    pub dpi_distribution: HashMap<String, u32>,
    /// Resolution consistency
    pub resolution_consistency: bool,
    /// High resolution image count
    pub high_res_count: u32,
    /// Low resolution image count
    pub low_res_count: u32,
}

/// Font preservation results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontPreservationResults {
    /// Font preservation score
    pub preservation_score: f64,
    /// Fonts analyzed
    pub fonts_analyzed: u32,
    /// Fonts preserved
    pub fonts_preserved: u32,
    /// Fonts substituted
    pub fonts_substituted: u32,
    /// Font embedding analysis
    pub embedding_analysis: FontEmbeddingAnalysis,
    /// Font subset analysis
    pub subset_analysis: FontSubsetAnalysis,
    /// Individual font results
    pub individual_results: Vec<IndividualFontResult>,
}

/// Font embedding analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontEmbeddingAnalysis {
    /// Fully embedded fonts
    pub fully_embedded: u32,
    /// Subset embedded fonts
    pub subset_embedded: u32,
    /// Not embedded fonts
    pub not_embedded: u32,
    /// Embedding completeness score
    pub completeness_score: f64,
    /// Embedding issues
    pub embedding_issues: Vec<FontEmbeddingIssue>,
}

/// Font embedding issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontEmbeddingIssue {
    /// Font name
    pub font_name: String,
    /// Issue type
    pub issue_type: FontEmbeddingIssueType,
    /// Issue description
    pub description: String,
    /// Impact on document
    pub impact: String,
    /// Recommended action
    pub recommended_action: String,
}

/// Font embedding issue types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FontEmbeddingIssueType {
    NotEmbedded,
    IncompleteSubset,
    CorruptedFont,
    LicenseIssue,
    UnsupportedFormat,
    MissingGlyphs,
}

/// Font subset analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontSubsetAnalysis {
    /// Subset efficiency score
    pub efficiency_score: f64,
    /// Character coverage analysis
    pub character_coverage: CharacterCoverageAnalysis,
    /// Subset optimization potential
    pub optimization_potential: f64,
    /// Subset issues
    pub subset_issues: Vec<FontSubsetIssue>,
}

/// Character coverage analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CharacterCoverageAnalysis {
    /// Total characters available
    pub total_characters: u32,
    /// Characters used
    pub characters_used: u32,
    /// Coverage percentage
    pub coverage_percentage: f64,
    /// Missing characters
    pub missing_characters: Vec<char>,
    /// Unused characters
    pub unused_character_count: u32,
}

/// Font subset issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontSubsetIssue {
    /// Font name
    pub font_name: String,
    /// Issue type
    pub issue_type: FontSubsetIssueType,
    /// Issue description
    pub description: String,
    /// Characters affected
    pub characters_affected: Vec<char>,
    /// Severity
    pub severity: FontSubsetSeverity,
}

/// Font subset issue types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FontSubsetIssueType {
    MissingCharacters,
    IncompleteGlyphs,
    EncodingMismatch,
    SubsetTooLarge,
    SubsetTooSmall,
    InvalidSubset,
}

/// Font subset issue severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FontSubsetSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Individual font preservation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndividualFontResult {
    /// Font name
    pub font_name: String,
    /// Font object reference
    pub object_ref: ObjectReference,
    /// Preservation status
    pub preservation_status: PreservationStatus,
    /// Font properties before
    pub properties_before: FontProperties,
    /// Font properties after
    pub properties_after: FontProperties,
    /// Font metrics comparison
    pub metrics_comparison: FontMetricsComparison,
    /// Issues detected
    pub issues: Vec<FontPreservationIssue>,
}

/// Font properties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontProperties {
    /// Font name
    pub name: String,
    /// Font type
    pub font_type: String,
    /// Font subtype
    pub subtype: Option<String>,
    /// Base font
    pub base_font: Option<String>,
    /// Encoding
    pub encoding: Option<String>,
    /// Embedded status
    pub embedded: bool,
    /// Subset status
    pub subset: bool,
    /// Font file size
    pub file_size: Option<u64>,
    /// Character count
    pub character_count: Option<u32>,
}

/// Font metrics comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontMetricsComparison {
    /// Metrics match
    pub metrics_match: bool,
    /// Ascender difference
    pub ascender_diff: f64,
    /// Descender difference
    pub descender_diff: f64,
    /// Line height difference
    pub line_height_diff: f64,
    /// Character width differences
    pub char_width_diffs: HashMap<char, f64>,
    /// Kerning differences
    pub kerning_diffs: Vec<KerningDifference>,
}

/// Kerning difference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerningDifference {
    /// First character
    pub char1: char,
    /// Second character
    pub char2: char,
    /// Original kerning value
    pub original_kerning: f64,
    /// Current kerning value
    pub current_kerning: f64,
    /// Difference
    pub difference: f64,
}

/// Font preservation issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontPreservationIssue {
    /// Issue type
    pub issue_type: FontPreservationIssueType,
    /// Issue description
    pub description: String,
    /// Characters affected
    pub characters_affected: Option<Vec<char>>,
    /// Visual impact score
    pub visual_impact: f64,
    /// Severity
    pub severity: FontPreservationSeverity,
}

/// Font preservation issue types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FontPreservationIssueType {
    FontSubstitution,
    MetricsChange,
    EncodingChange,
    EmbeddingLoss,
    SubsetChange,
    GlyphCorruption,
    KerningLoss,
    LigatureLoss,
}

/// Font preservation issue severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FontPreservationSeverity {
    Critical,
    Major,
    Minor,
    Cosmetic,
}

//=============================================================================
// PDF VERSION AND HEADER STRUCTURES
//=============================================================================

/// PDF version information extracted from document header
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PdfVersion {
    /// Major version number (e.g., 1 for PDF 1.4)
    pub major: u8,
    /// Minor version number (e.g., 4 for PDF 1.4)
    pub minor: u8,
    /// Raw header bytes including %PDF- prefix
    pub header_bytes: Vec<u8>,
    /// Byte offset where header starts (usually 0)
    pub header_offset: u64,
    /// Header comment lines following version (if any)
    pub header_comments: Vec<String>,
}

impl std::fmt::Display for PdfVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

//=============================================================================
// TRAILER DICTIONARY STRUCTURES - CRITICAL FOR FORENSIC MATCHING
//=============================================================================

/// Trailer dictionary data - most critical component for forensic identity
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrailerData {
    /// Total number of entries in cross-reference table
    pub size: u32,
    /// Reference to catalog (root) object
    pub root_ref: ObjectReference,
    /// Reference to info dictionary (optional but critical)
    pub info_ref: Option<ObjectReference>,
    /// PDF ID array [original_id, current_id] - ABSOLUTELY CRITICAL
    /// Must be preserved byte-for-byte for forensic matching
    pub id_array: Option<[String; 2]>,
    /// Byte offset to previous cross-reference table (incremental updates)
    pub prev_offset: Option<u64>,
    /// Reference to encryption dictionary (if encrypted)
    pub encrypt_ref: Option<ObjectReference>,
    /// Raw trailer dictionary bytes as they appear in file
    pub raw_trailer_bytes: Vec<u8>,
    /// Byte offset where trailer keyword appears
    pub trailer_offset: u64,
    /// Additional trailer fields not in standard specification
    pub additional_fields: HashMap<String, TrailerValue>,
}

/// Values that can appear in trailer dictionary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrailerValue {
    /// Numeric value
    Number(i64),
    /// Object reference
    Reference(ObjectReference),
    /// String value
    String(String),
    /// Array of values
    Array(Vec<TrailerValue>),
    /// Boolean value
    Boolean(bool),
    /// Null value
    Null,
}

impl Default for XRefData {
    fn default() -> Self {
        Self {
            xref_type: XRefType::Table,
            entries: Vec::new(),
            subsections: Vec::new(),
            xref_offset: 0,
            raw_xref_bytes: Vec::new(),
            stream_dict: None,
            hybrid_info: None,
            trailer: TrailerData::default(),
        }
    }
}

//=============================================================================
// CROSS-REFERENCE TABLE STRUCTURES
//=============================================================================

/// Cross-reference table or stream data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XRefData {
    /// Type of cross-reference structure
    pub xref_type: XRefType,
    /// All cross-reference entries in order
    pub entries: Vec<XRefEntry>,
    /// Subsection information for traditional xref tables
    pub subsections: Vec<XRefSubsection>,
    /// Byte offset where xref table/stream starts
    pub xref_offset: u64,
    /// Raw bytes of complete xref structure
    pub raw_xref_bytes: Vec<u8>,
    /// XRef stream dictionary (for stream-based xref)
    pub stream_dict: Option<XRefStreamDict>,
    /// Hybrid xref information (mixed table/stream)
    pub hybrid_info: Option<HybridXRefInfo>,
    /// Trailer data associated with this xref
    pub trailer: TrailerData,
}

/// Type of cross-reference structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum XRefType {
    /// Traditional cross-reference table
    Table,
    /// Cross-reference stream (PDF 1.5+)
    Stream,
    /// Hybrid (both table and stream references)
    Hybrid,
}

/// Individual cross-reference entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XRefEntry {
    /// Object number
    pub object_number: u32,
    /// Generation number
    pub generation: u16,
    /// Byte offset, object stream index, or next free object
    pub offset_or_index: u64,
    /// Entry type: in-use, free, or compressed
    pub entry_type: XRefEntryType,
    /// Raw entry bytes (for traditional tables)
    pub raw_bytes: Option<Vec<u8>>,
}

/// Type of cross-reference entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum XRefEntryType {
    /// Object is in use (type 1 for streams, 'n' for tables)
    InUse,
    /// Object is free (type 0 for streams, 'f' for tables)
    Free,
    /// Object is in object stream (type 2 for streams only)
    Compressed { stream_obj: u32, index: u16 },
}

/// Cross-reference subsection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XRefSubsection {
    /// Starting object number for this subsection
    pub start_object: u32,
    /// Number of entries in this subsection
    pub count: u32,
    /// Byte offset where subsection starts
    pub offset: u64,
}

/// XRef stream dictionary (PDF 1.5+)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XRefStreamDict {
    /// Width array specifying field widths
    pub w_array: Vec<u8>,
    /// Index array specifying object ranges
    pub index_array: Option<Vec<u32>>,
    /// Stream filter specifications
    pub filter: Option<StreamFilter>,
    /// Decode parameters
    pub decode_parms: Option<DecodeParams>,
    /// Stream length
    pub length: u64,
}

/// Hybrid cross-reference information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridXRefInfo {
    /// Traditional table offset
    pub table_offset: u64,
    /// Stream object reference
    pub stream_ref: ObjectReference,
    /// Objects covered by table vs stream
    pub coverage_map: HashMap<u32, XRefCoverage>,
}

/// Coverage type for hybrid xref
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum XRefCoverage {
    /// Object referenced in traditional table
    Table,
    /// Object referenced in stream
    Stream,
}

//=============================================================================
// OBJECT REFERENCE AND OBJECT DATA STRUCTURES
//=============================================================================

/// Object reference (indirect object identifier)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub struct ObjectReference {
    /// Object number
    pub number: u32,
    /// Generation number
    pub generation: u16,
}

impl ObjectReference {
    pub fn new(number: u32, generation: u16) -> Self {
        Self { number, generation }
    }
}

impl AsRef<ObjectReference> for ObjectReference {
    fn as_ref(&self) -> &ObjectReference {
        self
    }
}

/// Complete indirect object information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndirectObject {
    /// Object reference
    pub reference: ObjectReference,
    /// Byte offset where object starts in file
    pub offset: u64,
    /// Total size of object including header and content
    pub size: u64,
    /// Object type from dictionary (if present)
    pub object_type: Option<String>,
    /// Object subtype from dictionary (if present)
    pub subtype: Option<String>,
    /// Whether object contains a stream
    pub has_stream: bool,
    /// Stream length (if object has stream)
    pub stream_length: Option<u64>,
    /// Object dictionary content (parsed)
    pub dictionary: Option<PdfDictionary>,
    /// Stream filters applied
    pub stream_filters: Vec<StreamFilter>,
    /// Whether object is compressed in object stream
    pub compressed: bool,
    /// Object stream reference (if compressed)
    pub object_stream_ref: Option<ObjectReference>,
    /// Index within object stream (if compressed)
    pub object_stream_index: Option<u16>,
}

/// PDF dictionary representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfDictionary {
    /// Dictionary entries
    pub entries: HashMap<String, PdfValue>,
    /// Raw dictionary bytes
    pub raw_bytes: Vec<u8>,
}

impl PdfDictionary {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            raw_bytes: Vec::new(),
        }
    }
}

/// PDF value types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PdfValue {
    /// Null value
    Null,
    /// Boolean value
    Boolean(bool),
    /// Integer value
    Integer(i64),
    /// Real (floating point) value
    Real(f64),
    /// String value (literal or hex)
    String(PdfString),
    /// Name value
    Name(String),
    /// Array of values
    Array(Vec<PdfValue>),
    /// Dictionary value
    Dictionary(PdfDictionary),
    /// Stream value
    Stream(PdfStream),
    /// Object reference
    Reference(ObjectReference),
}

/// PDF string representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfString {
    /// String content
    pub content: String,
    /// Original encoding (literal, hex, etc.)
    pub encoding: StringEncoding,
    /// Raw bytes as they appear in PDF
    pub raw_bytes: Vec<u8>,
}

/// PDF string encoding types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StringEncoding {
    /// Literal string (parentheses)
    Literal,
    /// Hexadecimal string (angle brackets)
    Hexadecimal,
    /// UTF-16BE with BOM
    Utf16Be,
    /// PDFDocEncoding
    PdfDocEncoding,
}

/// PDF stream representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfStream {
    /// Stream dictionary
    pub dictionary: PdfDictionary,
    /// Raw stream data (possibly compressed)
    pub raw_data: Vec<u8>,
    /// Decompressed stream data (if applicable)
    pub decoded_data: Option<Vec<u8>>,
    /// Stream filters applied
    pub filters: Vec<StreamFilter>,
}

//=============================================================================
// ENCRYPTION STRUCTURES
//=============================================================================

/// Complete encryption dictionary data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionData {
    /// Security handler name
    pub filter: String,
    /// Version of encryption algorithm
    pub v: u8,
    /// Revision of encryption algorithm
    pub r: u8,
    /// Owner password hash - MUST BE PRESERVED EXACTLY
    pub o: Vec<u8>,
    /// User password hash - MUST BE PRESERVED EXACTLY
    pub u: Vec<u8>,
    /// Permission flags
    pub p: i32,
    /// Encryption key length in bits
    pub length: Option<u16>,
    /// String filter method
    pub str_f: Option<String>,
    /// Stream filter method
    pub stm_f: Option<String>,
    /// Encrypt metadata flag
    pub encrypt_metadata: Option<bool>,
    /// Crypt filters dictionary
    pub cf: Option<CryptFilters>,
    /// Additional encryption parameters
    pub additional_params: HashMap<String, String>,
    /// Raw encryption dictionary bytes
    pub raw_dict_bytes: Vec<u8>,
}

/// Crypt filters for advanced encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptFilters {
    /// Individual crypt filter definitions
    pub filters: HashMap<String, CryptFilter>,
}

impl EncryptionData {
    /// Create default encryption data with error message
    pub fn default_with_error(error_msg: &str) -> Self {
        Self {
            filter: "Standard".to_string(),
            v: 1,
            r: 2,
            o: vec![0; 32], // Default O entry
            u: vec![0; 32], // Default U entry
            p: -4, // Default permissions
            length: Some(40),
            str_f: None,
            stm_f: None,
            encrypt_metadata: Some(true),
            cf: None,
            additional_params: {
                let mut params = HashMap::new();
                params.insert("error".to_string(), error_msg.to_string());
                params
            },
            raw_dict_bytes: format!("<< /Filter /Standard /V 1 /R 2 /Error ({}) >>", error_msg).into_bytes(),
        }
    }
}

/// Individual crypt filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptFilter {
    /// Filter method
    pub cfm: String,
    /// Authorization event
    pub auth_event: Option<String>,
    /// Key length
    pub length: Option<u16>,
}

//=============================================================================
// DOCUMENT METADATA STRUCTURES
//=============================================================================

/// Document metadata from /Info dictionary and XMP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentMetadata {
    /// Document title
    pub title: Option<String>,
    /// Document author
    pub author: Option<String>,
    /// Document subject
    pub subject: Option<String>,
    /// Document keywords
    pub keywords: Option<String>,
    /// Creating application
    pub creator: Option<String>,
    /// PDF producer software - critical for tool detection
    pub producer: Option<String>,
    /// Document creation date - MUST BE PRESERVED EXACTLY
    pub creation_date: Option<String>,
    /// Document modification date - MUST BE PRESERVED EXACTLY
    pub mod_date: Option<String>,
    /// Trapped field
    pub trapped: Option<TrappedValue>,
    /// Custom metadata fields beyond standard
    pub custom_fields: HashMap<String, String>,
    /// Raw /Info dictionary bytes
    pub raw_info_bytes: Vec<u8>,
    /// Info object reference
    pub info_object_ref: Option<ObjectReference>,
}

/// Trapped field values
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrappedValue {
    /// True value
    True,
    /// False value
    False,
    /// Unknown value
    Unknown,
}

impl Default for DocumentMetadata {
    fn default() -> Self {
        Self {
            title: None,
            author: None,
            subject: None,
            keywords: None,
            creator: None,
            producer: None,
            creation_date: None,
            mod_date: None,
            trapped: None,
            custom_fields: HashMap::new(),
            raw_info_bytes: Vec::new(),
            info_object_ref: None,
        }
    }
}

//=============================================================================
// XMP METADATA STRUCTURES
//=============================================================================

/// XMP metadata stream information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XmpMetadata {
    /// Raw XMP XML content
    pub raw_xml: String,
    /// Parsed XMP properties
    pub properties: HashMap<String, XmpProperty>,
    /// XMP namespaces used
    pub namespaces: HashMap<String, String>,
    /// XMP packet wrapper information
    pub packet_info: XmpPacketInfo,
    /// Object reference containing XMP
    pub object_ref: ObjectReference,
}

/// Individual XMP property
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XmpProperty {
    /// Property value
    pub value: String,
    /// Property namespace
    pub namespace: String,
    /// Property attributes
    pub attributes: HashMap<String, String>,
}

/// XMP packet wrapper information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct XmpPacketInfo {
    /// Packet begin marker
    pub begin: String,
    /// Packet end marker
    pub end: String,
    /// Packet ID (if present)
    pub id: Option<String>,
    /// Packet bytes attribute
    pub bytes: Option<u64>,
    /// Packet encoding
    pub encoding: String,
}

//=============================================================================
// TIMESTAMP STRUCTURES - CRITICAL FOR FORENSIC MATCHING
//=============================================================================

/// Timestamp data - MUST BE PRESERVED EXACTLY FOR FORENSIC MATCHING
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TimestampData {
    /// Raw creation date string as it appears in PDF
    pub creation_raw: Option<String>,
    /// Raw modification date string as it appears in PDF
    pub modification_raw: Option<String>,
    /// Parsed creation timestamp (for validation only)
    pub creation_parsed: Option<ParsedTimestamp>,
    /// Parsed modification timestamp (for validation only)
    pub modification_parsed: Option<ParsedTimestamp>,
    /// Timestamp format detected
    pub format_type: TimestampFormat,
    /// Timezone information
    pub timezone_info: Option<TimezoneInfo>,
    /// Timestamp validation status
    pub validation_status: TimestampValidation,
}

/// Parsed timestamp structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedTimestamp {
    /// Year
    pub year: i32,
    /// Month (1-12)
    pub month: u8,
    /// Day (1-31)
    pub day: u8,
    /// Hour (0-23)
    pub hour: u8,
    /// Minute (0-59)
    pub minute: u8,
    /// Second (0-59)
    pub second: u8,
    /// UTC offset in minutes
    pub utc_offset: Option<i16>,
}

/// Timestamp format types
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum TimestampFormat {
    /// PDF date format: D:YYYYMMDDHHmmSSOHH'mm
    #[default]
    PdfDate,
    /// ISO 8601 format
    Iso8601,
    /// Custom format
    Custom(String),
    /// Invalid/unparseable format
    Invalid,
}

/// Timezone information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimezoneInfo {
    /// UTC offset in minutes
    pub utc_offset: i16,
    /// Timezone abbreviation (if known)
    pub abbreviation: Option<String>,
    /// Whether daylight saving time
    pub dst: Option<bool>,
}

/// Timestamp source information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampSource {
    /// Source location in the PDF
    pub source_type: String,
    /// Raw timestamp value
    pub raw_value: String,
    /// Offset in file where found
    pub file_offset: u64,
    /// Context information
    pub context: String,
}

/// Timestamp validation status
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum TimestampValidation {
    /// Timestamp is valid and parseable
    #[default]
    Valid,
    /// Timestamp has minor formatting issues but is parseable
    ValidWithWarnings(Vec<String>),
    /// Timestamp is invalid or corrupted
    Invalid(String),
}

//=============================================================================
// PERMISSION AND SECURITY STRUCTURES
//=============================================================================

/// Document permission and security data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionData {
    /// Print permission
    pub print: PermissionLevel,
    /// Modify document permission
    pub modify: PermissionLevel,
    /// Copy/extract content permission
    pub copy: PermissionLevel,
    /// Add/modify annotations permission
    pub add_notes: PermissionLevel,
    /// Fill form fields permission
    pub fill_forms: PermissionLevel,
    /// Extract for accessibility permission
    pub extract_accessibility: PermissionLevel,
    /// Assemble document permission
    pub assemble: PermissionLevel,
    /// Print high quality permission
    pub print_high_quality: PermissionLevel,
    /// Raw permission bits from encryption dictionary
    pub raw_permission_bits: i32,
    /// Security handler revision
    pub security_revision: Option<u8>,
}

/// Permission level enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PermissionLevel {
    /// Permission is explicitly allowed
    Allowed,
    /// Permission is explicitly denied
    Denied,
    /// Permission is not applicable (no encryption)
    NotApplicable,
    /// Permission state is unknown/indeterminate
    Unknown,
}

impl Default for PermissionData {
    fn default() -> Self {
        Self {
            print: PermissionLevel::NotApplicable,
            modify: PermissionLevel::NotApplicable,
            copy: PermissionLevel::NotApplicable,
            add_notes: PermissionLevel::NotApplicable,
            fill_forms: PermissionLevel::NotApplicable,
            extract_accessibility: PermissionLevel::NotApplicable,
            assemble: PermissionLevel::NotApplicable,
            print_high_quality: PermissionLevel::NotApplicable,
            raw_permission_bits: 0,
            security_revision: None,
        }
    }
}

//=============================================================================
// STRUCTURAL DATA AND OBJECT ANALYSIS
//=============================================================================

/// PDF structural data and object organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuralData {
    /// Total file size in bytes
    pub file_size: u64,
    /// Total number of indirect objects
    pub object_count: u32,
    /// All indirect objects in the file
    pub indirect_objects: Vec<IndirectObject>,
    /// EOF marker information
    pub eof_marker: EofMarker,
    /// Page tree structure
    pub page_tree: Option<PageTreeStructure>,
    /// Font information
    pub fonts: Vec<FontInfo>,
    /// Image information
    pub images: Vec<ImageInfo>,
    /// Content stream analysis
    pub content_streams: Vec<ContentStreamInfo>,
    /// Embedded files
    pub embedded_files: Vec<EmbeddedFileInfo>,
    /// JavaScript objects
    pub javascript_objects: Vec<JavaScriptInfo>,
    /// Suspicious object indicators
    pub suspicious_objects: Vec<SuspiciousObjectInfo>,
}

impl Default for StructuralData {
    fn default() -> Self {
        Self {
            file_size: 0,
            object_count: 0,
            indirect_objects: Vec::new(),
            eof_marker: EofMarker {
                offset: 0,
                raw_bytes: Vec::new(),
                at_file_end: false,
                trailing_bytes: None,
            },
            page_tree: None,
            fonts: Vec::new(),
            images: Vec::new(),
            content_streams: Vec::new(),
            embedded_files: Vec::new(),
            javascript_objects: Vec::new(),
            suspicious_objects: Vec::new(),
        }
    }
}

/// EOF marker information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EofMarker {
    /// Byte offset where %%EOF marker appears
    pub offset: u64,
    /// Raw EOF marker bytes
    pub raw_bytes: Vec<u8>,
    /// Whether EOF is at actual end of file
    pub at_file_end: bool,
    /// Bytes after EOF marker (if any)
    pub trailing_bytes: Option<Vec<u8>>,
}

/// Page tree structure analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PageTreeStructure {
    /// Linear page structure
    Linear,
    /// Balanced tree structure
    Balanced,
    /// Unbalanced tree structure
    Unbalanced,
    /// Corrupted or invalid structure
    Corrupted,
}

/// Page tree analysis data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageTreeAnalysis {
    /// Root pages object reference
    pub root_ref: ObjectReference,
    /// Total page count
    pub page_count: u32,
    /// Individual page references in order
    pub page_refs: Vec<ObjectReference>,
    /// Page tree depth
    pub tree_depth: u32,
    /// Intermediate page tree nodes
    pub intermediate_nodes: Vec<ObjectReference>,
    /// Structure type
    pub structure_type: PageTreeStructure,
}

/// Font information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontInfo {
    /// Font object reference
    pub object_ref: ObjectReference,
    /// Font type (Type1, TrueType, etc.)
    pub font_type: String,
    /// Font name
    pub base_font: Option<String>,
    /// Font encoding
    pub encoding: Option<String>,
    /// Whether font is embedded
    pub embedded: bool,
    /// Font descriptor reference
    pub font_descriptor: Option<ObjectReference>,
}

/// Font type enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FontType {
    Type1,
    TrueType,
    Type0,
    Type3,
    CIDFontType0,
    CIDFontType2,
    Unknown,
}

/// Font metrics information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontMetrics {
    pub ascent: f32,
    pub descent: f32,
    pub cap_height: f32,
    pub x_height: f32,
    pub font_bbox: Rectangle,
}

/// Action type enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionType {
    JavaScript,
    GoTo,
    URI,
    Launch,
}

/// Color enumeration for watermarks and graphics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Color {
    /// RGB color
    Rgb { red: f64, green: f64, blue: f64 },
    /// CMYK color
    Cmyk { cyan: f64, magenta: f64, yellow: f64, black: f64 },
    /// Grayscale color
    Gray { gray: f64 },
}

/// Blend mode enumeration for watermarks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlendMode {
    Normal,
    Multiply,
    Screen,
    Overlay,
}

/// Object type enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObjectType {
    Catalog, Pages, Page, Font, Image, Form,
    Annotation, Action, Outlines, Metadata,
    ExtGState, ColorSpace, Pattern, Shading,
    OptionalContent, StructureElement,
    FileSpecification, EmbeddedFile, Stream, Dictionary,
}

impl Display for ObjectType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ObjectType::Catalog => write!(f, "Catalog"),
            ObjectType::Pages => write!(f, "Pages"),
            ObjectType::Page => write!(f, "Page"),
            ObjectType::Font => write!(f, "Font"),
            ObjectType::Image => write!(f, "Image"),
            ObjectType::Form => write!(f, "Form"),
            ObjectType::Annotation => write!(f, "Annotation"),
            ObjectType::Action => write!(f, "Action"),
            ObjectType::Outlines => write!(f, "Outlines"),
            ObjectType::Metadata => write!(f, "Metadata"),
            ObjectType::ExtGState => write!(f, "ExtGState"),
            ObjectType::ColorSpace => write!(f, "ColorSpace"),
            ObjectType::Pattern => write!(f, "Pattern"),
            ObjectType::Shading => write!(f, "Shading"),
            ObjectType::OptionalContent => write!(f, "OptionalContent"),
            ObjectType::StructureElement => write!(f, "StructureElement"),
            ObjectType::FileSpecification => write!(f, "FileSpecification"),
            ObjectType::EmbeddedFile => write!(f, "EmbeddedFile"),
            ObjectType::Stream => write!(f, "Stream"),
            ObjectType::Dictionary => write!(f, "Dictionary"),
        }
    }
}

/// Font style enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FontStyle {
    Regular,
    Bold,
    Italic,
    BoldItalic,
}

/// Font encoding enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FontEncoding {
    StandardEncoding,
    MacRomanEncoding,
    WinAnsiEncoding,
    PDFDocEncoding,
}

impl Display for FontEncoding {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            FontEncoding::StandardEncoding => write!(f, "StandardEncoding"),
            FontEncoding::MacRomanEncoding => write!(f, "MacRomanEncoding"),
            FontEncoding::WinAnsiEncoding => write!(f, "WinAnsiEncoding"),
            FontEncoding::PDFDocEncoding => write!(f, "PDFDocEncoding"),
        }
    }
}

/// Image information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    /// Image object reference
    pub object_ref: ObjectReference,
    /// Image width in pixels
    pub width: u32,
    /// Image height in pixels
    pub height: u32,
    /// Bits per component
    pub bits_per_component: u8,
    /// Color space
    pub color_space: String,
    /// Image filters applied
    pub filters: Vec<StreamFilter>,
    /// Whether image has alpha channel
    pub has_alpha: bool,
    /// Image data size in bytes
    pub data_size: u64,
}

/// Content stream information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentStreamInfo {
    /// Content stream object reference
    pub object_ref: ObjectReference,
    /// Associated page reference
    pub page_ref: Option<ObjectReference>,
    /// Stream length
    pub length: u64,
    /// Filters applied to stream
    pub filters: Vec<StreamFilter>,
    /// Content operators used
    pub operators: HashSet<String>,
    /// Referenced resources
    pub resources: Vec<ObjectReference>,
}

/// Embedded file information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedFileInfo {
    /// Embedded file object reference
    pub object_ref: ObjectReference,
    /// File name
    pub filename: Option<String>,
    /// File size
    pub size: Option<u64>,
    /// MIME type
    pub mime_type: Option<String>,
    /// Creation date
    pub creation_date: Option<String>,
    /// Modification date
    pub modification_date: Option<String>,
    /// Checksum
    pub checksum: Option<String>,
}

/// JavaScript information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaScriptInfo {
    /// JavaScript object reference
    pub object_ref: ObjectReference,
    /// JavaScript code snippet (first 1000 chars)
    pub code_snippet: String,
    /// Code size in bytes
    pub code_size: u64,
    /// Suspicious patterns detected
    pub suspicious_patterns: Vec<String>,
    /// Associated action trigger
    pub trigger: Option<String>,
}

/// Suspicious object information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousObjectInfo {
    /// Suspicious object reference
    pub object_ref: ObjectReference,
    /// Suspicion reasons
    pub suspicion_reasons: Vec<String>,
    /// Risk level assessment
    pub risk_level: RiskLevel,
    /// Recommended action
    pub recommended_action: RecommendedAction,
    /// Additional context
    pub context: String,
}

/// Risk level assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    /// Low risk
    Low,
    /// Medium risk
    Medium,
    /// High risk
    High,
    /// Critical risk
    Critical,
}

/// Recommended action for suspicious objects
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendedAction {
    /// Monitor but no action needed
    Monitor,
    /// Investigate further
    Investigate,
    /// Remove or quarantine
    Remove,
    /// Replace with safe version
    Replace,
    /// Block completely
    Block,
}

//=============================================================================
// STREAM FILTER AND COMPRESSION STRUCTURES
//=============================================================================

/// Stream filter types and parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamFilter {
    /// ASCII85 encoding
    Ascii85Decode,
    /// ASCIIHex encoding
    AsciiHexDecode,
    /// Flate/ZIP compression
    FlateDecode {
        /// Predictor value
        predictor: Option<u8>,
        /// Colors per sample
        colors: Option<u8>,
        /// Bits per component
        bits_per_component: Option<u8>,
        /// Columns per row
        columns: Option<u16>,
    },
    /// LZW compression
    LzwDecode {
        /// Predictor value
        predictor: Option<u8>,
        /// Early change flag
        early_change: Option<bool>,
    },
    /// RunLength encoding
    RunLengthDecode,
    /// CCITTFax compression
    CcittFaxDecode {
        /// K parameter
        k: Option<i16>,
        /// End of line flag
        end_of_line: Option<bool>,
        /// Encoded byte align
        encoded_byte_align: Option<bool>,
        /// Columns
        columns: Option<u16>,
        /// Rows
        rows: Option<u16>,
        /// End of block flag
        end_of_block: Option<bool>,
        /// Black is 1 flag
        black_is_1: Option<bool>,
        /// Damaged rows before error
        damaged_rows_before_error: Option<u16>,
    },
    /// DCT (JPEG) compression
    DctDecode {
        /// Color transform
        color_transform: Option<u8>,
    },
    /// JBIG2 compression
    Jbig2Decode {
        /// Global segments
        jbig2_globals: Option<ObjectReference>,
    },
    /// JPX (JPEG2000) compression
    JpxDecode,
    /// Crypt filter
    Crypt {
        /// Crypt filter name
        name: Option<String>,
    },
    /// Custom filter
    Custom {
        /// Filter name
        name: String,
        /// Filter parameters
        params: HashMap<String, String>,
    },
}

/// Decode parameters for stream filters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodeParams {
    /// Parameters for each filter
    pub params: Vec<HashMap<String, DecodeParam>>,
}

/// Individual decode parameter value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecodeParam {
    /// Integer parameter
    Integer(i64),
    /// Boolean parameter
    Boolean(bool),
    /// Name parameter
    Name(String),
    /// Array parameter
    Array(Vec<DecodeParam>),
    /// Object reference parameter
    Reference(ObjectReference),
}

//=============================================================================
// INCREMENTAL UPDATE AND VERSION CONTROL
//=============================================================================

/// Incremental update chain data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateChainData {
    /// All incremental updates in chronological order
    pub updates: Vec<IncrementalUpdate>,
    /// Original document state (before updates)
    pub original_state: OriginalDocumentState,
    /// Update chain validation status
    pub chain_integrity: ChainIntegrity,
}

/// Individual incremental update information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncrementalUpdate {
    /// Update sequence number (0 = original, 1+ = updates)
    pub update_number: u32,
    /// Byte offset where update begins
    pub start_offset: u64,
    /// Size of update section in bytes
    pub size: u64,
    /// Xref table for this update
    pub xref_data: XRefData,
    /// Trailer for this update
    pub trailer_data: TrailerData,
    /// Objects modified in this update
    pub modified_objects: Vec<ObjectReference>,
    /// Objects added in this update
    pub added_objects: Vec<ObjectReference>,
    /// Objects deleted in this update
    pub deleted_objects: Vec<ObjectReference>,
    /// Timestamp of update (if determinable)
    pub update_timestamp: Option<String>,
    /// Tool signature for update (if detectable)
    pub update_tool: Option<String>,
    /// Purpose of update (if determinable)
    pub update_purpose: Option<UpdatePurpose>,
}

/// Purpose classification for incremental updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpdatePurpose {
    /// Form filling
    FormFilling,
    /// Digital signature
    DigitalSignature,
    /// Annotation addition
    AnnotationAddition,
    /// Metadata modification
    MetadataModification,
    /// Content modification
    ContentModification,
    /// Security changes
    SecurityChanges,
    /// Tool processing
    ToolProcessing,
    /// Unknown purpose
    Unknown,
}

/// Original document state information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginalDocumentState {
    /// Original file size before updates
    pub original_size: u64,
    /// Original object count
    pub original_object_count: u32,
    /// Original trailer data
    pub original_trailer: TrailerData,
    /// Original document metadata
    pub original_metadata: DocumentMetadata,
}

/// Update chain integrity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainIntegrity {
    /// Whether chain is valid and consistent
    pub is_valid: bool,
    /// Integrity check errors
    pub errors: Vec<String>,
    /// Integrity check warnings
    pub warnings: Vec<String>,
    /// Cross-reference consistency
    pub xref_consistency: bool,
    /// Object reference consistency
    pub object_ref_consistency: bool,
}

impl Default for UpdateChainData {
    fn default() -> Self {
        Self {
            updates: Vec::new(),
            original_state: OriginalDocumentState {
                original_size: 0,
                original_object_count: 0,
                original_trailer: TrailerData::default(),
                original_metadata: DocumentMetadata::default(),
            },
            chain_integrity: ChainIntegrity {
                is_valid: true,
                errors: Vec::new(),
                warnings: Vec::new(),
                xref_consistency: true,
                object_ref_consistency: true,
            },
        }
    }
}

//=============================================================================
// FORM FIELD STRUCTURES
//=============================================================================

/// Form field data (structure only, no values for security)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormFieldData {
    /// All form fields in document
    pub fields: Vec<FormField>,
    /// Form submission actions
    pub submit_actions: Vec<SubmitAction>,
    /// Form validation scripts
    pub validation_scripts: Vec<ValidationScript>,
    /// Form field hierarchy
    pub field_hierarchy: FormFieldHierarchy,
    /// AcroForm dictionary reference
    pub acroform_ref: Option<ObjectReference>,
}

/// Individual form field information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormField {
    /// Field object reference
    pub object_ref: ObjectReference,
    /// Field name (partial and fully qualified)
    pub field_name: FieldName,
    /// Field type
    pub field_type: FormFieldType,
    /// Field flags
    pub flags: FormFieldFlags,
    /// Field coordinates and appearance
    pub geometry: Option<FieldGeometry>,
    /// Default value (structure only, not actual value)
    pub default_value_type: Option<ValueType>,
    /// Parent field reference
    pub parent_ref: Option<ObjectReference>,
    /// Child field references
    pub children_refs: Vec<ObjectReference>,
    /// Annotation reference (for widget)
    pub widget_ref: Option<ObjectReference>,
}

/// Form field name information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldName {
    /// Partial field name
    pub partial_name: Option<String>,
    /// Fully qualified field name
    pub full_name: String,
    /// Alternate field name
    pub alternate_name: Option<String>,
    /// Mapping name
    pub mapping_name: Option<String>,
}

/// Form field types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FormFieldType {
    /// Text field
    Text {
        /// Maximum length
        max_length: Option<u32>,
        /// Multiline flag
        multiline: bool,
        /// Password flag
        password: bool,
    },
    /// Button field (pushbutton, checkbox, radio)
    Button {
        /// Button style
        style: ButtonStyle,
        /// Radio group (for radio buttons)
        radio_group: Option<String>,
    },
    /// Choice field (list, combo)
    Choice {
        /// Choice style
        style: ChoiceStyle,
        /// Available options
        options: Vec<ChoiceOption>,
        /// Multiple selection allowed
        multiple_select: bool,
    },
    /// Signature field
    Signature {
        /// Signature flags
        sig_flags: u32,
        /// Signature appearance
        appearance_type: SignatureAppearance,
    },
}

/// Button field styles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ButtonStyle {
    /// Push button
    PushButton,
    /// Checkbox
    CheckBox,
    /// Radio button
    Radio,
}

/// Choice field styles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChoiceStyle {
    /// List box
    List,
    /// Combo box
    Combo,
}

/// Choice option information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChoiceOption {
    /// Export value
    pub export_value: String,
    /// Display text
    pub display_text: Option<String>,
    /// Option index
    pub index: u32,
}

/// Signature appearance types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureAppearance {
    /// No appearance
    NoAppearance,
    /// Description only
    Description,
    /// Graphic and description
    GraphicAndDescription,
    /// Graphic only
    GraphicOnly,
}

/// Form field flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormFieldFlags {
    /// Read only flag
    pub readonly: bool,
    /// Required flag
    pub required: bool,
    /// No export flag
    pub no_export: bool,
    /// Raw flag bits
    pub raw_flags: u32,
}

/// Field geometry and positioning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldGeometry {
    /// Field rectangle coordinates
    pub rect: Rectangle,
    /// Page number containing field
    pub page_number: u32,
    /// Rotation angle
    pub rotation: Option<i16>,
    /// Border style
    pub border_style: Option<BorderStyle>,
}

/// Value type classification (not actual values)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValueType {
    /// Text value
    Text,
    /// Numeric value
    Number,
    /// Date value
    Date,
    /// Boolean value
    Boolean,
    /// Choice selection
    Choice,
    /// Signature
    Signature,
}

/// Submit action information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitAction {
    /// Action object reference
    pub object_ref: ObjectReference,
    /// Submit URL
    pub url: String,
    /// Submit method
    pub method: SubmitMethod,
    /// Fields to submit
    pub fields: Vec<String>,
    /// Submit flags
    pub flags: u32,
}

/// Submit methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubmitMethod {
    /// POST method
    Post,
    /// GET method
    Get,
    /// FDF format
    Fdf,
    /// HTML form
    Html,
}

/// Validation script information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationScript {
    /// Script object reference
    pub object_ref: ObjectReference,
    /// Associated field reference
    pub field_ref: ObjectReference,
    /// Script trigger event
    pub trigger: ScriptTrigger,
    /// Script language
    pub language: ScriptLanguage,
    /// Script size in bytes
    pub script_size: u64,
}

/// Script trigger events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScriptTrigger {
    /// Field validation
    Validate,
    /// Field calculation
    Calculate,
    /// Field formatting
    Format,
    /// Keystroke event
    Keystroke,
    /// Focus event
    Focus,
    /// Blur event
    Blur,
}

/// Script languages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScriptLanguage {
    /// JavaScript
    JavaScript,
    /// FormCalc
    FormCalc,
    /// VBScript
    VbScript,
    /// Unknown language
    Unknown(String),
}

/// Form field hierarchy structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormFieldHierarchy {
    /// Root level fields
    pub root_fields: Vec<ObjectReference>,
    /// Field parent-child relationships
    pub relationships: HashMap<ObjectReference, Vec<ObjectReference>>,
    /// Maximum hierarchy depth
    pub max_depth: u32,
}

impl Default for FormFieldData {
    fn default() -> Self {
        Self {
            fields: Vec::new(),
            submit_actions: Vec::new(),
            validation_scripts: Vec::new(),
            field_hierarchy: FormFieldHierarchy {
                root_fields: Vec::new(),
                relationships: HashMap::new(),
                max_depth: 0,
            },
            acroform_ref: None,
        }
    }
}

//=============================================================================
// ANNOTATION STRUCTURES
//=============================================================================

/// Annotation data and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotationData {
    /// All annotations in document
    pub annotations: Vec<Annotation>,
    /// Annotation statistics
    pub statistics: AnnotationStatistics,
    /// Annotation appearances
    pub appearances: Vec<AnnotationAppearance>,
}

/// Individual annotation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    /// Annotation object reference
    pub object_ref: ObjectReference,
    /// Annotation type
    pub annotation_type: AnnotationType,
    /// Annotation rectangle
    pub rect: Rectangle,
    /// Associated page reference
    pub page_ref: ObjectReference,
    /// Annotation flags
    pub flags: AnnotationFlags,
    /// Annotation content/text
    pub contents: Option<String>,
    /// Annotation title/author
    pub title: Option<String>,
    /// Creation date
    pub creation_date: Option<String>,
    /// Modification date
    pub modification_date: Option<String>,
    /// Whether annotation appears original to document
    pub is_original: bool,
    /// Tool signature (if detectable)
    pub tool_signature: Option<String>,
    /// Additional properties
    pub properties: HashMap<String, String>,
}

/// Annotation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnnotationType {
    /// Text annotation
    Text,
    /// Link annotation
    Link {
        /// Link destination
        destination: LinkDestination,
    },
    /// Free text annotation
    FreeText {
        /// Text formatting
        formatting: TextFormatting,
    },
    /// Line annotation
    Line {
        /// Line endpoints
        endpoints: (Point, Point),
        /// Line style
        style: LineStyle,
    },
    /// Square annotation
    Square {
        /// Border style
        border: BorderStyle,
    },
    /// Circle annotation
    Circle {
        /// Border style
        border: BorderStyle,
    },
    /// Polygon annotation
    Polygon {
        /// Polygon vertices
        vertices: Vec<Point>,
    },
    /// Polyline annotation
    PolyLine {
        /// Polyline vertices
        vertices: Vec<Point>,
    },
    /// Highlight annotation
    Highlight {
        /// Highlighted text quads
        quads: Vec<TextQuad>,
    },
    /// Underline annotation
    Underline {
        /// Underlined text quads
        quads: Vec<TextQuad>,
    },
    /// Squiggly annotation
    Squiggly {
        /// Squiggly text quads
        quads: Vec<TextQuad>,
    },
    /// Strike out annotation
    StrikeOut {
        /// Strike out text quads
        quads: Vec<TextQuad>,
    },
    /// Stamp annotation
    Stamp {
        /// Stamp name
        name: String,
    },
    /// Caret annotation
    Caret,
    /// Ink annotation
    Ink {
        /// Ink paths
        paths: Vec<InkPath>,
    },
    /// Popup annotation
    Popup {
        /// Parent annotation reference
        parent_ref: ObjectReference,
    },
    /// File attachment annotation
    FileAttachment {
        /// Attached file reference
        file_ref: ObjectReference,
    },
    /// Sound annotation
    Sound {
        /// Sound object reference
        sound_ref: ObjectReference,
    },
    /// Movie annotation
    Movie {
        /// Movie object reference
        movie_ref: ObjectReference,
    },
    /// Widget annotation (form field)
    Widget {
        /// Associated form field reference
        field_ref: ObjectReference,
    },
    /// Screen annotation
    Screen {
        /// Screen action
        action: Option<String>,
    },
    /// Printer mark annotation
    PrinterMark,
    /// Trap net annotation
    TrapNet,
    /// Watermark annotation
    Watermark {
        /// Watermark properties
        properties: WatermarkProperties,
    },
    /// 3D annotation
    ThreeD {
        /// 3D artwork reference
        artwork_ref: ObjectReference,
    },
    /// Redact annotation
    Redact {
        /// Overlay text
        overlay_text: Option<String>,
    },
}

/// Link destination types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LinkDestination {
    /// Internal page destination
    Page {
        /// Target page number
        page: u32,
        /// View specification
        view: PageView,
    },
    /// Named destination
    Named {
        /// Destination name
        name: String,
    },
    /// External URL
    Url {
        /// Target URL
        url: String,
    },
    /// File launch
    Launch {
        /// File path
        path: String,
        /// Launch parameters
        params: Option<String>,
    },
}

/// Page view specifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PageView {
    /// Fit page in window
    Fit,
    /// Fit page width
    FitH { top: Option<f64> },
    /// Fit page height
    FitV { left: Option<f64> },
    /// Fit rectangle
    FitR { rect: Rectangle },
    /// Fit bounding box
    FitB,
    /// Fit bounding box width
    FitBH { top: Option<f64> },
    /// Fit bounding box height
    FitBV { left: Option<f64> },
    /// XYZ positioning
    Xyz { 
        left: Option<f64>, 
        top: Option<f64>, 
        zoom: Option<f64> 
    },
}

/// Text formatting for annotations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextFormatting {
    /// Font name
    pub font_name: Option<String>,
    /// Font size
    pub font_size: Option<f64>,
    /// Text color
    pub text_color: Option<Color>,
    /// Text alignment
    pub alignment: Option<TextAlignment>,
    /// Bold flag
    pub bold: bool,
    /// Italic flag
    pub italic: bool,
}

/// Text alignment options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TextAlignment {
    /// Left aligned
    Left,
    /// Center aligned
    Center,
    /// Right aligned
    Right,
    /// Justified
    Justify,
}

/// Line style information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineStyle {
    /// Line width
    pub width: f64,
    /// Line color
    pub color: Option<Color>,
    /// Line dash pattern
    pub dash_pattern: Option<Vec<f64>>,
    /// Line cap style
    pub cap_style: CapStyle,
    /// Line join style
    pub join_style: JoinStyle,
}

/// Line cap styles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CapStyle {
    /// Butt cap
    Butt,
    /// Round cap
    Round,
    /// Square cap
    Square,
}

/// Line join styles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JoinStyle {
    /// Miter join
    Miter,
    /// Round join
    Round,
    /// Bevel join
    Bevel,
}

/// Border style information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BorderStyle {
    /// Border width
    pub width: f64,
    /// Border style type
    pub style: BorderStyleType,
    /// Border color
    pub color: Option<Color>,
    /// Dash pattern
    pub dash_pattern: Option<Vec<f64>>,
}

/// Border style types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BorderStyleType {
    /// Solid border
    Solid,
    /// Dashed border
    Dashed,
    /// Beveled border
    Beveled,
    /// Inset border
    Inset,
    /// Underline border
    Underline,
}

/// Text quad for text markup annotations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextQuad {
    /// Bottom-left corner
    pub bottom_left: Point,
    /// Bottom-right corner
    pub bottom_right: Point,
    /// Top-left corner
    pub top_left: Point,
    /// Top-right corner
    pub top_right: Point,
}

/// Ink path for ink annotations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InkPath {
    /// Path points
    pub points: Vec<Point>,
    /// Path properties
    pub properties: InkPathProperties,
}

/// Ink path properties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InkPathProperties {
    /// Line width
    pub width: f64,
    /// Line color
    pub color: Option<Color>,
    /// Opacity
    pub opacity: Option<f64>,
}

/// Watermark properties for watermark annotations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatermarkProperties {
    /// Watermark text
    pub text: Option<String>,
    /// Watermark opacity
    pub opacity: f64,
    /// Watermark rotation
    pub rotation: Option<f64>,
    /// Watermark scale
    pub scale: Option<f64>,
}

/// Annotation flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotationFlags {
    /// Invisible flag
    pub invisible: bool,
    /// Hidden flag
    pub hidden: bool,
    /// Print flag
    pub print: bool,
    /// No zoom flag
    pub no_zoom: bool,
    /// No rotate flag
    pub no_rotate: bool,
    /// No view flag
    pub no_view: bool,
    /// Read only flag
    pub read_only: bool,
    /// Locked flag
    pub locked: bool,
    /// Toggle no view flag
    pub toggle_no_view: bool,
    /// Locked contents flag
    pub locked_contents: bool,
    /// Raw flag bits
    pub raw_flags: u32,
}

/// Annotation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotationStatistics {
    /// Total annotation count
    pub total_count: u32,
    /// Count by type
    pub count_by_type: HashMap<String, u32>,
    /// Count by page
    pub count_by_page: HashMap<u32, u32>,
    /// Average annotation size
    pub average_size: f64,
    /// Modification date range
    pub date_range: Option<(String, String)>,
}

impl Default for AnnotationData {
    fn default() -> Self {
        Self {
            annotations: Vec::new(),
            statistics: AnnotationStatistics {
                total_count: 0,
                count_by_type: HashMap::new(),
                count_by_page: HashMap::new(),
                average_size: 0.0,
                date_range: None,
            },
            appearances: Vec::new(),
        }
    }
}

/// Annotation appearance information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotationAppearance {
    /// Annotation reference
    pub annotation_ref: ObjectReference,
    /// Appearance streams
    pub appearance_streams: Vec<AppearanceStream>,
    /// Appearance state
    pub appearance_state: Option<String>,
}

/// Appearance stream information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppearanceStream {
    /// Stream object reference
    pub stream_ref: ObjectReference,
    /// Appearance type
    pub appearance_type: AppearanceType,
    /// Stream bounding box
    pub bbox: Option<Rectangle>,
    /// Transformation matrix
    pub matrix: Option<TransformationMatrix>,
}

/// Appearance types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AppearanceType {
    /// Normal appearance
    Normal,
    /// Rollover appearance
    Rollover,
    /// Down appearance
    Down,
}

//=============================================================================
// OBJECT STREAM STRUCTURES (PDF 1.5+)
//=============================================================================

/// Object stream data for compressed objects
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectStreamData {
    /// All object streams in document
    pub object_streams: Vec<ObjectStream>,
    /// Object stream statistics
    pub statistics: ObjectStreamStatistics,
}

/// Individual object stream information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectStream {
    /// Object stream reference
    pub stream_ref: ObjectReference,
    /// Number of objects in stream
    pub object_count: u32,
    /// First object offset within stream
    pub first_object_offset: u64,
    /// Objects contained in stream
    pub contained_objects: Vec<ObjectReference>,
    /// Stream compression filters
    pub filters: Vec<StreamFilter>,
    /// Stream length
    pub stream_length: u64,
    /// Extends reference (if extends another object stream)
    pub extends_ref: Option<ObjectReference>,
}

/// Object stream statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectStreamStatistics {
    /// Total object stream count
    pub total_streams: u32,
    /// Total compressed objects
    pub total_compressed_objects: u32,
    /// Compression ratio achieved
    pub compression_ratio: f64,
    /// Average objects per stream
    pub average_objects_per_stream: f64,
}

impl Default for ObjectStreamData {
    fn default() -> Self {
        Self {
            object_streams: Vec::new(),
            statistics: ObjectStreamStatistics {
                total_streams: 0,
                total_compressed_objects: 0,
                compression_ratio: 1.0,
                average_objects_per_stream: 0.0,
            },
        }
    }
}

//=============================================================================
// LINEARIZATION STRUCTURES
//=============================================================================

/// Linearization data for optimized PDFs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinearizationData {
    /// Linearization parameter dictionary
    pub parameter_dict: LinearizationParameters,
    /// Hint tables
    pub hint_tables: Vec<HintTable>,
    /// Page tree linearization info
    pub page_linearization: PageLinearizationInfo,
    /// Linearization validation status
    pub validation_status: LinearizationValidation,
}

/// Linearization parameters
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LinearizationParameters {
    /// File length
    pub file_length: u64,
    /// Primary hint stream offset
    pub hint_offset: u64,
    /// Primary hint stream length
    pub hint_length: u64,
    /// Main cross-reference table offset
    pub main_xref_offset: u64,
    /// First page number
    pub first_page: u32,
    /// Number of pages
    pub page_count: u32,
    /// First page object number
    pub first_page_object: u32,
    /// First page end offset
    pub first_page_end: u64,
}

/// Hint table information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HintTable {
    /// Hint table type
    pub table_type: HintTableType,
    /// Table offset
    pub offset: u64,
    /// Table length
    pub length: u64,
    /// Table data (parsed)
    pub data: HintTableData,
}

/// Hint table types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HintTableType {
    /// Page offset hint table
    PageOffset,
    /// Shared object hint table
    SharedObject,
    /// Thumbnail hint table
    Thumbnail,
    /// Outline hint table
    Outline,
    /// Thread hint table
    Thread,
}

/// Hint table data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HintTableData {
    /// Page offset hints
    PageOffset(PageOffsetHints),
    /// Shared object hints
    SharedObject(SharedObjectHints),
    /// Other hint data
    Other(Vec<u8>),
}

/// Page offset hint information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageOffsetHints {
    /// Least number of objects in a page
    pub least_objects: u32,
    /// Location of first page's page object
    pub first_page_offset: u64,
    /// Number of bits for object number delta
    pub bits_per_object_delta: u8,
    /// Least length of a page
    pub least_page_length: u32,
    /// Number of bits for page length delta
    pub bits_per_page_length_delta: u8,
    /// Page hint entries
    pub page_hints: Vec<PageHint>,
}

/// Individual page hint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageHint {
    /// Number of objects delta
    pub objects_delta: u32,
    /// Page length delta
    pub length_delta: u32,
    /// Number of shared objects
    pub shared_objects: u32,
    /// Shared object identifiers
    pub shared_object_ids: Vec<u32>,
    /// Numerator for fraction
    pub numerator: u32,
    /// Denominator for fraction
    pub denominator: u32,
}

/// Shared object hint information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedObjectHints {
    /// Object number of first shared object group
    pub first_shared_object: u32,
    /// Location of first shared object group
    pub first_shared_offset: u64,
    /// Number of shared object groups
    pub shared_group_count: u32,
    /// Number of bits for group length
    pub bits_per_group_length: u8,
    /// Least length of a group
    pub least_group_length: u32,
    /// Shared object group hints
    pub group_hints: Vec<SharedObjectGroupHint>,
}

/// Shared object group hint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedObjectGroupHint {
    /// Group length delta
    pub length_delta: u32,
    /// Signature flags
    pub signature: u32,
    /// Number of objects in group
    pub object_count: u16,
    /// Number of bits for object number delta
    pub bits_per_object_delta: u8,
    /// Least object number
    pub least_object_number: u32,
}

/// Page linearization information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PageLinearizationInfo {
    /// Page loading order
    pub page_order: Vec<u32>,
    /// Page dependencies
    pub page_dependencies: HashMap<u32, Vec<u32>>,
    /// Shared resources by page
    pub shared_resources: HashMap<u32, Vec<ObjectReference>>,
}

/// Linearization validation status
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LinearizationValidation {
    /// Whether linearization is valid
    pub is_valid: bool,
    /// Validation errors
    pub errors: Vec<String>,
    /// Validation warnings
    pub warnings: Vec<String>,
    /// Hint table consistency
    pub hint_consistency: bool,
}

//=============================================================================
// FORENSIC MARKER AND DETECTION STRUCTURES
//=============================================================================

/// Forensic markers for watermark and tool detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicMarkers {
    /// Detected watermarks with analysis
    pub watermarks: Vec<WatermarkDetection>,
    /// Third-party tool signatures found
    pub tool_signatures: Vec<ToolSignature>,
    /// Digital signature information
    pub digital_signatures: Vec<DigitalSignatureInfo>,
    /// Suspicious patterns detected
    pub suspicious_patterns: Vec<SuspiciousPattern>,
    /// Document authenticity indicators
    pub authenticity_indicators: AuthenticityIndicators,
    /// Tampering evidence
    pub tampering_evidence: Vec<TamperingEvidence>,
    /// Metadata inconsistencies
    pub metadata_inconsistencies: Vec<MetadataInconsistency>,
}

impl Default for ForensicMarkers {
    fn default() -> Self {
        Self {
            watermarks: Vec::new(),
            tool_signatures: Vec::new(),
            digital_signatures: Vec::new(),
            suspicious_patterns: Vec::new(),
            authenticity_indicators: AuthenticityIndicators::default(),
            tampering_evidence: Vec::new(),
            metadata_inconsistencies: Vec::new(),
        }
    }
}

/// Comprehensive watermark detection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatermarkDetection {
    /// Watermark coordinates and positioning
    pub coordinates: Rectangle,
    /// Detected source tool or origin
    pub source_tool: Option<WatermarkSource>,
    /// Whether watermark appears original to document
    pub is_original: bool,
    /// Detection confidence (0.0-1.0)
    pub confidence: f64,
    /// Watermark type classification
    pub watermark_type: WatermarkType,
    /// Watermark content (text/image description)
    pub content: WatermarkContent,
    /// Visual properties
    pub visual_properties: WatermarkVisualProperties,
    /// Associated objects
    pub associated_objects: Vec<ObjectReference>,
    /// Detection method used
    pub detection_method: WatermarkDetectionMethod,
}

/// Watermark source tools
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WatermarkSource {
    /// iLovePDF online tool
    ILovePdf {
        /// Specific signature pattern
        signature: String,
        /// URL pattern found
        url_pattern: Option<String>,
    },
    /// Adobe Acrobat/Reader
    Adobe {
        /// Adobe product version
        product: String,
        /// Version number
        version: Option<String>,
    },
    /// Foxit Reader/PhantomPDF
    Foxit {
        /// Foxit product
        product: String,
        /// License type detected
        license_type: Option<String>,
    },
    /// SmallPDF online tool
    SmallPdf {
        /// Service URL
        service_url: Option<String>,
    },
    /// PDF24 online tool
    Pdf24 {
        /// Tool signature
        signature: String,
    },
    /// Sejda online tool
    Sejda {
        /// Service identifier
        service_id: Option<String>,
    },
    /// PDFCreator
    PdfCreator {
        /// Version information
        version: Option<String>,
    },
    /// LibreOffice/OpenOffice
    LibreOffice {
        /// Suite version
        version: Option<String>,
    },
    /// Microsoft Office
    MicrosoftOffice {
        /// Office version
        version: Option<String>,
        /// Specific application
        application: Option<String>,
    },
    /// Google Docs/Drive
    GoogleDocs,
    /// Custom/company watermark
    Custom {
        /// Organization identifier
        organization: Option<String>,
        /// Watermark purpose
        purpose: Option<String>,
    },
    /// Unknown source
    Unknown {
        /// Detected patterns
        patterns: Vec<String>,
    },
}

/// Watermark type classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WatermarkType {
    /// Text-based watermark
    Text {
        /// Text content
        text: String,
        /// Font information
        font_info: Option<FontInfo>,
    },
    /// Image-based watermark
    Image {
        /// Image dimensions
        dimensions: (u32, u32),
        /// Image format
        format: String,
        /// Image size in bytes
        size_bytes: u64,
    },
    /// Logo watermark
    Logo {
        /// Logo type
        logo_type: LogoType,
        /// Logo dimensions
        dimensions: (u32, u32),
    },
    /// URL/link watermark
    Url {
        /// URL text
        url: String,
        /// Link destination
        destination: Option<String>,
    },
    /// Annotation-based watermark
    Annotation {
        /// Annotation type
        annotation_type: String,
        /// Annotation properties
        properties: HashMap<String, String>,
    },
    /// Overlay watermark
    Overlay {
        /// Overlay properties
        properties: OverlayProperties,
    },
}

/// Logo types for logo watermarks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogoType {
    /// Company logo
    Company,
    /// Tool/software logo
    Software,
    /// Service provider logo
    Service,
    /// Generic logo
    Generic,
}

/// Watermark content information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WatermarkContent {
    /// Text content
    Text {
        /// Text string
        text: String,
        /// Language detected
        language: Option<String>,
        /// Text encoding
        encoding: StringEncoding,
    },
    /// Image content
    Image {
        /// Image description
        description: Option<String>,
        /// Image hash for identification
        hash: String,
        /// Image properties
        properties: ImageProperties,
    },
    /// Mixed content
    Mixed {
        /// Text components
        text_parts: Vec<String>,
        /// Image components
        image_parts: Vec<String>,
    },
    /// Unknown content
    Unknown,
}

/// Watermark visual properties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatermarkVisualProperties {
    /// Opacity/transparency
    pub opacity: Option<f64>,
    /// Color information
    pub color: Option<Color>,
    /// Rotation angle
    pub rotation: Option<f64>,
    /// Scale factor
    pub scale: Option<f64>,
    /// Blend mode
    pub blend_mode: Option<String>,
    /// Z-order/layer
    pub z_order: Option<i32>,
    /// Visibility conditions
    pub visibility: WatermarkVisibility,
}

/// Watermark visibility conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatermarkVisibility {
    /// Visible when printing
    pub print: bool,
    /// Visible on screen
    pub screen: bool,
    /// Visible in specific zoom ranges
    pub zoom_range: Option<(f64, f64)>,
    /// Conditional visibility
    pub conditional: bool,
}

/// Watermark detection methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WatermarkDetectionMethod {
    /// Text pattern analysis
    TextPattern {
        /// Patterns matched
        patterns: Vec<String>,
    },
    /// Coordinate analysis
    CoordinateAnalysis {
        /// Position patterns
        position_patterns: Vec<String>,
    },
    /// Metadata signature analysis
    MetadataSignature {
        /// Signature fields
        signature_fields: Vec<String>,
    },
    /// Visual analysis
    VisualAnalysis {
        /// Visual features detected
        features: Vec<String>,
    },
    /// Object relationship analysis
    ObjectRelationship {
        /// Relationship patterns
        patterns: Vec<String>,
    },
    /// Combined analysis
    Combined {
        /// Methods used
        methods: Vec<String>,
    },
}

/// Third-party tool signature information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSignature {
    /// Tool identification
    pub tool: DetectedTool,
    /// Signature pattern that was matched
    pub signature_pattern: String,
    /// Byte offset or object where signature was found
    pub location: SignatureLocation,
    /// Signature type classification
    pub signature_type: SignatureType,
    /// Detection confidence (0.0-1.0)
    pub confidence: f64,
    /// Additional signature context
    pub context: SignatureContext,
}

/// Detected tool information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectedTool {
    /// PDF creation/editing tools
    PdfTool {
        /// Tool name
        name: String,
        /// Version information
        version: Option<String>,
        /// Tool category
        category: ToolCategory,
    },
    /// Online PDF services
    OnlineService {
        /// Service name
        name: String,
        /// Service URL
        url: Option<String>,
        /// Service type
        service_type: ServiceType,
    },
    /// Operating system tools
    SystemTool {
        /// OS name
        os: String,
        /// Tool name
        tool: String,
        /// Version
        version: Option<String>,
    },
    /// Programming libraries
    Library {
        /// Library name
        name: String,
        /// Language
        language: Option<String>,
        /// Version
        version: Option<String>,
    },
    /// Unknown tool
    Unknown {
        /// Detected patterns
        patterns: Vec<String>,
    },
}

/// Tool categories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ToolCategory {
    /// PDF reader/viewer
    Reader,
    /// PDF editor
    Editor,
    /// PDF creator
    Creator,
    /// PDF converter
    Converter,
    /// PDF printer driver
    Printer,
    /// PDF security tool
    Security,
    /// PDF optimization tool
    Optimizer,
    /// PDF form tool
    FormTool,
    /// PDF annotation tool
    Annotation,
    /// Unknown category
    Unknown,
}

/// Online service types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceType {
    /// Conversion service
    Conversion,
    /// Editing service
    Editing,
    /// Compression service
    Compression,
    /// Security service
    Security,
    /// Merger service
    Merger,
    /// Splitting service
    Splitter,
    /// OCR service
    Ocr,
    /// General service
    General,
}

/// Signature location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureLocation {
    /// Found in metadata fields
    Metadata {
        /// Field name
        field: String,
        /// Object reference
        object_ref: Option<ObjectReference>,
    },
    /// Found in object content
    Object {
        /// Object reference
        object_ref: ObjectReference,
        /// Byte offset within object
        offset: u64,
    },
    /// Found in stream data
    Stream {
        /// Stream object reference
        stream_ref: ObjectReference,
        /// Offset within stream
        offset: u64,
    },
    /// Found in file structure
    Structure {
        /// Structure type
        structure_type: String,
        /// Byte offset in file
        offset: u64,
    },
    /// Found in annotations
    Annotation {
        /// Annotation reference
        annotation_ref: ObjectReference,
    },
    /// Found in forms
    Form {
        /// Form field reference
        field_ref: ObjectReference,
    },
}

/// Signature type classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureType {
    /// Producer field signature
    Producer,
    /// Creator field signature
    Creator,
    /// Custom metadata signature
    CustomMetadata,
    /// Object name signature
    ObjectName,
    /// Stream content signature
    StreamContent,
    /// Comment signature
    Comment,
    /// Font signature
    Font,
    /// Image signature
    Image,
    /// JavaScript signature
    JavaScript,
    /// Form signature
    Form,
    /// Annotation signature
    Annotation,
    /// Watermark signature
    Watermark,
    /// Structural signature
    Structural,
    /// Unknown signature type
    Unknown,
}

/// Signature context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureContext {
    /// Related objects
    pub related_objects: Vec<ObjectReference>,
    /// Processing timestamp (if determinable)
    pub processing_time: Option<String>,
    /// File size before/after processing
    pub size_change: Option<(u64, u64)>,
    /// Quality/compression changes
    pub quality_change: Option<QualityChange>,
    /// Additional context notes
    pub notes: Vec<String>,
}

/// Quality/compression change information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityChange {
    /// Image quality change
    pub image_quality: Option<QualityDelta>,
    /// Compression ratio change
    pub compression: Option<f64>,
    /// Font subsetting changes
    pub font_changes: Vec<String>,
}

/// Quality delta information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityDelta {
    /// Before quality metric
    pub before: f64,
    /// After quality metric
    pub after: f64,
    /// Quality metric type
    pub metric_type: String,
}

/// Digital signature information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalSignatureInfo {
    /// Signature object reference
    pub signature_ref: ObjectReference,
    /// Signature field reference
    pub field_ref: Option<ObjectReference>,
    /// Signature type
    pub signature_type: DigitalSignatureType,
    /// Signature status
    pub status: SignatureStatus,
    /// Signer information
    pub signer: Option<SignerInfo>,
    /// Signing time
    pub signing_time: Option<String>,
    /// Signature algorithm
    pub algorithm: Option<String>,
    /// Certificate chain
    pub certificate_chain: Vec<CertificateInfo>,
    /// Signature coverage
    pub coverage: SignatureCoverage,
}

/// Digital signature types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DigitalSignatureType {
    /// PKCS#7 detached signature
    Pkcs7Detached,
    /// PKCS#7 SHA1 signature
    Pkcs7Sha1,
    /// Adobe PPKLite signature
    AdobePpkLite,
    /// Adobe PPKLite SHA1 signature
    AdobePpkLiteSha1,
    /// ETSI PAdES signature
    EtsiPades,
    /// Unknown signature type
    Unknown(String),
}

/// Signature validation status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureStatus {
    /// Signature is valid
    Valid,
    /// Signature is invalid
    Invalid {
        /// Reason for invalidity
        reason: String,
    },
    /// Signature cannot be verified
    Unverifiable {
        /// Reason for inability to verify
        reason: String,
    },
    /// Signature verification not attempted
    NotVerified,
}

/// Signer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerInfo {
    /// Signer name
    pub name: Option<String>,
    /// Signer email
    pub email: Option<String>,
    /// Signer organization
    pub organization: Option<String>,
    /// Signer location
    pub location: Option<String>,
    /// Signer reason
    pub reason: Option<String>,
    /// Contact information
    pub contact_info: Option<String>,
}

/// Certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// Certificate subject
    pub subject: String,
    /// Certificate issuer
    pub issuer: String,
    /// Certificate serial number
    pub serial_number: String,
    /// Valid from date
    pub valid_from: Option<String>,
    /// Valid to date
    pub valid_to: Option<String>,
    /// Certificate status
    pub status: CertificateStatus,
}

/// Certificate validation status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CertificateStatus {
    /// Certificate is valid
    Valid,
    /// Certificate is expired
    Expired,
    /// Certificate is revoked
    Revoked,
    /// Certificate is unknown
    Unknown,
    /// Certificate cannot be verified
    Unverifiable,
}

/// Signature coverage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureCoverage {
    /// Byte range covered by signature
    pub byte_range: Vec<u64>,
    /// Objects covered by signature
    pub covered_objects: Vec<ObjectReference>,
    /// Whether entire document is covered
    pub covers_entire_document: bool,
    /// Modifications after signing
    pub modifications_after_signing: Vec<ObjectReference>,
}

/// Suspicious pattern detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousPattern {
    /// Pattern type
    pub pattern_type: SuspiciousPatternType,
    /// Pattern description
    pub description: String,
    /// Severity level
    pub severity: SeverityLevel,
    /// Pattern location
    pub location: Vec<PatternLocation>,
    /// Risk assessment
    pub risk_assessment: RiskAssessment,
    /// Recommended actions
    pub recommended_actions: Vec<String>,
}

/// Types of suspicious patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SuspiciousPatternType {
    /// Unusual object relationships
    ObjectRelationship,
    /// Suspicious JavaScript
    JavaScript,
    /// Unusual form fields
    FormField,
    /// Suspicious annotations
    Annotation,
    /// Unusual file attachments
    FileAttachment,
    /// Suspicious encryption
    Encryption,
    /// Unusual metadata
    Metadata,
    /// Suspicious timestamps
    Timestamp,
    /// Unusual structure
    Structure,
    /// Potential malware
    Malware,
    /// Data exfiltration risk
    DataExfiltration,
    /// Unknown pattern
    Unknown,
}

/// Severity levels for patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SeverityLevel {
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

/// Pattern location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternLocation {
    /// Located in specific object
    Object(ObjectReference),
    /// Located in metadata
    Metadata(String),
    /// Located in structure
    Structure(String),
    /// Located in stream
    Stream(ObjectReference),
    /// Located in annotation
    Annotation(ObjectReference),
    /// Located in form
    Form(ObjectReference),
}

/// Risk assessment for patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// Overall risk score (0.0-1.0)
    pub risk_score: f64,
    /// Risk factors identified
    pub risk_factors: Vec<String>,
    /// Mitigation strategies
    pub mitigation_strategies: Vec<String>,
    /// Impact assessment
    pub impact_assessment: ImpactAssessment,
}

/// Impact assessment information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactAssessment {
    /// Potential security impact
    pub security_impact: SecurityImpact,
    /// Potential privacy impact
    pub privacy_impact: PrivacyImpact,
    /// Potential data integrity impact
    pub data_integrity_impact: DataIntegrityImpact,
}

/// Security impact levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityImpact {
    /// No security impact
    None,
    /// Low security impact
    Low,
    /// Medium security impact
    Medium,
    /// High security impact
    High,
    /// Critical security impact
    Critical,
}

/// Privacy impact levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivacyImpact {
    /// No privacy impact
    None,
    /// Low privacy impact
    Low,
    /// Medium privacy impact
    Medium,
    /// High privacy impact
    High,
}

/// Data integrity impact levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataIntegrityImpact {
    /// No data integrity impact
    None,
    /// Low impact
    Low,
    /// Medium impact
    Medium,
    /// High impact
    High,
}

/// Document authenticity indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticityIndicators {
    /// Overall authenticity score (0.0-1.0)
    pub authenticity_score: f64,
    /// Positive authenticity indicators
    pub positive_indicators: Vec<AuthenticityIndicator>,
    /// Negative authenticity indicators
    pub negative_indicators: Vec<AuthenticityIndicator>,
    /// Authenticity assessment
    pub assessment: AuthenticityAssessment,
}

impl Default for AuthenticityIndicators {
    fn default() -> Self {
        Self {
            authenticity_score: 1.0,
            positive_indicators: Vec::new(),
            negative_indicators: Vec::new(),
            assessment: AuthenticityAssessment::Authentic { confidence: 1.0 },
        }
    }
}

/// Individual authenticity indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticityIndicator {
    /// Indicator type
    pub indicator_type: AuthenticityIndicatorType,
    /// Indicator strength
    pub strength: IndicatorStrength,
    /// Indicator description
    pub description: String,
    /// Supporting evidence
    pub evidence: Vec<String>,
}

/// Types of authenticity indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthenticityIndicatorType {
    /// Consistent metadata
    ConsistentMetadata,
    /// Original creation tool
    OriginalTool,
    /// Consistent timestamps
    ConsistentTimestamps,
    /// No third-party modifications
    NoThirdPartyMods,
    /// Digital signature present
    DigitalSignature,
    /// Consistent structure
    ConsistentStructure,
    /// Original fonts
    OriginalFonts,
    /// Consistent encoding
    ConsistentEncoding,
    /// No suspicious patterns
    NoSuspiciousPatterns,
    /// Unknown indicator
    Unknown,
}

/// Indicator strength levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IndicatorStrength {
    /// Weak indicator
    Weak,
    /// Moderate indicator
    Moderate,
    /// Strong indicator
    Strong,
    /// Very strong indicator
    VeryStrong,
}

/// Overall authenticity assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthenticityAssessment {
    /// Document appears authentic
    Authentic {
        /// Confidence level
        confidence: f64,
    },
    /// Document appears modified
    Modified {
        /// Modification type
        modification_type: String,
        /// Confidence level
        confidence: f64,
    },
    /// Document authenticity is questionable
    Questionable {
        /// Reasons for questioning
        reasons: Vec<String>,
    },
    /// Document appears forged
    Forged {
        /// Forgery indicators
        indicators: Vec<String>,
    },
    /// Cannot determine authenticity
    Indeterminate {
        /// Reasons for indeterminacy
        reasons: Vec<String>,
    },
}

/// Tampering evidence information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperingEvidence {
    /// Evidence type
    pub evidence_type: TamperingEvidenceType,
    /// Evidence description
    pub description: String,
    /// Evidence strength
    pub strength: EvidenceStrength,
    /// Evidence location
    pub location: Vec<ObjectReference>,
    /// Supporting data
    pub supporting_data: TamperingEvidenceData,
}

/// Types of tampering evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TamperingEvidenceType {
    /// Inconsistent timestamps
    TimestampInconsistency,
    /// Modified metadata
    MetadataModification,
    /// Object substitution
    ObjectSubstitution,
    /// Content modification
    ContentModification,
    /// Structure modification
    StructureModification,
    /// Signature invalidation
    SignatureInvalidation,
    /// Incremental update anomaly
    IncrementalUpdateAnomaly,
    /// Cross-reference inconsistency
    XrefInconsistency,
    /// Stream modification
    StreamModification,
    /// Unknown tampering
    Unknown,
}

/// Evidence strength levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceStrength {
    /// Weak evidence
    Weak,
    /// Moderate evidence
    Moderate,
    /// Strong evidence
    Strong,
    /// Conclusive evidence
    Conclusive,
}

/// Supporting data for tampering evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TamperingEvidenceData {
    /// Timestamp comparison data
    Timestamps {
        /// Original timestamp
        original: Option<String>,
        /// Modified timestamp
        modified: String,
        /// Time difference
        difference: i64,
    },
    /// Metadata comparison
    Metadata {
        /// Original metadata
        original: HashMap<String, String>,
        /// Modified metadata
        modified: HashMap<String, String>,
    },
    /// Object comparison
    Objects {
        /// Original object data
        original: Vec<u8>,
        /// Modified object data
        modified: Vec<u8>,
    },
    /// Hash comparison
    Hashes {
        /// Original hash
        original: String,
        /// Current hash
        current: String,
    },
    /// Other evidence data
    Other(Vec<u8>),
}

/// Metadata inconsistency information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataInconsistency {
    /// Inconsistency type
    pub inconsistency_type: InconsistencyType,
    /// Fields involved in inconsistency
    pub fields: Vec<String>,
    /// Inconsistency description
    pub description: String,
    /// Severity of inconsistency
    pub severity: InconsistencySeverity,
    /// Possible explanations
    pub possible_explanations: Vec<String>,
}

/// Types of metadata inconsistencies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InconsistencyType {
    /// Timestamp inconsistency
    Timestamp,
    /// Tool version inconsistency
    ToolVersion,
    /// Creation/modification order
    CreationOrder,
    /// Encoding inconsistency
    Encoding,
    /// Language inconsistency
    Language,
    /// Size inconsistency
    Size,
    /// Format version inconsistency
    FormatVersion,
    /// Custom field inconsistency
    CustomField,
    /// Unknown inconsistency
    Unknown,
}

/// Inconsistency severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InconsistencySeverity {
    /// Minor inconsistency
    Minor,
    /// Moderate inconsistency
    Moderate,
    /// Major inconsistency
    Major,
    /// Critical inconsistency
    Critical,
}

//=============================================================================
// FILE PROPERTIES AND VALIDATION STRUCTURES
//=============================================================================

/// File-level properties and hashes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileProperties {
    /// File size in bytes
    pub file_size: u64,
    /// MD5 hash of entire file
    pub md5_hash: String,
    /// SHA1 hash of entire file
    pub sha1_hash: String,
    /// SHA256 hash of entire file
    pub sha256_hash: String,
    /// File creation time (filesystem)
    pub file_created: Option<String>,
    /// File modification time (filesystem)
    pub file_modified: Option<String>,
    /// File permissions (if applicable)
    pub file_permissions: Option<String>,
    /// File path information
    pub file_path: Option<PathBuf>,
    /// MIME type detection
    pub mime_type: Option<String>,
    /// File extension
    pub file_extension: Option<String>,
}

impl Default for FileProperties {
    fn default() -> Self {
        Self {
            file_size: 0,
            md5_hash: String::new(),
            sha1_hash: String::new(),
            sha256_hash: String::new(),
            file_created: None,
            file_modified: None,
            file_permissions: None,
            file_path: None,
            mime_type: None,
            file_extension: None,
        }
    }
}

/// File information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    /// File path
    pub path: String,
    /// File size in bytes
    pub size: u64,
    /// Last modified time
    pub modified_time: chrono::DateTime<chrono::Utc>,
    /// Whether file is readable
    pub is_readable: bool,
    /// Whether file is writable
    pub is_writable: bool,
    /// Whether file is a PDF
    pub is_pdf: bool,
}

//=============================================================================
// EXTRACTION AND CONFIGURATION STRUCTURES
//=============================================================================

/// Extraction configuration and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionInfo {
    /// Timestamp when extraction was performed
    pub extraction_time: String,
    /// Tool version used for extraction
    pub tool_version: String,
    /// Source file hash for verification
    pub source_file_hash: String,
    /// Extraction configuration used
    pub extraction_config: ExtractionConfig,
    /// Extraction statistics
    pub extraction_stats: ExtractionStatistics,
    /// Extraction warnings
    pub warnings: Vec<String>,
    /// Extraction errors (non-fatal)
    pub errors: Vec<String>,
}

impl Default for ExtractionInfo {
    fn default() -> Self {
        Self {
            extraction_time: String::new(),
            tool_version: String::new(),
            source_file_hash: String::new(),
            extraction_config: ExtractionConfig::default(),
            extraction_stats: ExtractionStatistics::default(),
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }
}



/// Configuration for extraction operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionConfig {
    /// Extract XMP metadata
    pub extract_xmp: bool,
    /// Extract form field structures
    pub extract_forms: bool,
    /// Extract annotation data
    pub extract_annotations: bool,
    /// Perform watermark detection
    pub detect_watermarks: bool,
    /// Perform third-party tool detection
    pub detect_third_party: bool,
    /// Extract object stream data
    pub extract_object_streams: bool,
    /// Analyze incremental updates
    pub analyze_incremental_updates: bool,
    /// Extract linearization data
    pub extract_linearization: bool,
    /// Perform security analysis
    pub security_analysis: bool,
    /// Extract embedded files
    pub extract_embedded_files: bool,
    /// Analyze JavaScript objects
    pub analyze_javascript: bool,
    /// Validate PDF structure
    pub validate_structure: bool,
    /// Deep content analysis
    pub deep_content_analysis: bool,
    /// Forensic signature analysis
    pub forensic_analysis: bool,
    /// Memory usage limit (bytes)
    pub memory_limit: Option<u64>,
    /// Processing timeout (seconds)
    pub timeout: Option<u64>,
    /// Extract metadata
    pub extract_metadata: bool,
    /// Extract structure
    pub extract_structure: bool,
    /// Extract timestamps
    pub extract_timestamps: bool,
    /// Extract forensic markers
    pub extract_forensic_markers: bool,
    /// Extract encryption info
    pub extract_encryption_info: bool,
    /// Deep analysis
    pub deep_analysis: bool,
    /// Memory limit in MB
    pub memory_limit_mb: u64,
    /// Timeout in seconds
    pub timeout_seconds: u64,
}

/// Extraction statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionStatistics {
    /// Objects processed
    pub objects_processed: u32,
    /// Streams analyzed
    pub streams_analyzed: u32,
    /// Metadata fields extracted
    pub metadata_fields: u32,
    /// Watermarks detected
    pub watermarks_detected: u32,
    /// Tool signatures found
    pub tool_signatures: u32,
    /// Processing time in milliseconds
    pub processing_time_ms: u64,
    /// Memory peak usage in bytes
    pub peak_memory_usage: u64,
    /// Bytes processed
    pub bytes_processed: u64,
}

impl Default for ExtractionStatistics {
    fn default() -> Self {
        Self {
            objects_processed: 0,
            streams_analyzed: 0,
            metadata_fields: 0,
            watermarks_detected: 0,
            tool_signatures: 0,
            processing_time_ms: 0,
            peak_memory_usage: 0,
            bytes_processed: 0,
        }
    }
}

//=============================================================================
// INJECTION AND MODIFICATION STRUCTURES
//=============================================================================

/// Context information for injection operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionContext {
    /// Original cross-reference data
    pub original_xref: XRefData,
    /// Info object location (if exists)
    pub info_object_location: Option<XRefEntry>,
    /// Encrypt object location (if exists)
    pub encrypt_object_location: Option<XRefEntry>,
    /// Target file size
    pub target_file_size: u64,
    /// Processing start time
    pub processing_start: SystemTime,
}

/// Configuration for injection operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionConfig {
    /// Strip detected watermarks
    pub strip_watermarks: bool,
    /// Remove third-party signatures
    pub remove_third_party: bool,
    /// Preserve original timestamps exactly
    pub preserve_timestamps: bool,
    /// Rebuild cross-reference table
    pub rebuild_xref: bool,
    /// Validate output PDF
    pub validate_output: bool,
    /// Preserve content integrity
    pub preserve_content: bool,
    /// Update modification date
    pub update_mod_date: bool,
    /// Compress output streams
    pub compress_streams: bool,
    /// Linearize output
    pub linearize_output: bool,
    /// Security settings to apply
    pub security_settings: Option<SecuritySettings>,
}

/// Security settings for injection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    /// Apply encryption
    pub encrypt: bool,
    /// User password
    pub user_password: Option<String>,
    /// Owner password
    pub owner_password: Option<String>,
    /// Permission settings
    pub permissions: PermissionData,
    /// Encryption algorithm
    pub encryption_algorithm: EncryptionAlgorithm,
}

/// Encryption algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    /// 40-bit RC4
    Rc4_40,
    /// 128-bit RC4
    Rc4_128,
    /// 128-bit AES
    Aes128,
    /// 256-bit AES
    Aes256,
}

//=============================================================================
// VALIDATION AND COMPARISON STRUCTURES
//=============================================================================

/// Validation result for PDF operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether PDF structure is valid
    pub is_valid: bool,
    /// Validation errors found
    pub errors: Vec<ValidationError>,
    /// Validation warnings
    pub warnings: Vec<ValidationWarning>,
    /// Forensic signature match (for cloned PDFs)
    pub forensic_match: Option<ForensicMatch>,
    /// Validation statistics
    pub validation_stats: ValidationStatistics,
}

/// Individual validation error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    /// Error code
    pub code: String,
    /// Error message
    pub message: String,
    /// Error severity
    pub severity: ErrorSeverity,
    /// Error location
    pub location: Option<ErrorLocation>,
    /// Suggested fix
    pub suggested_fix: Option<String>,
}

/// Individual validation warning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationWarning {
    /// Warning code
    pub code: String,
    /// Warning message
    pub message: String,
    /// Warning location
    pub location: Option<ErrorLocation>,
    /// Recommendation
    pub recommendation: Option<String>,
}

/// Error severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ErrorSeverity {
    /// Critical error (PDF cannot be processed)
    Critical,
    /// Major error (PDF may not work correctly)
    Major,
    /// Minor error (PDF works but has issues)
    Minor,
    /// Informational (not an error)
    Info,
}

/// Error location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorLocation {
    /// Error in file structure
    FileStructure {
        /// Byte offset
        offset: u64,
    },
    /// Error in specific object
    Object {
        /// Object reference
        object_ref: ObjectReference,
        /// Offset within object
        offset: Option<u64>,
    },
    /// Error in metadata
    Metadata {
        /// Field name
        field: String,
    },
    /// Error in cross-reference table
    XRef {
        /// Entry number
        entry: u32,
    },
    /// Error in trailer
    Trailer,
    /// Error in stream
    Stream {
        /// Stream object reference
        stream_ref: ObjectReference,
    },
    /// Error in security/encryption
    Security,
    /// Error in document structure
    DocumentStructure,
    /// Error in document content
    Content,
}

/// Forensic match information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicMatch {
    /// Whether forensic signatures match
    pub matches: bool,
    /// Match confidence (0.0-1.0)
    pub confidence: f64,
    /// Matching elements
    pub matching_elements: Vec<String>,
    /// Non-matching elements
    pub non_matching_elements: Vec<String>,
    /// Match details
    pub details: ForensicMatchDetails,
}

/// Detailed forensic match information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicMatchDetails {
    /// ID array match
    pub id_match: bool,
    /// Timestamp match
    pub timestamp_match: bool,
    /// Metadata match
    pub metadata_match: bool,
    /// Structure match
    pub structure_match: bool,
    /// Encryption match
    pub encryption_match: bool,
    /// Permission match
    pub permission_match: bool,
}

/// Validation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationStatistics {
    /// Objects validated
    pub objects_validated: u32,
    /// Streams validated
    pub streams_validated: u32,
    /// References validated
    pub references_validated: u32,
    /// Validation time in milliseconds
    pub validation_time_ms: u64,
}

/// Comparison result between two PDFs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonResult {
    /// Whether PDFs are forensically identical
    pub forensically_identical: bool,
    /// Overall similarity score (0.0-1.0)
    pub similarity_score: f64,
    /// Detailed differences found
    pub differences: Vec<ForensicDifference>,
    /// Comparison statistics
    pub comparison_stats: ComparisonStatistics,
    /// Comparison configuration used
    pub comparison_config: ComparisonConfig,
}

/// Individual forensic difference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicDifference {
    /// Type of difference
    pub difference_type: DifferenceType,
    /// Difference description
    pub description: String,
    /// Difference severity
    pub severity: DifferenceSeverity,
    /// Location of difference
    pub location: Option<String>,
    /// Expected value
    pub expected: Option<String>,
    /// Actual value
    pub actual: Option<String>,
    /// Impact assessment
    pub impact: DifferenceImpact,
}

/// Types of forensic differences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DifferenceType {
    /// PDF ID array difference
    IdArray,
    /// Metadata field difference
    Metadata,
    /// Timestamp difference
    Timestamp,
    /// Structural difference
    Structure,
    /// Encryption difference
    Encryption,
    /// Permission difference
    Permission,
    /// Object difference
    Object,
    /// Stream difference
    Stream,
    /// Annotation difference
    Annotation,
    /// Form difference
    Form,
    /// Watermark difference
    Watermark,
    /// Tool signature difference
    ToolSignature,
    /// Unknown difference
    Unknown,
}

/// Severity of differences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DifferenceSeverity {
    /// Critical difference affecting forensic identity
    Critical,
    /// Major difference with significant impact
    Major,
    /// Minor difference with limited impact
    Minor,
    /// Informational difference
    Info,
}

/// Impact of differences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DifferenceImpact {
    /// Breaks forensic matching
    ForensicBreaking,
    /// Affects authenticity assessment
    AuthenticityAffecting,
    /// Cosmetic difference only
    Cosmetic,
    /// No significant impact
    None,
}

/// Comparison statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonStatistics {
    /// Elements compared
    pub elements_compared: u32,
    /// Exact matches found
    pub exact_matches: u32,
    /// Partial matches found
    pub partial_matches: u32,
    /// Complete mismatches
    pub mismatches: u32,
    /// Comparison time in milliseconds
    pub comparison_time_ms: u64,
}

/// Configuration for comparison operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonConfig {
    /// Compare ID arrays
    pub compare_ids: bool,
    /// Compare timestamps
    pub compare_timestamps: bool,
    /// Compare metadata
    pub compare_metadata: bool,
    /// Compare structure
    pub compare_structure: bool,
    /// Compare encryption
    pub compare_encryption: bool,
    /// Compare permissions
    pub compare_permissions: bool,
    /// Compare watermarks
    pub compare_watermarks: bool,
    /// Ignore minor differences
    pub ignore_minor: bool,
    /// Timestamp tolerance in seconds
    pub timestamp_tolerance: u64,
}

//=============================================================================
// CONFIGURATION STRUCTURES - MISSING TYPES
//=============================================================================

/// Validation configuration for PDF operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
    /// Enable strict validation mode
    pub strict_mode: bool,
    /// Validate PDF structure
    pub validate_structure: bool,
    /// Check object references
    pub check_references: bool,
    /// Verify checksums
    pub verify_checksums: bool,
    /// Check compliance with PDF standards
    pub check_compliance: bool,
    /// Report warnings as errors
    pub fail_on_warnings: bool,
    /// Maximum validation time in seconds
    pub max_validation_time: u64,
    /// Validation depth level
    pub validation_depth: ValidationDepth,
}

/// Validation depth levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationDepth {
    /// Surface level validation
    Surface,
    /// Standard validation
    Standard,
    /// Deep validation
    Deep,
    /// Exhaustive validation
    Exhaustive,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: LogLevel,
    /// Enable file logging
    pub file_logging: bool,
    /// Enable console logging
    pub console_logging: bool,
    /// Log file path
    pub log_file_path: PathBuf,
    /// Maximum log file size
    pub max_log_size: u64,
    /// Enable log rotation
    pub log_rotation: bool,
    /// Include detailed error information
    pub detailed_errors: bool,
    /// Log forensic operations
    pub log_forensic_ops: bool,
}

/// Log levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    /// Error level
    Error,
    /// Warning level
    Warn,
    /// Info level
    Info,
    /// Debug level
    Debug,
    /// Trace level
    Trace,
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Maximum memory usage in bytes
    pub max_memory_usage: u64,
    /// Maximum processing time in seconds
    pub max_processing_time: u64,
    /// Enable parallel processing
    pub parallel_processing: bool,
    /// Maximum number of threads
    pub max_threads: u32,
    /// Enable caching
    pub cache_enabled: bool,
    /// Cache size in bytes
    pub cache_size: u64,
    /// Buffer size for I/O operations
    pub buffer_size: usize,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable security analysis
    pub security_analysis: bool,
    /// Scan for malicious content
    pub scan_malicious: bool,
    /// Check digital signatures
    pub verify_signatures: bool,
    /// Validate certificates
    pub validate_certificates: bool,
    /// Check for suspicious patterns
    pub check_suspicious_patterns: bool,
    /// Risk tolerance level
    pub risk_tolerance: RiskTolerance,
}

/// Risk tolerance levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskTolerance {
    /// Very low risk tolerance
    VeryLow,
    /// Low risk tolerance
    Low,
    /// Medium risk tolerance
    Medium,
    /// High risk tolerance
    High,
    /// Very high risk tolerance
    VeryHigh,
}

/// Output configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Output format
    pub format: OutputFormat,
    /// Include verbose information
    pub verbose: bool,
    /// Pretty print JSON output
    pub pretty_print: bool,
    /// Include timestamps in output
    pub include_timestamps: bool,
    /// Compress output files
    pub compress_output: bool,
    /// Output file permissions
    pub file_permissions: Option<u32>,
}

/// Output format types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    /// JSON format
    Json,
    /// YAML format
    Yaml,
    /// XML format
    Xml,
    /// Binary format
    Binary,
    /// Custom format
    Custom(String),
}

/// Tool integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolIntegrationConfig {
    /// Enable external tool validation
    pub enable_external_validation: bool,
    /// QPDF path for validation
    pub qpdf_path: Option<PathBuf>,
    /// PDFtk path for operations
    pub pdftk_path: Option<PathBuf>,
    /// Ghostscript path for validation
    pub ghostscript_path: Option<PathBuf>,
    /// Poppler utils path
    pub poppler_path: Option<PathBuf>,
    /// Tool timeout in seconds
    pub tool_timeout: u64,
}



//=============================================================================
// UTILITY AND HELPER STRUCTURES
//=============================================================================

/// Color representation for PDF elements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfColor {
    /// Color space
    pub color_space: ColorSpace,
    /// Color components
    pub components: Vec<f64>,
    /// Color name (if named color)
    pub name: Option<String>,
}

/// Color space types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ColorSpace {
    /// Device Gray
    DeviceGray,
    /// Device RGB
    DeviceRgb,
    /// Device CMYK
    DeviceCmyk,
    /// Calibrated Gray
    CalGray,
    /// Calibrated RGB
    CalRgb,
    /// Lab color space
    Lab,
    /// ICC-based color space
    IccBased,
    /// Indexed color space
    Indexed,
    /// Pattern color space
    Pattern,
    /// Separation color space
    Separation,
    /// DeviceN color space
    DeviceN,
}

/// Rectangle coordinates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rectangle {
    /// X coordinate
    pub x: f64,
    /// Y coordinate
    pub y: f64,
    /// Width
    pub width: f64,
    /// Height
    pub height: f64,
}

impl Rectangle {
    pub fn new(x: f64, y: f64, width: f64, height: f64) -> Self {
        Self { x, y, width, height }
    }
    
    /// Get rectangle area
    pub fn area(&self) -> f64 {
        self.width * self.height
    }
    
    /// Check if rectangle contains point
    pub fn contains_point(&self, point: &Point) -> bool {
        point.x >= self.x && point.x <= self.x + self.width &&
        point.y >= self.y && point.y <= self.y + self.height
    }
}

impl std::fmt::Display for Rectangle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {}, {}, {})", self.x, self.y, self.width, self.height)
    }
}

/// Point coordinates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Point {
    /// X coordinate
    pub x: f64,
    /// Y coordinate
    pub y: f64,
}

/// Transformation matrix
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformationMatrix {
    /// Matrix elements [a, b, c, d, e, f]
    pub elements: [f64; 6],
}

/// Image properties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageProperties {
    /// Image width
    pub width: u32,
    /// Image height
    pub height: u32,
    /// Bits per component
    pub bits_per_component: u8,
    /// Color space
    pub color_space: String,
    /// Compression method
    pub compression: Option<String>,
    /// Has alpha channel
    pub has_alpha: bool,
    /// Image format
    pub format: ImageFormat,
}

/// Image format types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImageFormat {
    /// JPEG format
    Jpeg,
    /// PNG format
    Png,
    /// TIFF format
    Tiff,
    /// GIF format
    Gif,
    /// BMP format
    Bmp,
    /// JPEG2000 format
    Jpeg2000,
    /// JBIG2 format
    Jbig2,
    /// CCITTFax format
    CcittFax,
    /// Unknown format
    Unknown(String),
}

/// Overlay properties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayProperties {
    /// Overlay type
    pub overlay_type: OverlayType,
    /// Overlay position
    pub position: OverlayPosition,
    /// Overlay opacity
    pub opacity: f64,
    /// Overlay scale
    pub scale: f64,
    /// Overlay rotation
    pub rotation: f64,
}

/// Overlay types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OverlayType {
    /// Text overlay
    Text,
    /// Image overlay
    Image,
    /// Shape overlay
    Shape,
    /// Mixed overlay
    Mixed,
}

/// Overlay positioning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OverlayPosition {
    /// Top-left corner
    TopLeft,
    /// Top-center
    TopCenter,
    /// Top-right corner
    TopRight,
    /// Middle-left
    MiddleLeft,
    /// Center
    Center,
    /// Middle-right
    MiddleRight,
    /// Bottom-left corner
    BottomLeft,
    /// Bottom-center
    BottomCenter,
    /// Bottom-right corner
    BottomRight,
    /// Custom position
    Custom { x: f64, y: f64 },
}

//=============================================================================
// CONSTANTS AND DEFAULTS
//=============================================================================

/// PDF specification constants
pub mod constants {
    /// PDF header signature
    pub const PDF_HEADER_SIGNATURE: &[u8] = b"%PDF-";
    
    /// PDF EOF marker
    pub const PDF_EOF_SIGNATURE: &[u8] = b"%%EOF";
    
    /// XRef table signature
    pub const XREF_SIGNATURE: &[u8] = b"xref";
    
    /// Trailer signature
    pub const TRAILER_SIGNATURE: &[u8] = b"trailer";
    
    /// StartXRef signature
    pub const STARTXREF_SIGNATURE: &[u8] = b"startxref";
    
    /// Stream begin marker
    pub const STREAM_BEGIN: &[u8] = b"stream";
    
    /// Stream end marker
    pub const STREAM_END: &[u8] = b"endstream";
    
    /// Object begin marker
    pub const OBJ_BEGIN: &[u8] = b"obj";
    
    /// Object end marker
    pub const OBJ_END: &[u8] = b"endobj";
    
    /// Known third-party tool signatures
    pub const ILOVEPDF_SIGNATURES: &[&str] = &[
        "iLovePDF.com",
        "iLovePDF",
        "https://www.ilovepdf.com",
    ];
    
    pub const ADOBE_SIGNATURES: &[&str] = &[
        "Adobe Acrobat",
        "Adobe PDF Library",
        "Adobe Acrobat Pro",
        "Adobe Acrobat Reader",
        "Adobe Distiller",
    ];
    
    pub const FOXIT_SIGNATURES: &[&str] = &[
        "Foxit Reader",
        "Foxit PDF Creator",
        "Foxit PhantomPDF",
        "Foxit PDF SDK",
    ];
    
    pub const ONLINE_TOOL_SIGNATURES: &[&str] = &[
        "SmallPDF",
        "PDF24",
        "Sejda",
        "PDFtk",
        "PDFCreator",
    ];
    
    /// PDF permission bit flags (as defined in PDF specification)
    pub const PERM_PRINT: i32 = 1 << 2;
    pub const PERM_MODIFY: i32 = 1 << 3;
    pub const PERM_COPY: i32 = 1 << 4;
    pub const PERM_ADD_NOTES: i32 = 1 << 5;
    pub const PERM_FILL_FORMS: i32 = 1 << 8;
    pub const PERM_EXTRACT_ACCESSIBILITY: i32 = 1 << 9;
    pub const PERM_ASSEMBLE: i32 = 1 << 10;
    pub const PERM_PRINT_HIGH_QUALITY: i32 = 1 << 11;
    
    /// Default configuration values
    pub const DEFAULT_MEMORY_LIMIT: u64 = 512 * 1024 * 1024; // 512 MB
    pub const DEFAULT_TIMEOUT: u64 = 300; // 5 minutes
    pub const DEFAULT_BUFFER_SIZE: usize = 8192; // 8 KB
    pub const MAX_OBJECT_SIZE: u64 = 100 * 1024 * 1024; // 100 MB
    pub const MAX_STRING_LENGTH: usize = 1024 * 1024; // 1 MB
}

//=============================================================================
// DEFAULT IMPLEMENTATIONS
//=============================================================================

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self {
            extract_xmp: true,
            extract_forms: true,
            extract_annotations: true,
            detect_watermarks: true,
            detect_third_party: true,
            extract_object_streams: true,
            analyze_incremental_updates: true,
            extract_linearization: true,
            security_analysis: true,
            extract_embedded_files: true,
            analyze_javascript: true,
            validate_structure: true,
            deep_content_analysis: false,
            forensic_analysis: true,
            memory_limit: Some(constants::DEFAULT_MEMORY_LIMIT),
            timeout: Some(constants::DEFAULT_TIMEOUT),
            extract_metadata: true,
            extract_structure: true,
            extract_timestamps: true,
            extract_forensic_markers: true,
            extract_encryption_info: true,
            deep_analysis: false,
            memory_limit_mb: 512,
            timeout_seconds: 300,
        }
    }
}

impl Default for InjectionConfig {
    fn default() -> Self {
        Self {
            strip_watermarks: true,
            remove_third_party: true,
            preserve_timestamps: true,
            rebuild_xref: true,
            validate_output: true,
            preserve_content: true,
            update_mod_date: false,
            compress_streams: false,
            linearize_output: false,
            security_settings: Some(SecuritySettings {
                encrypt: false,
                user_password: None,
                owner_password: None,
                permissions: PermissionData {
                    print: PermissionLevel::Allowed,
                    modify: PermissionLevel::Allowed,
                    copy: PermissionLevel::Allowed,
                    add_notes: PermissionLevel::Allowed,
                    fill_forms: PermissionLevel::Allowed,
                    extract_accessibility: PermissionLevel::Allowed,
                    assemble: PermissionLevel::Allowed,
                    print_high_quality: PermissionLevel::Allowed,
                    raw_permission_bits: -1,
                    security_revision: Some(4),
                },
                encryption_algorithm: EncryptionAlgorithm::Aes256,
            }),
        }
    }
}

impl Default for ComparisonConfig {
    fn default() -> Self {
        Self {
            compare_ids: true,
            compare_timestamps: true,
            compare_metadata: true,
            compare_structure: true,
            compare_encryption: true,
            compare_permissions: true,
            compare_watermarks: true,
            ignore_minor: false,
            timestamp_tolerance: 1, // 1 second tolerance
        }
    }
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            strict_mode: false,
            validate_structure: true,
            check_references: true,
            verify_checksums: true,
            check_compliance: false,
            fail_on_warnings: false,
            max_validation_time: 300,
            validation_depth: ValidationDepth::Standard,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            file_logging: true,
            console_logging: true,
            log_file_path: PathBuf::from("pdf-forensic.log"),
            max_log_size: 10 * 1024 * 1024, // 10MB
            log_rotation: true,
            detailed_errors: true,
            log_forensic_ops: true,
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            max_memory_usage: constants::DEFAULT_MEMORY_LIMIT,
            max_processing_time: constants::DEFAULT_TIMEOUT,
            parallel_processing: true,
            max_threads: 4,
            cache_enabled: true,
            cache_size: 100 * 1024 * 1024, // 100MB
            buffer_size: constants::DEFAULT_BUFFER_SIZE,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            security_analysis: true,
            scan_malicious: true,
            verify_signatures: true,
            validate_certificates: true,
            check_suspicious_patterns: true,
            risk_tolerance: RiskTolerance::Medium,
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Json,
            verbose: false,
            pretty_print: true,
            include_timestamps: true,
            compress_output: false,
            file_permissions: Some(644),
        }
    }
}

impl Default for ToolIntegrationConfig {
    fn default() -> Self {
        Self {
            enable_external_validation: false,
            qpdf_path: None,
            pdftk_path: None,
            ghostscript_path: None,
            poppler_path: None,
            tool_timeout: 60,
        }
    }
}

//=============================================================================
// DISPLAY IMPLEMENTATIONS
//=============================================================================

impl fmt::Display for ObjectReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} R", self.number, self.generation)
    }
}

impl fmt::Display for WatermarkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WatermarkType::Text { text, .. } => write!(f, "Text: {}", text),
            WatermarkType::Image { dimensions, .. } => write!(f, "Image: {}x{}", dimensions.0, dimensions.1),
            WatermarkType::Logo { logo_type, .. } => write!(f, "Logo: {:?}", logo_type),
            WatermarkType::Url { url, .. } => write!(f, "URL: {}", url),
            WatermarkType::Annotation { annotation_type, .. } => write!(f, "Annotation: {}", annotation_type),
            WatermarkType::Overlay { .. } => write!(f, "Overlay"),
        }
    }
}





impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.x, self.y)
    }
}

//=============================================================================
// CONVERSION IMPLEMENTATIONS
//=============================================================================

//=============================================================================
// UTILITY FUNCTIONS
//=============================================================================


impl Point {
    /// Create a new point
    pub fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }
    
    /// Calculate distance to another point
    pub fn distance_to(&self, other: &Point) -> f64 {
        ((self.x - other.x).powi(2) + (self.y - other.y).powi(2)).sqrt()
    }
}

impl PdfVersion {
    /// Create a new PDF version
    pub fn new(major: u8, minor: u8) -> Self {
        let header_bytes = format!("%PDF-{}.{}", major, minor).into_bytes();
        Self {
            major,
            minor,
            header_bytes,
            header_offset: 0,
            header_comments: Vec::new(),
        }
    }
    
    /// Check if version is valid
    pub fn is_valid(&self) -> bool {
        self.major > 0 && self.major <= 2 && self.minor <= 9
    }
    
    /// Get version as float
    pub fn as_float(&self) -> f32 {
        self.major as f32 + (self.minor as f32 / 10.0)
    }
}

// End of types.rs - Total lines: ~6000+
// This file serves as the complete single source of truth for all data structures
// used throughout the PDF forensic clone tool application.

//=============================================================================
// MISSING TYPE DEFINITIONS FOR COMPILATION
//=============================================================================

/// Hybrid reference table information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridInfo {
    /// Traditional xref table present
    pub has_traditional_xref: bool,
    /// Cross-reference stream present
    pub has_xref_stream: bool,
    /// Compatibility mode
    pub compatibility_mode: bool,
    /// Entry count discrepancies
    pub entry_discrepancies: Vec<String>,
}

/// Page tree structural data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageTreeData {
    /// Total page count
    pub page_count: u32,
    /// Tree depth
    pub tree_depth: u32,
    /// Node references
    pub node_references: Vec<ObjectReference>,
    /// Page references
    pub page_references: Vec<ObjectReference>,
    /// Structural integrity
    pub structural_integrity: bool,
}

/// Date range for filtering and analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DateRange {
    /// Start date
    pub start_date: chrono::DateTime<chrono::Utc>,
    /// End date
    pub end_date: chrono::DateTime<chrono::Utc>,
    /// Include boundaries
    pub include_boundaries: bool,
}



impl Default for XRefValidationResult {
    fn default() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            reference_consistency: true,
            generation_consistency: true,
            offset_accuracy: 1.0,
            free_chain_integrity: true,
        }
    }
}

impl Default for ObjectIntegrityResults {
    fn default() -> Self {
        Self {
            overall_status: IntegrityStatus::Valid,
            object_results: HashMap::new(),
            integrity_score: 1.0,
            compromised_objects: Vec::new(),
            verified_objects: Vec::new(),
        }
    }
}

impl Default for StreamAnalysisResults {
    fn default() -> Self {
        Self {
            total_streams: 0,
            successful_streams: 0,
            failed_streams: 0,
            stream_types: HashMap::new(),
            compression_analysis: CompressionAnalysis {
                overall_ratio: 1.0,
                filter_ratios: HashMap::new(),
                uncompressed_size: 0,
                compressed_size: 0,
                efficiency_score: 1.0,
            },
            filter_analysis: FilterAnalysis {
                filter_usage: HashMap::new(),
                filter_chains: Vec::new(),
                compatibility_issues: Vec::new(),
                deprecated_filters: Vec::new(),
            },
            integrity_results: Vec::new(),
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            extraction: ExtractionConfig::default(),
            injection: InjectionConfig::default(),
            validation: ValidationConfig::default(),
            logging: LoggingConfig::default(),
            performance: PerformanceConfig::default(),
            security: SecurityConfig::default(),
            output: OutputConfig::default(),
            tool_integration: ToolIntegrationConfig::default(),
        }
    }
}

impl Default for ContentPreservationResults {
    fn default() -> Self {
        Self {
            overall_status: PreservationStatus::FullyPreserved,
            preserved_categories: HashMap::new(),
            hash_verification: HashVerificationResults {
                overall_status: true,
                hash_results: HashMap::new(),
                algorithms_used: Vec::new(),
                verification_time_ms: 0,
            },
            visual_preservation: VisualPreservationResults {
                overall_score: 1.0,
                page_rendering: Vec::new(),
                layout_preservation: LayoutPreservationResult {
                    preservation_score: 1.0,
                    text_flow_preserved: true,
                    positioning_preserved: true,
                    page_boundaries_preserved: true,
                    layout_issues: Vec::new(),
                },
                visual_elements: Vec::new(),
                color_preservation: ColorPreservationResult {
                    preservation_score: 1.0,
                    color_space_preserved: true,
                    color_accuracy: ColorAccuracyMetrics {
                        delta_e_average: 0.0,
                        delta_e_maximum: 0.0,
                        difference_threshold: 2.0,
                        colors_within_threshold: 100.0,
                    },
                    color_profile_preserved: true,
                    color_issues: Vec::new(),
                },
            },
            text_preservation: TextPreservationResults {
                preservation_score: 1.0,
                text_extraction: TextExtractionComparison {
                    original_length: 0,
                    extracted_length: 0,
                    similarity_score: 1.0,
                    character_differences: 0,
                    word_differences: 0,
                    line_differences: 0,
                    extraction_errors: Vec::new(),
                },
                font_preservation: FontPreservationSummary {
                    preservation_score: 1.0,
                    fonts_preserved: 0,
                    fonts_substituted: 0,
                    fonts_missing: 0,
                    substitution_details: Vec::new(),
                },
                encoding_preservation: EncodingPreservationResult {
                    preservation_score: 1.0,
                    character_encoding_preserved: true,
                    unicode_normalization_preserved: true,
                    bom_preserved: true,
                    encoding_issues: Vec::new(),
                },
                accessibility_preservation: AccessibilityPreservationResult {
                    preservation_score: 1.0,
                    structure_tags_preserved: true,
                    alt_text_preserved: true,
                    reading_order_preserved: true,
                    language_info_preserved: true,
                    accessibility_issues: Vec::new(),
                },
            },
            image_preservation: ImagePreservationResults {
                preservation_score: 1.0,
                images_preserved: 0,
                images_quality_loss: 0,
                images_corrupted: 0,
                individual_results: Vec::new(),
                format_analysis: ImageFormatAnalysis {
                    format_distribution: HashMap::new(),
                    compression_analysis: HashMap::new(),
                    color_space_analysis: HashMap::new(),
                    resolution_analysis: ResolutionAnalysis {
                        average_dpi: 300.0,
                        dpi_distribution: HashMap::new(),
                        resolution_consistency: true,
                        high_res_count: 0,
                        low_res_count: 0,
                    },
                },
            },
            font_preservation: FontPreservationResults {
                preservation_score: 1.0,
                fonts_analyzed: 0,
                fonts_preserved: 0,
                fonts_substituted: 0,
                embedding_analysis: FontEmbeddingAnalysis {
                    fully_embedded: 0,
                    subset_embedded: 0,
                    not_embedded: 0,
                    completeness_score: 1.0,
                    embedding_issues: Vec::new(),
                },
                subset_analysis: FontSubsetAnalysis {
                    efficiency_score: 1.0,
                    character_coverage: CharacterCoverageAnalysis {
                        total_characters: 0,
                        characters_used: 0,
                        coverage_percentage: 100.0,
                        missing_characters: Vec::new(),
                        unused_character_count: 0,
                    },
                    optimization_potential: 0.0,
                    subset_issues: Vec::new(),
                },
                individual_results: Vec::new(),
            },
        }
    }
}
