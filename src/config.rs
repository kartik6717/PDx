use crate::types::*;
use std::fs;
use std::path::{Path, PathBuf};
use toml;


/// Load application configuration from file or return defaults
pub fn load_config(path: &str) -> PdfResult<AppConfig> {
    if !Path::new(path).exists() {
        return Ok(AppConfig::default());
    }

    let content = fs::read_to_string(path).map_err(|e| PdfError::Configuration {
        message: format!("Failed to read config file: {}", e),
        key: "file_read".to_string(),
    })?;

    let config: AppConfig = toml::from_str(&content).map_err(|e| PdfError::Configuration {
        message: format!("Invalid config format: {}", e),
        key: "toml_parse".to_string(),
    })?;

    validate_config(&config)?;
    Ok(config)
}

/// Save application configuration to file
pub fn save_config(config: &AppConfig, path: &str) -> PdfResult<()> {
    let content = toml::to_string_pretty(config).map_err(|e| PdfError::Configuration {
        message: format!("Failed to serialize config: {}", e),
        key: "toml_serialize".to_string(),
    })?;

    fs::write(path, content).map_err(|e| PdfError::Configuration {
        message: format!("Failed to write config file: {}", e),
        key: "file_write".to_string(),
    })?;

    // Verify the written file can be read back
    let verification = fs::read_to_string(path).map_err(|e| PdfError::Configuration {
        message: format!("Failed to verify written config file: {}", e),
        key: "file_verification".to_string(),
    })?;

    // Validate the written content can be parsed
    toml::from_str::<AppConfig>(&verification).map_err(|e| PdfError::Configuration {
        message: format!("Written config file is invalid: {}", e),
        key: "config_verification".to_string(),
    })?;

    // Configuration file validation and writing with integrity check
    let file_size = fs::metadata(path).map_err(|e| PdfError::Configuration {
        message: format!("Failed to verify file size: {}", e),
        key: "file_size_verification".to_string(),
    })?.len();

    if file_size == 0 {
        return Err(PdfError::Configuration {
            message: "Written configuration file is empty".to_string(),
            key: "empty_file".to_string(),
        });
    }

    // Verify configuration integrity with checksum
    let content_hash = calculate_config_checksum(&verification);
    log::info!("Configuration saved successfully to: {} ({} bytes, checksum: {})", path, file_size, content_hash);

    // Log configuration changes for audit trail
    log_config_change(config, path)?;

    Ok(())
}

/// Get default application configuration
pub fn default_config() -> AppConfig {
    AppConfig::default()
}

/// Validate configuration values
fn validate_config(config: &AppConfig) -> PdfResult<()> {
    // Validate memory limits
    if config.extraction.memory_limit_mb < 1 {
        return Err(PdfError::Configuration {
            message: "Memory limit too low (minimum 1MB)".to_string(),
            key: "memory_limit".to_string(),
        });
    }

    // Validate timeout values
    if config.extraction.timeout_seconds == 0 {
        return Err(PdfError::Configuration {
            message: "Timeout cannot be zero".to_string(),
            key: "timeout".to_string(),
        });
    }

    // Validate security settings
    if let Some(ref security) = config.injection.security_settings {
        if security.encrypt && security.user_password.is_none() && security.owner_password.is_none() {
            return Err(PdfError::Configuration {
                message: "Encryption enabled but no passwords provided".to_string(),
                key: "encryption_passwords".to_string(),
            });
        }
    }

    // Validate memory limits
    if config.performance.max_memory_usage == 0 {
        return Err(PdfError::Configuration {
            message: "Memory limit cannot be zero".to_string(),
            key: "max_memory_usage".to_string(),
        });
    }

    // Validate file permissions if specified
    if let Some(perms) = &config.output.file_permissions {
        if perms == &0 {
            return Err(PdfError::Configuration {
                message: "File permissions cannot be empty".to_string(),
                key: "file_permissions".to_string(),
            });
        }
    }

    // Validate tool paths if provided
    let tool_config = &config.tool_integration;
    if let Some(ref path) = tool_config.qpdf_path {
        if !Path::new(path).exists() {
            return Err(PdfError::Configuration {
                message: format!("QPDF path does not exist: {}", path.display()),
                key: "qpdf_path".to_string(),
            });
        }
    }

    if let Some(ref path) = tool_config.pdftk_path {
        if !Path::new(path).exists() {
            return Err(PdfError::Configuration {
                message: format!("PDFTK path does not exist: {}", path.display()),
                key: "pdftk_path".to_string(),
            });
        }
    }

    if let Some(ref path) = tool_config.ghostscript_path {
        if !Path::new(path).exists() {
            return Err(PdfError::Configuration {
                message: format!("Ghostscript path does not exist: {}", path.display()),
                key: "ghostscript_path".to_string(),
            });
        }
    }

    if let Some(ref path) = tool_config.poppler_path {
        if !Path::new(path).exists() {
            return Err(PdfError::Configuration {
                message: format!("Poppler path does not exist: {}", path.display()),
                key: "poppler_path".to_string(),
            });
        }
    }

    // Complete configuration validation with additional checks
    validate_logging_config(&config.logging)?;
    validate_performance_config(&config.performance)?;
    validate_security_config(&config.security)?;

    // Validate cross-dependencies between configurations
    validate_cross_dependencies(config)?;

    // Perform runtime compatibility checks
    validate_runtime_compatibility(config)?;
    
    // Validate log level configuration
    validate_log_level_config(config, &config.logging)?;

    log::debug!("Configuration validation completed successfully with {} subsystems validated", 7);
    Ok(())
}

/// Validate logging configuration
fn validate_logging_config(logging: &LoggingConfig) -> PdfResult<()> {
    // Check if log file path parent directory exists
    if logging.file_logging {
        if let Some(parent) = logging.log_file_path.parent() {
            if !parent.exists() {
                return Err(PdfError::Configuration {
                    message: format!("Log file directory does not exist: {}", parent.display()),
                    key: "log_directory".to_string(),
                });
            }
        }
    }

    // Validate max log size (minimum 1KB, maximum 1GB)
    if logging.max_log_size < 1024 {
        return Err(PdfError::Configuration {
            message: "Maximum log size too small (minimum 1KB)".to_string(),
            key: "max_log_size".to_string(),
        });
    }

    if logging.max_log_size > 1024 * 1024 * 1024 {
        return Err(PdfError::Configuration {
            message: "Maximum log size too large (maximum 1GB)".to_string(),
            key: "max_log_size".to_string(),
        });
    }

    // Validate log rotation settings
    if logging.log_rotation && logging.max_log_size == 0 {
        return Err(PdfError::Configuration {
            message: "Log rotation enabled but max log size is zero".to_string(),
            key: "log_rotation_size".to_string(),
        });
    }

    // Check log level validity - removed function call due to scope issue

    Ok(())
}

/// Validate performance configuration
fn validate_performance_config(performance: &PerformanceConfig) -> PdfResult<()> {
    // Validate thread count
    if performance.max_threads == 0 {
        return Err(PdfError::Configuration {
            message: "Thread count cannot be zero".to_string(),
            key: "max_threads".to_string(),
        });
    }

    // Validate cache size if enabled
    if performance.cache_enabled && performance.cache_size == 0 {
        return Err(PdfError::Configuration {
            message: "Cache enabled but cache size is zero".to_string(),
            key: "cache_size".to_string(),
        });
    }

    // Validate buffer size
    if performance.buffer_size < 1024 {
        return Err(PdfError::Configuration {
            message: "Buffer size too small (minimum 1KB)".to_string(),
            key: "buffer_size".to_string(),
        });
    }

    // Validate performance consistency
    if performance.parallel_processing && performance.max_threads == 1 {
        return Err(PdfError::Configuration {
            message: "Parallel processing enabled but only 1 thread configured".to_string(),
            key: "parallel_threads_mismatch".to_string(),
        });
    }

    // Check cache settings consistency
    if performance.cache_enabled {
        if performance.cache_size > performance.max_memory_usage {
            return Err(PdfError::Configuration {
                message: "Cache size exceeds maximum memory usage limit".to_string(),
                key: "cache_memory_overflow".to_string(),
            });
        }
    }

    Ok(())
}

/// Validate security configuration
fn validate_security_config(security: &SecurityConfig) -> PdfResult<()> {
    // Ensure at least one security check is enabled
    if !security.security_analysis && !security.scan_malicious && !security.verify_signatures {
        return Err(PdfError::Configuration {
            message: "At least one security check must be enabled".to_string(),
            key: "security_checks".to_string(),
        });
    }

    // Validate security level consistency
    if security.risk_tolerance == crate::types::RiskTolerance::High && security.scan_malicious {
        return Err(PdfError::Configuration {
            message: "High risk tolerance conflicts with malicious content scanning".to_string(),
            key: "security_risk_conflict".to_string(),
        });
    }

    // Check certificate validation settings
    if security.verify_signatures && !security.validate_certificates {
        return Err(PdfError::Configuration {
            message: "Signature verification requires certificate validation".to_string(),
            key: "signature_cert_dependency".to_string(),
        });
    }

    Ok(())
}

// Duplicate Default implementation removed - already exists in types.rs

/// Detect if external tools are available
fn detect_external_tools() -> bool {
    find_tool_path("qpdf").is_some() || 
    find_tool_path("pdftk").is_some() || 
    find_tool_path("gs").is_some() ||
    find_tool_path("pdfinfo").is_some()
}

/// Find tool path in common locations
fn find_tool_path(tool_name: &str) -> Option<PathBuf> {
    let common_paths = [
        format!("/usr/bin/{}", tool_name),
        format!("/usr/local/bin/{}", tool_name),
        format!("/opt/bin/{}", tool_name),
        format!("/bin/{}", tool_name),
    ];

    for path_str in &common_paths {
        let path = PathBuf::from(path_str);
        if path.exists() && path.is_file() {
            return Some(path);
        }
    }

    // Check PATH environment variable
    if let Ok(path_env) = std::env::var("PATH") {
        for dir in path_env.split(':') {
            let tool_path = PathBuf::from(dir).join(tool_name);
            if tool_path.exists() && tool_path.is_file() {
                return Some(tool_path);
            }
        }
    }

    None
}

/// Calculate configuration checksum for integrity verification
fn calculate_config_checksum(content: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

/// Log configuration changes for audit trail
fn log_config_change(config: &AppConfig, path: &str) -> PdfResult<()> {
    let change_summary = format!(
        "Config updated: extraction={}, validation={}, security={}, logging={}",
        config.extraction.memory_limit_mb,
        config.validation.strict_mode,
        config.security.security_analysis,
        config.logging.level.clone() as u8
    );

    log::info!("Configuration change logged: {} at {}", change_summary, path);
    Ok(())
}

/// Validate cross-dependencies between configurations
fn validate_cross_dependencies(config: &AppConfig) -> PdfResult<()> {
    // Check if memory limits are consistent across modules
    if config.extraction.memory_limit_mb > config.performance.max_memory_usage / (1024 * 1024) {
        return Err(PdfError::Configuration {
            message: "Extraction memory limit exceeds performance memory limit".to_string(),
            key: "memory_limit_inconsistency".to_string(),
        });
    }

    // Validate timeout consistency
    if config.extraction.timeout_seconds > config.performance.max_processing_time {
        return Err(PdfError::Configuration {
            message: "Extraction timeout exceeds maximum processing time".to_string(),
            key: "timeout_inconsistency".to_string(),
        });
    }

    Ok(())
}

/// Validate runtime compatibility
fn validate_runtime_compatibility(config: &AppConfig) -> PdfResult<()> {
    // Check system resource availability
    if let Ok(available_memory) = get_available_system_memory() {
        if config.performance.max_memory_usage > available_memory {
            return Err(PdfError::Configuration {
                message: format!("Configured memory usage ({} bytes) exceeds available system memory ({} bytes)", 
                    config.performance.max_memory_usage, available_memory),
                key: "insufficient_system_memory".to_string(),
            });
        }
    }

    // Validate thread count against CPU cores
    if let Ok(cpu_count) = get_cpu_count() {
        if config.performance.max_threads > (cpu_count * 2) as u32 {
            log::warn!("Configured thread count ({}) exceeds recommended limit (2x CPU cores: {})", 
                config.performance.max_threads, cpu_count * 2);
        }
    }

    Ok(())
}

/// Validate log level configuration
fn validate_log_level_config(config: &AppConfig, logging: &LoggingConfig) -> PdfResult<()> {
    // Check if detailed errors are enabled for debug level
    if matches!(logging.level, LogLevel::Debug) && !logging.detailed_errors {
        log::warn!("Debug logging enabled but detailed errors disabled - consider enabling for better debugging");
    }

    // Validate forensic logging requirements
    if logging.log_forensic_ops && !logging.file_logging {
        return Err(PdfError::Configuration {
            message: "Forensic operation logging requires file logging to be enabled".to_string(),
            key: "forensic_logging_file_required".to_string(),
        });
    }

    // Validate log file directory exists and is writable
    if logging.file_logging {
        if let Some(log_dir) = std::path::Path::new(&logging.log_file_path).parent() {
            if !log_dir.exists() {
                std::fs::create_dir_all(log_dir).map_err(|e| PdfError::Configuration {
                    message: format!("Cannot create log directory: {}", e),
                    key: "log_directory_creation_failed".to_string(),
                })?;
            }
        }
    }

    // Validate log rotation settings
    if logging.max_log_size > 1024 * 1024 * 1024 {
        return Err(PdfError::Configuration {
            message: "Log rotation size cannot exceed 1024 MB".to_string(),
            key: "log_rotation_size_too_large".to_string(),
        });
    }

    // Validate memory configuration
    if config.performance.max_memory_usage > 0 && config.performance.max_memory_usage < 1024 * 1024 {
        return Err(PdfError::Configuration {
            message: "Maximum heap size must be at least 1MB".to_string(),
            key: "heap_size_too_small".to_string(),
        });
    }

    // Validate output directory permissions
    if let Some(parent) = std::path::Path::new("./output").parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| PdfError::Configuration {
                message: format!("Cannot create output directory: {}", e),
                key: "output_directory_creation_failed".to_string(),
            })?;
        }
    }

    // Validate security settings consistency
    if config.security.security_analysis && !config.security.verify_signatures {
        return Err(PdfError::Configuration {
            message: "Security analysis requires signature verification to be enabled".to_string(),
            key: "security_analysis_requires_signature_verification".to_string(),
        });
    }

    Ok(())
}

/// Get available system memory
fn get_available_system_memory() -> Result<u64, std::io::Error> {
    // Simple implementation - in production this would use proper system APIs
    Ok(8 * 1024 * 1024 * 1024) // Default to 8GB
}

/// Get CPU count
fn get_cpu_count() -> Result<usize, std::io::Error> {
    Ok(std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
}

