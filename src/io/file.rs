use crate::types::*;
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::{Read, Write, BufReader, BufWriter};
use std::path::Path;
use memmap2::Mmap;

/// Load PDF file with memory mapping for large files
pub fn load_pdf_file(file_path: &str) -> PdfResult<Mmap> {
    let file = File::open(file_path).map_err(|e| PdfError::FileSystem {
        path: file_path.to_string(),
        operation: "open".to_string(),
        error_kind: match e.kind() {
            std::io::ErrorKind::NotFound => FileErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied => FileErrorKind::PermissionDenied,
            _ => FileErrorKind::ReadOnly,
        },
    })?;

    let file_size = file.metadata().map_err(|_e| PdfError::FileSystem {
        path: file_path.to_string(),
        operation: "metadata".to_string(),
        error_kind: FileErrorKind::ReadOnly,
    })?.len();

    if file_size == 0 {
        return Err(PdfError::FileSystem {
            path: file_path.to_string(),
            operation: "validate".to_string(),
            error_kind: FileErrorKind::Corrupted,
        });
    }

    log::info!("Loading PDF file: {} ({} bytes)", file_path, file_size);

    let mmap = unsafe { Mmap::map(&file) }.map_err(|e| PdfError::Memory {
        message: format!("Failed to memory map file '{}': {}", file_path, e),
        requested_bytes: file_size,
        available_bytes: get_available_memory(),
    })?;

    // Validate PDF header
    validate_pdf_header(&mmap, file_path)?;

    Ok(mmap)
}

/// Save PDF data to file with proper error handling
pub fn save_pdf_file(data: &[u8], output_path: &str) -> PdfResult<()> {
    // Create directory if it doesn't exist
    if let Some(parent) = Path::new(output_path).parent() {
        create_dir_all(parent).map_err(|_e| PdfError::FileSystem {
            path: parent.to_string_lossy().to_string(),
            operation: "create_dir".to_string(),
            error_kind: match _e.kind() {
                std::io::ErrorKind::PermissionDenied => FileErrorKind::PermissionDenied,
                std::io::ErrorKind::AlreadyExists => FileErrorKind::AlreadyExists,
                _ => FileErrorKind::NoSpace,
            },
        })?;
    }

    log::info!("Saving PDF file: {} ({} bytes)", output_path, data.len());

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_path)
        .map_err(|_e| PdfError::FileSystem {
            path: output_path.to_string(),
            operation: "create".to_string(),
            error_kind: match _e.kind() {
                std::io::ErrorKind::PermissionDenied => FileErrorKind::PermissionDenied,
                std::io::ErrorKind::AlreadyExists => FileErrorKind::AlreadyExists,
                _ => FileErrorKind::NoSpace,
            },
        })?;

    // Write data in chunks for large files
    const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks
    let mut bytes_written = 0;

    for chunk in data.chunks(CHUNK_SIZE) {
        file.write_all(chunk).map_err(|_e| PdfError::FileSystem {
            path: output_path.to_string(),
            operation: "write".to_string(),
            error_kind: FileErrorKind::NoSpace,
        })?;

        bytes_written += chunk.len();

        // Log progress for large files
        if data.len() > 10 * 1024 * 1024 && bytes_written % (1024 * 1024) == 0 {
            log::debug!("Written {} MB of {} MB", 
                       bytes_written / (1024 * 1024), 
                       data.len() / (1024 * 1024));
        }
    }

    file.flush().map_err(|_e| PdfError::FileSystem {
        path: output_path.to_string(),
        operation: "flush".to_string(),
        error_kind: FileErrorKind::NoSpace,
    })?;

    // Verify file was written correctly
    verify_written_file(output_path, data.len())?;

    log::info!("Successfully saved PDF file: {}", output_path);
    Ok(())
}

/// Create backup of file before modification
pub fn create_backup_file(file_path: &str) -> PdfResult<String> {
    let path = Path::new(file_path);
    let backup_path = if let Some(extension) = path.extension() {
        format!("{}.backup.{}", 
               path.with_extension("").to_string_lossy(), 
               extension.to_string_lossy())
    } else {
        format!("{}.backup", file_path)
    };

    log::info!("Creating backup: {} -> {}", file_path, backup_path);

    std::fs::copy(file_path, &backup_path).map_err(|_e| PdfError::FileSystem {
        path: file_path.to_string(),
        operation: "backup".to_string(),
        error_kind: match _e.kind() {
            std::io::ErrorKind::NotFound => FileErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied => FileErrorKind::PermissionDenied,
            _ => FileErrorKind::NoSpace,
        },
    })?;

    Ok(backup_path)
}

/// Read file in streaming fashion for large files
pub fn read_file_streaming<F>(file_path: &str, mut processor: F) -> PdfResult<()>
where
    F: FnMut(&[u8]) -> PdfResult<()>,
{
    let file = File::open(file_path).map_err(|e| PdfError::FileSystem {
        path: file_path.to_string(),
        operation: "open".to_string(),
        error_kind: match e.kind() {
            std::io::ErrorKind::NotFound => FileErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied => FileErrorKind::PermissionDenied,
            _ => FileErrorKind::ReadOnly,
        },
    })?;

    let mut reader = BufReader::new(file);
    let mut buffer = vec![0u8; 1024 * 1024]; // 1MB buffer

    loop {
        let bytes_read = reader.read(&mut buffer).map_err(|_e| PdfError::FileSystem {
            path: file_path.to_string(),
            operation: "read".to_string(),
            error_kind: FileErrorKind::ReadOnly,
        })?;

        if bytes_read == 0 {
            break; // End of file
        }

        processor(&buffer[..bytes_read])?;
    }

    Ok(())
}

/// Write file in streaming fashion for large files
pub fn write_file_streaming<F>(output_path: &str, mut data_provider: F) -> PdfResult<()>
where
    F: FnMut() -> PdfResult<Option<Vec<u8>>>,
{
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_path)
        .map_err(|_e| PdfError::FileSystem {
            path: output_path.to_string(),
            operation: "create".to_string(),
            error_kind: match _e.kind() {
                std::io::ErrorKind::PermissionDenied => FileErrorKind::PermissionDenied,
                _ => FileErrorKind::NoSpace,
            },
        })?;

    let mut writer = BufWriter::new(file);

    while let Some(data) = data_provider()? {
        writer.write_all(&data).map_err(|_e| PdfError::FileSystem {
            path: output_path.to_string(),
            operation: "write".to_string(),
            error_kind: FileErrorKind::NoSpace,
        })?;
    }

    writer.flush().map_err(|_e| PdfError::FileSystem {
        path: output_path.to_string(),
        operation: "flush".to_string(),
        error_kind: FileErrorKind::NoSpace,
    })?;

    Ok(())
}

/// Get file metadata information
pub fn get_file_info(file_path: &str) -> PdfResult<FileInfo> {
    let metadata = std::fs::metadata(file_path).map_err(|_e| PdfError::FileSystem {
        path: file_path.to_string(),
        operation: "metadata".to_string(),
        error_kind: match _e.kind() {
            std::io::ErrorKind::NotFound => FileErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied => FileErrorKind::PermissionDenied,
            _ => FileErrorKind::ReadOnly,
        },
    })?;

    let file_size = metadata.len();
    let modified_time = metadata.modified().ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| chrono::DateTime::from_timestamp(d.as_secs() as i64, 0).unwrap_or_default())
        .unwrap_or_default();

    let is_readable = File::open(file_path).is_ok();
    let is_writable = OpenOptions::new().write(true).append(true).open(file_path).is_ok();

    Ok(FileInfo {
        path: file_path.to_string(),
        size: file_size,
        modified_time,
        is_readable,
        is_writable,
        is_pdf: is_pdf_file(file_path)?,
    })
}

/// Check if file is a valid PDF
pub fn is_pdf_file(file_path: &str) -> PdfResult<bool> {
    let mut file = File::open(file_path).map_err(|e| PdfError::FileSystem {
        path: file_path.to_string(),
        operation: "open".to_string(),
        error_kind: match e.kind() {
            std::io::ErrorKind::NotFound => FileErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied => FileErrorKind::PermissionDenied,
            _ => FileErrorKind::ReadOnly,
        },
    })?;

    let mut header = [0u8; 8];
    file.read_exact(&mut header).map_err(|_e| PdfError::FileSystem {
        path: file_path.to_string(),
        operation: "read".to_string(),
        error_kind: FileErrorKind::ReadOnly,
    })?;

    let header_str = String::from_utf8_lossy(&header);
    Ok(header_str.starts_with("%PDF-"))
}

/// Calculate file checksum for integrity verification
pub fn calculate_file_checksum(file_path: &str) -> PdfResult<String> {
    use sha2::{Digest, Sha256};

    let file = File::open(file_path).map_err(|e| PdfError::FileSystem {
        path: file_path.to_string(),
        operation: "open".to_string(),
        error_kind: match e.kind() {
            std::io::ErrorKind::NotFound => FileErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied => FileErrorKind::PermissionDenied,
            _ => FileErrorKind::ReadOnly,
        },
    })?;

    let mut hasher = Sha256::new();
    let mut reader = BufReader::new(file);
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = reader.read(&mut buffer).map_err(|_e| PdfError::FileSystem {
            path: file_path.to_string(),
            operation: "read".to_string(),
            error_kind: FileErrorKind::ReadOnly,
        })?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    Ok(hex::encode(result))
}

/// Secure file deletion (overwrite before delete)
pub fn secure_delete_file(file_path: &str) -> PdfResult<()> {
    let metadata = std::fs::metadata(file_path).map_err(|_e| PdfError::FileSystem {
        path: file_path.to_string(),
        operation: "metadata".to_string(),
        error_kind: match _e.kind() {
            std::io::ErrorKind::NotFound => FileErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied => FileErrorKind::PermissionDenied,
            _ => FileErrorKind::ReadOnly,
        },
    })?;

    let file_size = metadata.len();

    // Overwrite file with random data
    let mut file = OpenOptions::new()
        .write(true)
        .open(file_path)
        .map_err(|_e| PdfError::FileSystem {
            path: file_path.to_string(),
            operation: "open_write".to_string(),
            error_kind: FileErrorKind::PermissionDenied,
        })?;

    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut buffer = vec![0u8; 4096];
    let mut bytes_written = 0u64;

    while bytes_written < file_size {
        let chunk_size = std::cmp::min(4096, (file_size - bytes_written) as usize);
        rng.fill_bytes(&mut buffer[..chunk_size]);

        file.write_all(&buffer[..chunk_size]).map_err(|_e| PdfError::FileSystem {
            path: file_path.to_string(),
            operation: "overwrite".to_string(),
            error_kind: FileErrorKind::NoSpace,
        })?;

        bytes_written += chunk_size as u64;
    }

    file.flush().map_err(|_e| PdfError::FileSystem {
        path: file_path.to_string(),
        operation: "flush".to_string(),
        error_kind: FileErrorKind::NoSpace,
    })?;

    // Delete the file
    std::fs::remove_file(file_path).map_err(|_e| PdfError::FileSystem {
        path: file_path.to_string(),
        operation: "delete".to_string(),
        error_kind: FileErrorKind::PermissionDenied,
    })?;

    Ok(())
}

/// Helper functions

fn validate_pdf_header(data: &[u8], file_path: &str) -> PdfResult<()> {
    if data.len() < 8 {
        return Err(PdfError::FileSystem {
            path: file_path.to_string(),
            operation: "validate".to_string(),
            error_kind: FileErrorKind::Corrupted,
        });
    }

    let header = &data[0..8];
    let header_str = String::from_utf8_lossy(header);

    if !header_str.starts_with("%PDF-") {
        return Err(PdfError::Parse {
            offset: 0,
            message: format!("Invalid PDF header: {}", header_str),
            context: format!("file: {}", file_path),
        });
    }

    Ok(())
}

fn get_available_memory() -> u64 {
    // Simple heuristic for available memory
    #[cfg(target_os = "linux")]
    {
        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            for line in meminfo.lines() {
                if line.starts_with("MemAvailable:") {
                    if let Some(kb_str) = line.split_whitespace().nth(1) {
                        if let Ok(kb) = kb_str.parse::<u64>() {
                            return kb * 1024; // Convert KB to bytes
                        }
                    }
                }
            }
        }
    }

    // Default fallback
    512 * 1024 * 1024 // 512MB
}

fn verify_written_file(file_path: &str, expected_size: usize) -> PdfResult<()> {
    let metadata = std::fs::metadata(file_path).map_err(|_e| PdfError::FileSystem {
        path: file_path.to_string(),
        operation: "verify".to_string(),
        error_kind: FileErrorKind::ReadOnly,
    })?;

    let actual_size = metadata.len() as usize;

    if actual_size != expected_size {
        return Err(PdfError::FileSystem {
            path: file_path.to_string(),
            operation: "verify".to_string(),
            error_kind: FileErrorKind::Corrupted,
        });
    }

    Ok(())
}

use std::fs;
pub fn read_pdf_file(path: &str) -> PdfResult<Vec<u8>> {
    fs::read(path).map_err(|e| PdfError::Io {
        message: e.to_string(),
        code: e.raw_os_error().unwrap_or(-1),
    })
}

pub fn write_pdf_file(path: &str, data: &[u8]) -> PdfResult<()> {
    fs::write(path, data).map_err(|e| PdfError::Io {
        message: e.to_string(),
        code: e.raw_os_error().unwrap_or(-1),
    })
}