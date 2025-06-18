//! PDF Forensic Clone Tool Library
//! Provides programmatic access to forensic PDF operations

pub use types::*;

pub mod types;
pub mod config;
pub mod extractor;
pub mod injector;
pub mod io;
pub mod validator;
pub mod logger;

/// Extract complete forensic data from PDF file
pub fn extract_pdf_forensic_data(pdf_path: &str) -> PdfResult<PdfForensicData> {
    let config = ExtractionConfig::default();
    extractor::extract_pdf_forensic_data(pdf_path, &config)
}

/// Inject forensic data into target PDF
pub fn inject_pdf_forensic_data(
    target_path: &str,
    forensic_data: &PdfForensicData,
    output_path: &str,
) -> PdfResult<()> {
    injector::inject_forensic_data(target_path, forensic_data, output_path, true)
}

/// Validate PDF structure and forensic integrity
pub fn validate_pdf_structure(pdf_path: &str) -> PdfResult<ValidationResult> {
    validator::validate_pdf_file(pdf_path)
}

/// Compare forensic signatures of two PDFs
pub fn compare_pdf_forensics(pdf1_path: &str, pdf2_path: &str) -> PdfResult<ComparisonResult> {
    let config = ExtractionConfig::default();
    let data1 = extractor::extract_pdf_forensic_data(pdf1_path, &config)?;
    let data2 = extractor::extract_pdf_forensic_data(pdf2_path, &config)?;
    // Convert types::PdfForensicData to io::json::PdfForensicData
    let json_data1 = io::json::PdfForensicData::from(&data1);
    let json_data2 = io::json::PdfForensicData::from(&data2);
    Ok(io::json::compare_forensic_data(&json_data1, &json_data2))
}
