#include "advanced_pattern_recognizer.hpp"
#include "stealth_macros.hpp"
#include <algorithm>
#include <sstream>
#include <iostream>
#include "stealth_macros.hpp"
#include "stealth_macros.hpp"

AdvancedPatternRecognizer::AdvancedPatternRecognizer() {
    initialize_document_signature_database();
    initialize_specialized_profile_database();
    initialize_pattern_template_database();
    compile_regex_patterns_for_performance();
}

AdvancedPatternRecognizer::DocumentTypeSignature AdvancedPatternRecognizer::identify_document_type(const std::vector<uint8_t>& pdf_data) {
    std::string content(pdf_data.begin(), pdf_data.end());
    DocumentTypeSignature best_match;
    double highest_confidence = 0.0;
    
    // Test against all known document signatures
    for (const auto& category_pair : document_signatures_) {
        for (const auto& signature : category_pair.second) {
            double confidence = calculate_type_confidence(pdf_data, signature);
            
            if (confidence > highest_confidence && confidence >= signature.identification_threshold) {
                highest_confidence = confidence;
                best_match = signature;
            }
        }
    }
    
    // If no specific type identified, create generic signature
    if (highest_confidence == 0.0) {
        best_match.document_type = "generic_pdf";
        best_match.identification_threshold = 0.5;
        best_match.specialized_handler = "default";
    }
    
    return best_match;
}

std::vector<AdvancedPatternRecognizer::FormatPattern> AdvancedPatternRecognizer::extract_specialized_patterns(const std::vector<uint8_t>& pdf_data) {
    std::vector<FormatPattern> patterns;
    
    // Identify document type first
    DocumentTypeSignature doc_type = identify_document_type(pdf_data);
    
    // Extract patterns based on document type
    if (doc_type.document_type == "legal") {
        auto legal_patterns = extract_legal_citation_patterns(pdf_data);
        patterns.insert(patterns.end(), legal_patterns.begin(), legal_patterns.end());
    } else if (doc_type.document_type == "financial") {
        auto financial_patterns = extract_financial_statement_patterns(pdf_data);
        patterns.insert(patterns.end(), financial_patterns.begin(), financial_patterns.end());
    } else if (doc_type.document_type == "medical") {
        auto medical_patterns = extract_medical_record_patterns(pdf_data);
        patterns.insert(patterns.end(), medical_patterns.begin(), medical_patterns.end());
    } else if (doc_type.document_type == "academic") {
        auto academic_patterns = extract_academic_citation_patterns(pdf_data);
        patterns.insert(patterns.end(), academic_patterns.begin(), academic_patterns.end());
    }
    
    // Always extract common patterns
    auto table_patterns = analyze_complex_table_structures(pdf_data);
    patterns.insert(patterns.end(), table_patterns.begin(), table_patterns.end());
    
    auto embedded_patterns = analyze_embedded_object_patterns(pdf_data);
    patterns.insert(patterns.end(), embedded_patterns.begin(), embedded_patterns.end());
    
    return patterns;
}

AdvancedPatternRecognizer::DocumentTypeSignature AdvancedPatternRecognizer::recognize_legal_document_patterns(const std::vector<uint8_t>& pdf_data) {
    DocumentTypeSignature signature;
    signature.document_type = "legal";
    signature.identification_threshold = 0.7;
    
    std::string content(pdf_data.begin(), pdf_data.end());
    
    // Legal document structural patterns
    signature.structural_patterns = {
        "WHEREAS",
        "NOW THEREFORE",
        "IN WITNESS WHEREOF",
        "PARTIES AGREE",
        "JURISDICTION",
        "COURT OF",
        "PLAINTIFF",
        "DEFENDANT",
        "ATTORNEY FOR"
    };
    
    // Legal metadata patterns
    signature.metadata_patterns = {
        "Legal Brief",
        "Court Filing",
        "Contract",
        "Legal Opinion",
        "Case Law",
        "Attorney-Client"
    };
    
    // Legal content patterns (case citations, statute references)
    signature.content_patterns = {
        R"(\d+\s+[A-Z][a-z]+\.?\s+\d+)", // Case citations like "123 F.3d 456"
        R"(\d+\s+U\.S\.C\.?\s+§?\s*\d+)", // USC references
        R"(\d+\s+C\.F\.R\.?\s+§?\s*\d+)", // CFR references
        R"(No\.\s+\d{2}-\d+)", // Case numbers
        R"(\b\d{4}\s+WL\s+\d+\b)" // Westlaw citations
    };
    
    signature.specialized_handler = "legal_document_processor";
    
    return signature;
}

std::vector<AdvancedPatternRecognizer::FormatPattern> AdvancedPatternRecognizer::extract_legal_citation_patterns(const std::vector<uint8_t>& pdf_data) {
    std::vector<FormatPattern> patterns;
    std::string content(pdf_data.begin(), pdf_data.end());
    
    // Federal court citations
    std::regex federal_citation(R"((\d+)\s+(F\.\s*(?:2d|3d)?)\s+(\d+))");
    auto federal_matches = extract_patterns_by_regex(pdf_data, {federal_citation});
    for (auto& pattern : federal_matches) {
        pattern.pattern_type = "federal_court_citation";
        pattern.format_context = "legal_citation";
        patterns.push_back(pattern);
    }
    
    // Supreme Court citations
    std::regex supreme_citation(R"((\d+)\s+(U\.S\.)\s+(\d+))");
    auto supreme_matches = extract_patterns_by_regex(pdf_data, {supreme_citation});
    for (auto& pattern : supreme_matches) {
        pattern.pattern_type = "supreme_court_citation";
        pattern.format_context = "legal_citation";
        patterns.push_back(pattern);
    }
    
    // Statute citations
    std::regex statute_citation(R"((\d+)\s+(U\.S\.C\.?)\s+§?\s*(\d+))");
    auto statute_matches = extract_patterns_by_regex(pdf_data, {statute_citation});
    for (auto& pattern : statute_matches) {
        pattern.pattern_type = "statute_citation";
        pattern.format_context = "legal_reference";
        patterns.push_back(pattern);
    }
    
    return patterns;
}

AdvancedPatternRecognizer::DocumentTypeSignature AdvancedPatternRecognizer::recognize_financial_document_patterns(const std::vector<uint8_t>& pdf_data) {
    DocumentTypeSignature signature;
    signature.document_type = "financial";
    signature.identification_threshold = 0.7;
    
    // Financial structural patterns
    signature.structural_patterns = {
        "ASSETS",
        "LIABILITIES",
        "EQUITY",
        "REVENUE",
        "EXPENSES",
        "NET INCOME",
        "CASH FLOW",
        "BALANCE SHEET",
        "INCOME STATEMENT",
        "GAAP",
        "SEC FILING"
    };
    
    // Financial metadata patterns
    signature.metadata_patterns = {
        "10-K",
        "10-Q",
        "8-K",
        "Annual Report",
        "Quarterly Report",
        "Financial Statement",
        "Audit Report"
    };
    
    // Financial content patterns
    signature.content_patterns = {
        R"(\$\s*\d{1,3}(?:,\d{3})*(?:\.\d{2})?)", // Currency amounts
        R"(\(\$\s*\d{1,3}(?:,\d{3})*(?:\.\d{2})?\))", // Negative amounts in parentheses
        R"(\d{1,2}/\d{1,2}/\d{4})", // Date formats common in financial docs
        R"(CIK\s*:\s*\d+)", // SEC CIK numbers
        R"(CUSIP\s*:\s*[A-Z0-9]{9})" // CUSIP identifiers
    };
    
    signature.specialized_handler = "financial_document_processor";
    
    return signature;
}

std::vector<AdvancedPatternRecognizer::FormatPattern> AdvancedPatternRecognizer::extract_financial_statement_patterns(const std::vector<uint8_t>& pdf_data) {
    std::vector<FormatPattern> patterns;
    std::string content(pdf_data.begin(), pdf_data.end());
    
    // Currency amount patterns
    std::regex currency_pattern(R"(\$\s*(\d{1,3}(?:,\d{3})*)(?:\.(\d{2}))?)");
    auto currency_matches = extract_patterns_by_regex(pdf_data, {currency_pattern});
    for (auto& pattern : currency_matches) {
        pattern.pattern_type = "currency_amount";
        pattern.format_context = "financial_data";
        patterns.push_back(pattern);
    }
    
    // Percentage patterns
    std::regex percentage_pattern(R"((\d+(?:\.\d+)?)\s*%)");
    auto percentage_matches = extract_patterns_by_regex(pdf_data, {percentage_pattern});
    for (auto& pattern : percentage_matches) {
        pattern.pattern_type = "percentage";
        pattern.format_context = "financial_ratio";
        patterns.push_back(pattern);
    }
    
    // Fiscal year patterns
    std::regex fiscal_year_pattern(R"((?:FY|Fiscal Year)\s*(\d{4}))");
    auto fiscal_matches = extract_patterns_by_regex(pdf_data, {fiscal_year_pattern});
    for (auto& pattern : fiscal_matches) {
        pattern.pattern_type = "fiscal_year";
        pattern.format_context = "financial_period";
        patterns.push_back(pattern);
    }
    
    return patterns;
}

AdvancedPatternRecognizer::DocumentTypeSignature AdvancedPatternRecognizer::recognize_medical_document_patterns(const std::vector<uint8_t>& pdf_data) {
    DocumentTypeSignature signature;
    signature.document_type = "medical";
    signature.identification_threshold = 0.7;
    
    // Medical structural patterns
    signature.structural_patterns = {
        "PATIENT",
        "DIAGNOSIS",
        "TREATMENT",
        "MEDICATION",
        "DOSAGE",
        "SYMPTOMS",
        "MEDICAL HISTORY",
        "CLINICAL TRIAL",
        "HIPAA",
        "PHI",
        "CONFIDENTIAL MEDICAL"
    };
    
    // Medical metadata patterns
    signature.metadata_patterns = {
        "Medical Record",
        "Patient Chart",
        "Clinical Report",
        "Lab Results",
        "Prescription",
        "HIPAA Protected"
    };
    
    // Medical content patterns
    signature.content_patterns = {
        R"(\b[A-Z]{2,}\s*\d{2,8}\b)", // Medical record numbers
        R"(\b\d{3}-\d{2}-\d{4}\b)", // SSN format (for patient ID)
        R"(\b\d{1,2}/\d{1,2}/\d{4}\b)", // Date formats
        R"(\bmg|\bml|\bcc\b)", // Medical units
        R"(\bICD-\d+)", // ICD codes
        R"(\bCPT\s*\d{5})" // CPT codes
    };
    
    signature.specialized_handler = "medical_document_processor";
    
    return signature;
}

std::vector<AdvancedPatternRecognizer::FormatPattern> AdvancedPatternRecognizer::extract_medical_record_patterns(const std::vector<uint8_t>& pdf_data) {
    std::vector<FormatPattern> patterns;
    std::string content(pdf_data.begin(), pdf_data.end());
    
    // Medical record number patterns
    std::regex mrn_pattern(R"(\bMRN\s*:?\s*([A-Z0-9]{6,12})\b)");
    auto mrn_matches = extract_patterns_by_regex(pdf_data, {mrn_pattern});
    for (auto& pattern : mrn_matches) {
        pattern.pattern_type = "medical_record_number";
        pattern.format_context = "patient_identifier";
        patterns.push_back(pattern);
    }
    
    // ICD code patterns
    std::regex icd_pattern(R"(\b(ICD-(?:9|10))\s*:?\s*([A-Z]\d{2}(?:\.\d{1,3})?)\b)");
    auto icd_matches = extract_patterns_by_regex(pdf_data, {icd_pattern});
    for (auto& pattern : icd_matches) {
        pattern.pattern_type = "icd_code";
        pattern.format_context = "medical_diagnosis";
        patterns.push_back(pattern);
    }
    
    // Medication dosage patterns
    std::regex dosage_pattern(R"((\d+(?:\.\d+)?)\s*(mg|ml|cc|units?)\b)");
    auto dosage_matches = extract_patterns_by_regex(pdf_data, {dosage_pattern});
    for (auto& pattern : dosage_matches) {
        pattern.pattern_type = "medication_dosage";
        pattern.format_context = "medical_prescription";
        patterns.push_back(pattern);
    }
    
    return patterns;
}

AdvancedPatternRecognizer::DocumentTypeSignature AdvancedPatternRecognizer::recognize_academic_document_patterns(const std::vector<uint8_t>& pdf_data) {
    DocumentTypeSignature signature;
    signature.document_type = "academic";
    signature.identification_threshold = 0.7;
    
    // Academic structural patterns
    signature.structural_patterns = {
        "ABSTRACT",
        "INTRODUCTION",
        "METHODOLOGY",
        "RESULTS",
        "CONCLUSION",
        "REFERENCES",
        "BIBLIOGRAPHY",
        "CITATION",
        "PEER REVIEW",
        "JOURNAL",
        "UNIVERSITY"
    };
    
    // Academic metadata patterns
    signature.metadata_patterns = {
        "Research Paper",
        "Journal Article",
        "Thesis",
        "Dissertation",
        "Conference Paper",
        "Academic Publication"
    };
    
    // Academic content patterns
    signature.content_patterns = {
        R"(\b[A-Z][a-z]+,\s+[A-Z]\.\s+\(\d{4}\))", // Author citations
        R"(\bdoi:\s*10\.\d+/[^\s]+)", // DOI patterns
        R"(\bvol\.\s*\d+)", // Volume numbers
        R"(\bpp\.\s*\d+-\d+)", // Page ranges
        R"(\b\d{4}\b)", // Publication years
        R"(\bet\s+al\.)" // Et al. references
    };
    
    signature.specialized_handler = "academic_document_processor";
    
    return signature;
}

std::vector<AdvancedPatternRecognizer::FormatPattern> AdvancedPatternRecognizer::extract_academic_citation_patterns(const std::vector<uint8_t>& pdf_data) {
    std::vector<FormatPattern> patterns;
    std::string content(pdf_data.begin(), pdf_data.end());
    
    // APA style citations
    std::regex apa_pattern(R"(([A-Z][a-z]+,\s+[A-Z]\.(?:\s+[A-Z]\.)?)\s+\((\d{4})\)\.?\s+([^.]+)\.)");
    auto apa_matches = extract_patterns_by_regex(pdf_data, {apa_pattern});
    for (auto& pattern : apa_matches) {
        pattern.pattern_type = "apa_citation";
        pattern.format_context = "academic_reference";
        patterns.push_back(pattern);
    }
    
    // DOI patterns
    std::regex doi_pattern(R"(\bdoi:\s*(10\.\d+/[^\s]+))");
    auto doi_matches = extract_patterns_by_regex(pdf_data, {doi_pattern});
    for (auto& pattern : doi_matches) {
        pattern.pattern_type = "doi_reference";
        pattern.format_context = "academic_identifier";
        patterns.push_back(pattern);
    }
    
    // Journal reference patterns
    std::regex journal_pattern(R"(([A-Z][^,]+),\s+(\d+)\((\d+)\),\s+(\d+-\d+))");
    auto journal_matches = extract_patterns_by_regex(pdf_data, {journal_pattern});
    for (auto& pattern : journal_matches) {
        pattern.pattern_type = "journal_reference";
        pattern.format_context = "academic_publication";
        patterns.push_back(pattern);
    }
    
    return patterns;
}

std::vector<AdvancedPatternRecognizer::FormatPattern> AdvancedPatternRecognizer::analyze_complex_table_structures(const std::vector<uint8_t>& pdf_data) {
    std::vector<FormatPattern> patterns;
    std::string content(pdf_data.begin(), pdf_data.end());
    
    // Look for table markers in PDF structure
    size_t pos = 0;
    while ((pos = content.find("/Type /Table", pos)) != std::string::npos) {
        FormatPattern pattern;
        pattern.pattern_type = "pdf_table_structure";
        pattern.format_context = "document_structure";
        pattern.occurrence_positions.push_back(pos);
        pattern.pattern_confidence = 0.9;
        patterns.push_back(pattern);
        pos++;
    }
    
    // Look for tabular data patterns (repeated column structures)
    std::regex tabular_pattern(R"((\$?\d+(?:,\d{3})*(?:\.\d{2})?)\s+(\$?\d+(?:,\d{3})*(?:\.\d{2})?)\s+(\$?\d+(?:,\d{3})*(?:\.\d{2})?))");
    auto tabular_matches = extract_patterns_by_regex(pdf_data, {tabular_pattern});
    for (auto& pattern : tabular_matches) {
        pattern.pattern_type = "tabular_data";
        pattern.format_context = "data_table";
        patterns.push_back(pattern);
    }
    
    return patterns;
}

std::vector<AdvancedPatternRecognizer::FormatPattern> AdvancedPatternRecognizer::analyze_embedded_object_patterns(const std::vector<uint8_t>& pdf_data) {
    std::vector<FormatPattern> patterns;
    std::string content(pdf_data.begin(), pdf_data.end());
    
    // Image object patterns
    size_t pos = 0;
    while ((pos = content.find("/Type /XObject", pos)) != std::string::npos) {
        size_t subtype_pos = content.find("/Subtype", pos);
        if (subtype_pos != std::string::npos && subtype_pos < pos + 100) {
            FormatPattern pattern;
            pattern.pattern_type = "embedded_xobject";
            pattern.format_context = "pdf_object";
            pattern.occurrence_positions.push_back(pos);
            pattern.pattern_confidence = 0.85;
            patterns.push_back(pattern);
        }
        pos++;
    }
    
    // Font object patterns
    pos = 0;
    while ((pos = content.find("/Type /Font", pos)) != std::string::npos) {
        FormatPattern pattern;
        pattern.pattern_type = "embedded_font";
        pattern.format_context = "pdf_resource";
        pattern.occurrence_positions.push_back(pos);
        pattern.pattern_confidence = 0.8;
        patterns.push_back(pattern);
        pos++;
    }
    
    return patterns;
}

bool AdvancedPatternRecognizer::validate_specialized_pattern_integrity(const std::vector<uint8_t>& pdf_data, const std::vector<FormatPattern>& patterns) {
    // Validate that all critical patterns are preserved
    for (const auto& pattern : patterns) {
        if (pattern.pattern_confidence > 0.8) {
            // Check if high-confidence patterns are still present
            std::string content(pdf_data.begin(), pdf_data.end());
            
            bool pattern_found = false;
            for (size_t pos : pattern.occurrence_positions) {
                if (pos < content.length()) {
                    pattern_found = true;
                    break;
                }
            }
            
            if (!pattern_found) {
                return false; // Critical pattern missing
            }
        }
    }
    
    return true;
}

double AdvancedPatternRecognizer::calculate_type_confidence(const std::vector<uint8_t>& pdf_data, const DocumentTypeSignature& signature) {
    std::string content(pdf_data.begin(), pdf_data.end());
    double confidence = 0.0;
    
    // Check structural patterns
    int structural_matches = 0;
    for (const auto& pattern : signature.structural_patterns) {
        if (content.find(pattern) != std::string::npos) {
            structural_matches++;
        }
    }
    confidence += (static_cast<double>(structural_matches) / signature.structural_patterns.size()) * 0.4;
    
    // Check metadata patterns
    int metadata_matches = 0;
    for (const auto& pattern : signature.metadata_patterns) {
        if (content.find(pattern) != std::string::npos) {
            metadata_matches++;
        }
    }
    confidence += (static_cast<double>(metadata_matches) / signature.metadata_patterns.size()) * 0.3;
    
    // Check content patterns (regex)
    int content_matches = 0;
    for (const auto& pattern_str : signature.content_patterns) {
        try {
            std::regex pattern(pattern_str);
            if (std::regex_search(content, pattern)) {
                content_matches++;
            }
        } catch (const std::regex_error&) {
            // Skip invalid regex patterns
        }
    }
    confidence += (static_cast<double>(content_matches) / signature.content_patterns.size()) * 0.3;
    
    return confidence;
}

std::vector<AdvancedPatternRecognizer::FormatPattern> AdvancedPatternRecognizer::extract_patterns_by_regex(const std::vector<uint8_t>& pdf_data, const std::vector<std::regex>& patterns) {
    std::vector<FormatPattern> result_patterns;
    std::string content(pdf_data.begin(), pdf_data.end());
    
    for (const auto& regex_pattern : patterns) {
        std::sregex_iterator iter(content.begin(), content.end(), regex_pattern);
        std::sregex_iterator end;
        
        for (std::sregex_iterator i = iter; i != end; ++i) {
            std::smatch match = *i;
            FormatPattern pattern;
            pattern.occurrence_positions.push_back(match.position());
            pattern.pattern_confidence = 0.8;
            
            // Extract matched groups
            for (size_t j = 0; j < match.size(); ++j) {
                pattern.extracted_values["group_" + std::to_string(j)] = match[j].str();
            }
            
            result_patterns.push_back(pattern);
        }
    }
    
    return result_patterns;
}

void AdvancedPatternRecognizer::initialize_document_signature_database() {
    // Initialize with the document signatures created above
    document_signatures_[DocumentCategory::LEGAL] = {recognize_legal_document_patterns({})};
    document_signatures_[DocumentCategory::FINANCIAL] = {recognize_financial_document_patterns({})};
    document_signatures_[DocumentCategory::MEDICAL] = {recognize_medical_document_patterns({})};
    document_signatures_[DocumentCategory::ACADEMIC] = {recognize_academic_document_patterns({})};
}

void AdvancedPatternRecognizer::initialize_specialized_profile_database() {
    // Initialize specialized processing profiles for different document types
    SpecializedDocumentProfile legal_profile;
    legal_profile.profile_name = "Legal Document Processing";
    legal_profile.format_preservation_rules["citations"] = "preserve_exact_format";
    legal_profile.format_preservation_rules["case_numbers"] = "preserve_exact_format";
    legal_profile.critical_elements = {"citations", "case_numbers", "court_names", "dates"};
    legal_profile.validation_strategy = "strict_legal_compliance";
    specialized_profiles_["legal"] = legal_profile;
}

void AdvancedPatternRecognizer::initialize_pattern_template_database() {
    // Initialize common pattern templates for reuse
    pattern_templates_["currency"] = {
        FormatPattern{
            "currency_amount",
            R"(\$\s*\d{1,3}(?:,\d{3})*(?:\.\d{2})?)",
            {},
            0.9,
            "financial_data",
            {}
        }
    };
    
    pattern_templates_["date"] = {
        FormatPattern{
            "date_format",
            R"(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4})",
            {},
            0.85,
            "temporal_data",
            {}
        }
    };
}

void AdvancedPatternRecognizer::compile_regex_patterns_for_performance() {
    // Pre-compile frequently used regex patterns for better performance
    compiled_patterns_["currency"] = {
        std::regex(R"(\$\s*\d{1,3}(?:,\d{3})*(?:\.\d{2})?)"),
        std::regex(R"(\(\$\s*\d{1,3}(?:,\d{3})*(?:\.\d{2})?\))") // Negative amounts
    };
    
    compiled_patterns_["legal_citations"] = {
        std::regex(R"(\d+\s+[A-Z][a-z]+\.?\s+\d+)"),
        std::regex(R"(\d+\s+U\.S\.C\.?\s+§?\s*\d+)"),
        std::regex(R"(No\.\s+\d{2}-\d+)")
    };
    
    compiled_patterns_["medical_codes"] = {
        std::regex(R"(\bICD-\d+)"),
        std::regex(R"(\bCPT\s*\d{5})"),
        std::regex(R"(\bMRN\s*:?\s*[A-Z0-9]{6,12}\b)")
    };
}