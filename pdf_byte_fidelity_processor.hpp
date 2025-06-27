#ifndef PDF_BYTE_FIDELITY_PROCESSOR_HPP
#define PDF_BYTE_FIDELITY_PROCESSOR_HPP
#include "stealth_macros.hpp"

#include "source_format_preservation.hpp"
#include "format_validation_engine.hpp"
#include "document_lifecycle_simulator.hpp"
#include "professional_metadata_engine.hpp"
#include "statistical_pattern_masker.hpp"
#include "ml_evasion_engine.hpp"
#include "zero_trace_processor.hpp"
#include "temporal_consistency_manager.hpp"
#include "performance_optimizer.hpp"
#include "advanced_pattern_recognizer.hpp"
#include "format_migration_manager.hpp"
// Security and Stealth Components Integration
#include "stealth_scrubber.hpp"
#include "trace_cleaner.hpp"
#include "metadata_cleaner.hpp"
#include "memory_guard.hpp"
#include "memory_sanitizer.hpp"
#include "pdf_integrity_checker.hpp"
#include "integrity_checker.hpp"

#include <vector>
#include <string>
#include <memory>

class PDFByteFidelityProcessor {
public:
    struct ProcessingConfig {
        bool enable_format_preservation = true;
        bool enable_professional_simulation = true;
        bool enable_statistical_masking = true;
        bool enable_ml_evasion = true;
        bool enable_zero_trace_processing = true;
        bool enable_temporal_consistency = true;
        bool enable_performance_optimization = true;
        bool enable_pattern_recognition = true;
        bool enable_format_migration = true;
        
        // Processing modes
        bool injection_only_mode = true;
        bool strict_validation_mode = true;
        bool forensic_resistance_mode = true;
        
        // Target configurations
        std::string target_document_type = "legal";
        std::string target_software_ecosystem = "adobe";
        std::string target_organization_type = "enterprise";
    };

    struct ProcessingResult {
        bool success = false;
        std::vector<uint8_t> processed_data;
        std::vector<std::string> processing_log;
        std::vector<std::string> validation_results;
        double fidelity_score = 0.0;
        double authenticity_score = 0.0;
        double evasion_score = 0.0;
        size_t processing_time_ms = 0;
    };

    // Core processing functions
    ProcessingResult process_pdf_with_byte_fidelity(
        const std::vector<uint8_t>& source_pdf,
        const std::vector<uint8_t>& injection_data = {}
    );
    
    ProcessingResult inject_invisible_data_with_fidelity(
        const std::vector<uint8_t>& source_pdf,
        const std::vector<uint8_t>& data_to_inject
    );
    
    std::vector<uint8_t> extract_invisible_data_with_validation(
        const std::vector<uint8_t>& processed_pdf
    );

    // Configuration management
    void configure_processing(const ProcessingConfig& config);
    void set_injection_only_mode(bool enabled);
    void set_strict_validation_mode(bool enabled);
    void set_forensic_resistance_mode(bool enabled);
    
    // Validation and verification
    bool validate_complete_byte_fidelity(
        const std::vector<uint8_t>& source,
        const std::vector<uint8_t>& processed
    );
    
    bool verify_injection_only_operations(
        const std::vector<uint8_t>& source,
        const std::vector<uint8_t>& processed
    );
    
    ProcessingResult perform_comprehensive_validation(
        const std::vector<uint8_t>& source,
        const std::vector<uint8_t>& processed
    );

private:
    ProcessingConfig config_;
    
    // Core processing components
    std::unique_ptr<SourceFormatPreservation> format_preservation_;
    std::unique_ptr<FormatValidationEngine> validation_engine_;
    std::unique_ptr<DocumentLifecycleSimulator> lifecycle_simulator_;
    std::unique_ptr<ProfessionalMetadataEngine> metadata_engine_;
    std::unique_ptr<StatisticalPatternMasker> pattern_masker_;
    std::unique_ptr<MLEvasionEngine> ml_evasion_;
    std::unique_ptr<ZeroTraceProcessor> trace_processor_;
    std::unique_ptr<TemporalConsistencyManager> temporal_manager_;
    std::unique_ptr<PerformanceOptimizer> performance_optimizer_;
    std::unique_ptr<AdvancedPatternRecognizer> pattern_recognizer_;
    std::unique_ptr<FormatMigrationManager> migration_manager_;
    
    // Security and Stealth Components
    std::unique_ptr<StealthScrubber> stealth_scrubber_;
    std::unique_ptr<TraceCleaner> trace_cleaner_;
    std::unique_ptr<MetadataCleaner> metadata_cleaner_;
    std::unique_ptr<MemoryGuard> memory_guard_;
    std::unique_ptr<MemorySanitizer> memory_sanitizer_;
    std::unique_ptr<PDFIntegrityChecker> pdf_integrity_checker_;
    std::unique_ptr<IntegrityChecker> integrity_checker_;
    
    // Internal processing methods
    void initialize_processing_components();
    std::vector<uint8_t> apply_format_preservation(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> apply_professional_simulation(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> apply_statistical_masking(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> apply_ml_evasion(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> apply_zero_trace_processing(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> apply_temporal_consistency(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> apply_performance_optimization(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> apply_pattern_recognition(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> apply_format_migration(const std::vector<uint8_t>& pdf_data);
    
    // Injection processing
    std::vector<uint8_t> perform_safe_injection(
        const std::vector<uint8_t>& source_pdf,
        const std::vector<uint8_t>& injection_data
    );
    
    std::vector<size_t> identify_safe_injection_zones(const std::vector<uint8_t>& pdf_data);
    bool validate_injection_safety(
        const std::vector<uint8_t>& pdf_data,
        size_t injection_position,
        const std::vector<uint8_t>& injection_data
    );
    
    // Validation helpers
    void log_processing_step(const std::string& step, ProcessingResult& result);
    void validate_processing_step(
        const std::vector<uint8_t>& before,
        const std::vector<uint8_t>& after,
        const std::string& step_name,
        ProcessingResult& result
    );
};

#endif // PDF_BYTE_FIDELITY_PROCESSOR_HPP
