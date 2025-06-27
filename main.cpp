#include "production_silence_wrapper.hpp"
#include "silence_enforcement_config.hpp"
#include "pdf_byte_fidelity_processor.hpp"
#include "production_api_layer.hpp"
#include "source_format_preservation.hpp"
#include "threat_intelligence_engine.hpp"
#include "binary_signature_camouflage.hpp"
#include "comprehensive_forensic_evasion.hpp"
#include "ml_evasion_engine.hpp"
#include "document_lifecycle_simulator.hpp"
#include "professional_metadata_engine.hpp"
#include "statistical_pattern_masker.hpp"
#include "advanced_pattern_recognizer.hpp"
#include "format_migration_manager.hpp"
#include "pdf_version_converter.hpp"
#include "entropy_analysis.hpp"
#include "performance_optimizer.hpp"
#include "temporal_consistency_manager.hpp"
#include "format_validation_engine.hpp"
#include "anti_fingerprint_engine.hpp"
#include "scrubber.hpp"
#include "scrubber_config.hpp"
#include "stealth_macros.hpp"
#include "silent_operation_manager.hpp"
#include "stream_suppression.hpp"
#include "library_silence_config.hpp"
#include "silent_status_tracker.hpp"
#include "silent_error_handler.hpp"
#include "silent_execution_wrappers.hpp"
#include "global_silence_enforcer.hpp"
#include "production_mode_checker.hpp"
#include "silent_operation_validator.hpp"
#include "complete_output_suppressor.hpp"
#include "complete_silence_enforcer.hpp"
#include "lightweight_trace_suppressor.hpp"
#include "secure_exceptions.hpp"
#include "secure_memory.hpp"
#include "memory_guard.hpp"
#include "memory_sanitizer.hpp"
#include "metadata_cleaner.hpp"
#include "pdf_integrity_checker.hpp"
#include "security_validation.hpp"
#include "stealth_scrubber.hpp"
#include "strict_trace_cleaner.hpp"
#include "trace_cleaner.hpp"
#include "integrity_checker.hpp"
#include "lightweight_memory_scrubber.hpp"
#include "monitoring_web_server.hpp"
#include "final_security_implementations.hpp"
#include <iostream>
#include <fstream>
#include <memory>

int main(int argc, char* argv[]) {
    // Complete silence is already enforced by headers
    
    if (argc < 2) {
        return 1;
    }

    std::string mode = argv[1];

    if (mode == "api-server") {
        auto api_server = std::make_unique<ProductionAPILayer>();

        ProductionAPILayer::APIConfiguration config;
        config.server_host = "0.0.0.0";
        config.server_port = 5000;
        config.max_concurrent_requests = 100;
        config.enable_authentication = true;
        config.enable_rate_limiting = true;

        api_server->configure_api_server(config);
        api_server->start_api_server();

        std::cin.get();
        api_server->stop_api_server();

    } else if (mode == "process-file") {
        if (argc < 3) {
            return 1;
        }

        std::string input_file = argv[2];
        std::string output_file = argc > 3 ? argv[3] : "output_processed.pdf";

        auto ml_engine = std::make_unique<MLEvasionEngine>();
        auto lifecycle_sim = std::make_unique<DocumentLifecycleSimulator>();
        auto metadata_engine = std::make_unique<ProfessionalMetadataEngine>();
        auto pattern_masker = std::make_unique<StatisticalPatternMasker>();
        auto pattern_recognizer = std::make_unique<AdvancedPatternRecognizer>();
        auto format_manager = std::make_unique<FormatMigrationManager>();
        auto version_converter = std::make_unique<PDFVersionConverter>();
        auto entropy_analyzer = std::make_unique<EntropyAnalysis>();
        auto performance_optimizer = std::make_unique<PerformanceOptimizer>();
        auto temporal_manager = std::make_unique<TemporalConsistencyManager>();
        auto validation_engine = std::make_unique<FormatValidationEngine>();
        auto anti_fingerprint_engine = std::make_unique<AntiFingerprintEngine>();
        
        // Initialize security and stealth components
        auto stealth_scrubber = std::make_unique<StealthScrubber>();
        auto trace_cleaner = std::make_unique<TraceCleaner>();
        auto metadata_cleaner = std::make_unique<MetadataCleaner>();
        auto memory_guard = std::make_unique<MemoryGuard>();
        auto memory_sanitizer = std::make_unique<MemorySanitizer>();
        auto lightweight_scrubber = std::make_unique<LightweightMemoryScrubber>();
        auto pdf_integrity_checker = std::make_unique<PDFIntegrityChecker>();
        auto integrity_checker = std::make_unique<IntegrityChecker>();

        auto scrubber = std::make_unique<PDFScrubber>();
        scrubber->set_ml_evasion_engine(ml_engine.get());
        scrubber->set_lifecycle_simulator(lifecycle_sim.get());
        scrubber->set_metadata_engine(metadata_engine.get());
        scrubber->set_pattern_masker(pattern_masker.get());
        scrubber->set_pattern_recognizer(pattern_recognizer.get());
        scrubber->set_format_manager(format_manager.get());
        scrubber->set_version_converter(version_converter.get());
        scrubber->set_entropy_analyzer(entropy_analyzer.get());
        scrubber->set_performance_optimizer(performance_optimizer.get());
        scrubber->set_temporal_manager(temporal_manager.get());
        scrubber->set_validation_engine(validation_engine.get());
        scrubber->set_anti_fingerprint_engine(anti_fingerprint_engine.get());
        
        // Set security and stealth components
        scrubber->set_stealth_scrubber(stealth_scrubber.get());
        scrubber->set_trace_cleaner(trace_cleaner.get());
        scrubber->set_metadata_cleaner(metadata_cleaner.get());
        scrubber->set_memory_guard(memory_guard.get());
        scrubber->set_memory_sanitizer(memory_sanitizer.get());
        scrubber->set_pdf_integrity_checker(pdf_integrity_checker.get());
        scrubber->set_integrity_checker(integrity_checker.get());

        ScrubberConfig scrub_config;
        scrub_config.remove_metadata = true;
        scrub_config.remove_javascript = true;
        scrub_config.remove_embedded_files = true;
        scrub_config.remove_external_references = true;
        scrub_config.apply_entropy_masking = true;
        scrub_config.apply_pattern_disruption = true;
        scrub_config.apply_temporal_fuzzing = true;
        scrub_config.validate_structure = true;
        scrub_config.optimize_performance = true;
        scrub_config.enable_ml_evasion = true;
        scrub_config.simulate_lifecycle = true;
        scrub_config.apply_professional_metadata = true;
        scrub_config.deep_clean = true;

        std::ifstream input(input_file, std::ios::binary);
        if (!input) {
            return 1;
        }

        std::vector<uint8_t> pdf_data((std::istreambuf_iterator<char>(input)),
                                     std::istreambuf_iterator<char>());
        input.close();

        // Convert target PDF to PDF 1.4 before any processing
        pdf_data = PDFVersionConverter::convert_to_pdf14(pdf_data);

        std::string pdf_content(pdf_data.begin(), pdf_data.end());
        auto result = scrubber->scrub_pdf(pdf_content, scrub_config);

        if (result.success) {
            std::ofstream output(output_file, std::ios::binary);
            if (output) {
                output.write(result.scrubbed_content.data(), result.scrubbed_content.size());
                output.close();
            }
        }
    } else if (mode == "test-silent") {
        auto validator = SilentOperationValidator::validate_silent_operation();
        return validator.is_completely_silent ? 0 : 1;
    } else if (mode == "forensic-analyze") {
        if (argc < 3) {
            return 1;
        }

        std::string pdf_file = argv[2];
        auto forensic_validator = std::make_unique<ForensicValidator>();

        std::ifstream input(pdf_file, std::ios::binary);
        if (!input) {
            return 1;
        }

        std::string pdf_content((std::istreambuf_iterator<char>(input)),
                               std::istreambuf_iterator<char>());
        input.close();

        auto validation = forensic_validator->validate_forensic_invisibility(
            pdf_content.data(), pdf_content.size());

        return validation.is_forensically_clean ? 0 : 1;
    }

    return 0;
}