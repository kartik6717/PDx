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
#include <iostream>
#include <fstream>
#include <memory>

int main(int argc, char* argv[]) {
    // IMMEDIATE COMPLETE OUTPUT SUPPRESSION
    CompleteOutputSuppressor::suppress_all_output();
    GlobalSilenceEnforcer::activate_complete_silence();
    
    INITIALIZE_STEALTH_MODE();
    SilentOperationManager::enable_stealth_mode();
    StreamSuppression::suppress_all_streams();
    LibrarySilenceConfig::configure_all_libraries_silent();
    SilentStatusTracker::enable_tracking(false);
    
    // Validate silence enforcement
    if (ProductionModeChecker::is_production_mode()) {
        auto validation = SilentOperationValidator::validate_silent_operation();
        if (!validation.is_completely_silent) {
            std::exit(1);
        }
    }

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

        std::string pdf_content((std::istreambuf_iterator<char>(input)),
                               std::istreambuf_iterator<char>());
        input.close();

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