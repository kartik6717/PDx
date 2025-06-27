#ifndef FORMAT_MIGRATION_MANAGER_HPP
#define FORMAT_MIGRATION_MANAGER_HPP
#include "stealth_macros.hpp"

#include <vector>
#include <map>
#include <string>
#include <memory>

class FormatMigrationManager {
public:
    struct FormatVersion {
        std::string version_identifier;
        std::string specification_standard;
        std::vector<std::string> supported_features;
        std::vector<std::string> deprecated_features;
        std::map<std::string, std::string> compatibility_mappings;
        double compatibility_score;
    };

    struct MigrationPlan {
        std::string source_format;
        std::string target_format;
        std::vector<std::string> migration_steps;
        std::map<std::string, std::string> feature_transformations;
        std::vector<std::string> preservation_priorities;
        double fidelity_preservation_score;
        bool is_lossless_migration;
    };

    struct LegacyFormatHandler {
        std::string format_name;
        std::string format_version;
        std::vector<std::string> identification_patterns;
        std::function<bool(const std::vector<uint8_t>&)> validator;
        std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)> modernizer;
        std::map<std::string, std::string> known_issues;
    };

    // Core migration functionality
    bool is_migration_needed(const std::vector<uint8_t>& pdf_data);
    MigrationPlan create_migration_plan(const std::vector<uint8_t>& pdf_data, const std::string& target_format);
    std::vector<uint8_t> execute_format_migration(const std::vector<uint8_t>& pdf_data, const MigrationPlan& plan);
    bool validate_migration_success(const std::vector<uint8_t>& original, const std::vector<uint8_t>& migrated);

    // Legacy format support
    FormatVersion detect_pdf_format_version(const std::vector<uint8_t>& pdf_data);
    bool handle_legacy_pdf_formats(std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> modernize_legacy_structures(const std::vector<uint8_t>& pdf_data);
    bool preserve_legacy_compatibility(std::vector<uint8_t>& pdf_data);

    // PDF version specific migrations
    std::vector<uint8_t> migrate_pdf_1_0_to_current(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> migrate_pdf_1_1_to_current(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> migrate_pdf_1_2_to_current(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> migrate_pdf_1_3_to_current(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> migrate_pdf_1_4_to_current(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> migrate_pdf_1_5_to_current(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> migrate_pdf_1_6_to_current(const std::vector<uint8_t>& pdf_data);
    std::vector<uint8_t> migrate_pdf_1_7_to_current(const std::vector<uint8_t>& pdf_data);

    // Feature-specific migrations
    void migrate_obsolete_compression_methods(std::vector<uint8_t>& pdf_data);
    void migrate_deprecated_color_spaces(std::vector<uint8_t>& pdf_data);
    void migrate_legacy_font_encodings(std::vector<uint8_t>& pdf_data);
    void migrate_outdated_security_handlers(std::vector<uint8_t>& pdf_data);
    void migrate_old_annotation_formats(std::vector<uint8_t>& pdf_data);
    void migrate_legacy_form_fields(std::vector<uint8_t>& pdf_data);

    // Compatibility preservation
    bool ensure_backward_compatibility(std::vector<uint8_t>& pdf_data, const std::string& minimum_version);
    void preserve_essential_legacy_features(std::vector<uint8_t>& pdf_data);
    void maintain_cross_version_compatibility(std::vector<uint8_t>& pdf_data);
    bool validate_compatibility_requirements(const std::vector<uint8_t>& pdf_data, const std::vector<std::string>& requirements);

    // Advanced migration features
    void implement_progressive_migration(std::vector<uint8_t>& pdf_data);
    void perform_selective_feature_migration(std::vector<uint8_t>& pdf_data, const std::vector<std::string>& features);
    void apply_migration_with_rollback_capability(std::vector<uint8_t>& pdf_data, const MigrationPlan& plan);
    std::vector<uint8_t> create_migration_checkpoint(const std::vector<uint8_t>& pdf_data);

    // Format validation and verification
    bool validate_format_compliance(const std::vector<uint8_t>& pdf_data, const std::string& target_format);
    std::vector<std::string> identify_compliance_issues(const std::vector<uint8_t>& pdf_data);
    bool verify_format_integrity_post_migration(const std::vector<uint8_t>& pdf_data);
    double calculate_migration_fidelity_score(const std::vector<uint8_t>& original, const std::vector<uint8_t>& migrated);

    // Specialized format handling
    bool handle_pdf_a_requirements(std::vector<uint8_t>& pdf_data, const std::string& pdfa_level);
    bool handle_pdf_x_requirements(std::vector<uint8_t>& pdf_data, const std::string& pdfx_standard);
    bool handle_pdf_ua_requirements(std::vector<uint8_t>& pdf_data);
    bool handle_pdf_e_requirements(std::vector<uint8_t>& pdf_data);

    // Migration reporting and analysis
    std::vector<std::string> generate_migration_report(const MigrationPlan& plan, bool success);
    void analyze_migration_impact(const std::vector<uint8_t>& original, const std::vector<uint8_t>& migrated);
    std::map<std::string, std::string> document_format_changes(const std::vector<uint8_t>& original, const std::vector<uint8_t>& migrated);
    void log_migration_statistics(const MigrationPlan& plan, double processing_time);

    // Configuration and customization
    void configure_migration_priorities(const std::vector<std::string>& priorities);
    void set_migration_aggressiveness(MigrationAggressiveness level);
    void enable_experimental_migrations(bool enabled);
    void set_compatibility_requirements(const std::vector<std::string>& requirements);

    enum class MigrationAggressiveness {
        CONSERVATIVE,           // Minimal changes, maximum compatibility
        MODERATE,              // Balanced approach with safe modernizations
        AGGRESSIVE,            // Comprehensive modernization
        EXPERIMENTAL           // Include experimental format improvements
    };

    enum class MigrationStrategy {
        PRESERVE_STRUCTURE,     // Maintain original structure as much as possible
        OPTIMIZE_MODERN,        // Optimize for modern PDF features
        MINIMIZE_SIZE,          // Focus on file size reduction
        MAXIMIZE_COMPATIBILITY, // Ensure broad compatibility
        CUSTOM                  // Use custom migration rules
    };

private:
    MigrationAggressiveness migration_level_ = MigrationAggressiveness::CONSERVATIVE;
    MigrationStrategy migration_strategy_ = MigrationStrategy::PRESERVE_STRUCTURE;
    std::vector<std::string> migration_priorities_;
    std::vector<std::string> compatibility_requirements_;
    
    // Format version database
    std::map<std::string, FormatVersion> supported_versions_;
    std::map<std::string, LegacyFormatHandler> legacy_handlers_;
    std::map<std::string, std::vector<std::string>> version_migration_paths_;
    
    // Migration rule database
    std::map<std::string, std::vector<std::string>> migration_rules_;
    std::map<std::string, std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)>> migration_functions_;
    std::map<std::string, double> migration_risk_scores_;
    
    // Compatibility matrices
    std::map<std::pair<std::string, std::string>, double> compatibility_matrix_;
    std::map<std::string, std::vector<std::string>> feature_dependencies_;
    std::map<std::string, std::vector<std::string>> breaking_changes_;
    
    // Internal helper functions
    void initialize_format_version_database();
    void initialize_legacy_format_handlers();
    void initialize_migration_rule_database();
    void build_compatibility_matrix();
    
    // Format detection helpers
    std::string extract_pdf_version_from_header(const std::vector<uint8_t>& pdf_data);
    std::vector<std::string> detect_used_features(const std::vector<uint8_t>& pdf_data);
    bool contains_legacy_structures(const std::vector<uint8_t>& pdf_data);
    std::vector<std::string> identify_deprecated_features(const std::vector<uint8_t>& pdf_data);
    
    // Migration planning helpers
    std::vector<std::string> calculate_migration_path(const std::string& source, const std::string& target);
    bool is_direct_migration_possible(const std::string& source, const std::string& target);
    std::vector<std::string> find_intermediate_migration_steps(const std::string& source, const std::string& target);
    double estimate_migration_complexity(const MigrationPlan& plan);
    
    // Migration execution helpers
    void apply_version_header_migration(std::vector<uint8_t>& pdf_data, const std::string& target_version);
    void apply_object_structure_migration(std::vector<uint8_t>& pdf_data, const std::vector<std::string>& rules);
    void apply_feature_specific_migrations(std::vector<uint8_t>& pdf_data, const std::vector<std::string>& features);
    void apply_compliance_adjustments(std::vector<uint8_t>& pdf_data, const std::string& target_format);
    
    // Validation helpers
    bool validate_pdf_structure_integrity(const std::vector<uint8_t>& pdf_data);
    bool validate_object_references(const std::vector<uint8_t>& pdf_data);
    bool validate_stream_integrity(const std::vector<uint8_t>& pdf_data);
    bool validate_cross_reference_table(const std::vector<uint8_t>& pdf_data);
    
    // Rollback and recovery helpers
    std::vector<uint8_t> create_rollback_point(const std::vector<uint8_t>& pdf_data);
    bool restore_from_rollback_point(std::vector<uint8_t>& pdf_data, const std::vector<uint8_t>& rollback_data);
    bool verify_migration_safety(const MigrationPlan& plan);
    
    // Format-specific helpers
    void handle_pdf_a_color_space_requirements(std::vector<uint8_t>& pdf_data);
    void handle_pdf_a_font_requirements(std::vector<uint8_t>& pdf_data);
    void handle_pdf_a_metadata_requirements(std::vector<uint8_t>& pdf_data);
    void handle_pdf_x_print_requirements(std::vector<uint8_t>& pdf_data);
    void handle_pdf_ua_accessibility_requirements(std::vector<uint8_t>& pdf_data);
};

#endif // FORMAT_MIGRATION_MANAGER_HPP
