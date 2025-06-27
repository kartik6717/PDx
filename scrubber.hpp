#pragma once
#include "pdf_parser.hpp"
// Advanced Processing Engine Includes - Integration Complete
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
// Security and Stealth Components Integration
#include "stealth_scrubber.hpp"
#include "trace_cleaner.hpp"
#include "strict_trace_cleaner.hpp"
#include "metadata_cleaner.hpp"
#include "memory_guard.hpp"
#include "memory_sanitizer.hpp"
#include "lightweight_memory_scrubber.hpp"
#include "pdf_integrity_checker.hpp"
#include "integrity_checker.hpp"
#include "silent_operation_manager.hpp"
#include "complete_silence_enforcer.hpp"
#include "global_silence_enforcer.hpp"
#include "lightweight_trace_suppressor.hpp"
#include "complete_output_suppressor.hpp"
#include <vector>
#include <string>
#include <set>
#include <chrono>
#include <mutex>
#include <atomic>
#include <shared_mutex>
#include <thread>
#include <future>
#include <functional>
#include <climits>
#include <regex>
#include <openssl/rand.h>
#include <openssl/evp.h>

class PDFScrubber {
public:
    // Configuration enhancements
    enum class IntensityLevel { BASIC, STANDARD, AGGRESSIVE, MAXIMUM };
    enum class ScrubbingProfile { DEFAULT, ANONYMIZER, FORENSIC_EVASION, COMPLIANCE };
    
    PDFScrubber();
    ~PDFScrubber();
    
    // Main scrubbing function
    PDFStructure scrub(const PDFStructure& input_structure);
    
    // Configuration methods
    void set_intensity_level(IntensityLevel level);
    void set_scrubbing_profile(ScrubbingProfile profile);
    void add_to_whitelist(const std::string& metadata_key);
    void add_to_blacklist(const std::string& metadata_key);
    void clear_whitelist();
    void clear_blacklist();
    
    // Performance configuration
    bool enable_parallel_processing_;
    bool enable_incremental_scrubbing_;
    
    // Secure entropy generation
    std::vector<uint8_t> generate_secure_random_bytes(size_t length);
    bool initialize_secure_random();
    void secure_zero_memory(std::vector<uint8_t>& data);
    void secure_zero_memory(std::string& str);
    
    // Advanced Engine Setters - Integration Complete
    void set_ml_evasion_engine(MLEvasionEngine* engine);
    void set_lifecycle_simulator(DocumentLifecycleSimulator* simulator);
    void set_metadata_engine(ProfessionalMetadataEngine* engine);
    void set_pattern_masker(StatisticalPatternMasker* masker);
    void set_pattern_recognizer(AdvancedPatternRecognizer* recognizer);
    void set_format_manager(FormatMigrationManager* manager);
    void set_version_converter(PDFVersionConverter* converter);
    void set_entropy_analyzer(EntropyAnalysis* analyzer);
    void set_performance_optimizer(PerformanceOptimizer* optimizer);
    void set_temporal_manager(TemporalConsistencyManager* manager);
    void set_validation_engine(FormatValidationEngine* engine);
    void set_anti_fingerprint_engine(AntiFingerprintEngine* engine);
    
    // Security and Stealth Component Setters
    void set_stealth_scrubber(StealthScrubber* scrubber);
    void set_trace_cleaner(TraceCleaner* cleaner);
    void set_metadata_cleaner(MetadataCleaner* cleaner);
    void set_memory_guard(MemoryGuard* guard);
    void set_memory_sanitizer(MemorySanitizer* sanitizer);
    void set_pdf_integrity_checker(PDFIntegrityChecker* checker);
    void set_integrity_checker(IntegrityChecker* checker);
    
    // Security component integration helpers
    std::vector<uint8_t> structure_to_bytes(const PDFStructure& structure);
    PDFStructure bytes_to_structure(const std::vector<uint8_t>& bytes);
    
    // Result structure for PDF scrubbing
    struct ScrubResult {
        bool success = false;
        std::vector<uint8_t> scrubbed_content;
        std::string error_message;
    };
    
    // Main scrubbing method with config
    ScrubResult scrub_pdf(const std::string& pdf_content, const ScrubberConfig& config);
    
    // File processing interface
    bool scrub_pdf(const std::string& input_path, const std::string& output_path);
    
private:
    // Core scrubbing operations
    void scrub_info_object(PDFStructure& structure);
    void scrub_metadata_objects(PDFStructure& structure);
    void scrub_document_id(PDFStructure& structure);
    void scrub_encryption_data(PDFStructure& structure);
    void scrub_javascript_actions(PDFStructure& structure);
    void scrub_form_data(PDFStructure& structure);
    void scrub_embedded_files(PDFStructure& structure);
    void scrub_producer_information(PDFStructure& structure);
    void scrub_creation_dates(PDFStructure& structure);
    void scrub_modification_dates(PDFStructure& structure);
    void scrub_author_information(PDFStructure& structure);
    void scrub_application_data(PDFStructure& structure);
    void scrub_annotations(PDFStructure& structure);
    void scrub_bookmarks(PDFStructure& structure);
    void scrub_named_destinations(PDFStructure& structure);
    void scrub_optional_content(PDFStructure& structure);
    void scrub_digital_signatures(PDFStructure& structure);
    void scrub_usage_rights(PDFStructure& structure);
    void scrub_viewer_preferences(PDFStructure& structure);
    void scrub_thread_information(PDFStructure& structure);
    void scrub_web_capture_info(PDFStructure& structure);
    void scrub_structure_tree(PDFStructure& structure);
    
    // Advanced scrubbing techniques
    void remove_ghost_objects(PDFStructure& structure);
    void neutralize_hidden_streams(PDFStructure& structure);
    void clean_object_streams(PDFStructure& structure);
    void remove_incremental_updates(PDFStructure& structure);
    void scrub_whitespace_data(PDFStructure& structure);
    void remove_comment_blocks(PDFStructure& structure);
    void clean_xref_streams(PDFStructure& structure);
    void neutralize_linearization(PDFStructure& structure);
    void remove_page_thumbnails(PDFStructure& structure);
    void clean_resource_dictionaries(PDFStructure& structure);
    
    // Object manipulation
    void remove_object(PDFStructure& structure, int obj_number);
    void replace_object_content(PDFStructure& structure, int obj_number, const std::string& new_content);
    void insert_null_object(PDFStructure& structure, int obj_number);
    void modify_object_dictionary(PDFObject& obj, const std::string& key, const std::string& value);
    void remove_dictionary_key(PDFObject& obj, const std::string& key);
    
    // Reference handling
    void update_object_references(PDFStructure& structure, int old_obj_num, int new_obj_num);
    void remove_dangling_references(PDFStructure& structure);
    std::set<int> find_referenced_objects(const PDFStructure& structure);
    
    // Stream processing
    void scrub_stream_metadata(PDFObject& obj);
    void remove_stream_filters(PDFObject& obj);
    void neutralize_stream_data(PDFObject& obj);
    
    // Trailer manipulation
    void scrub_trailer_dictionary(PDFStructure& structure);
    void update_trailer_references(PDFStructure& structure);
    void recalculate_trailer_size(PDFStructure& structure);
    
    // XRef table cleaning
    void rebuild_xref_table(PDFStructure& structure);
    void remove_unused_xref_entries(PDFStructure& structure);
    void compact_object_numbers(PDFStructure& structure);
    
    // Anti-forensic techniques
    void apply_entropy_neutralization(PDFStructure& structure);
    void randomize_object_order(PDFStructure& structure);
    void insert_decoy_objects(PDFStructure& structure);
    void normalize_whitespace(PDFStructure& structure);
    void remove_forensic_markers(PDFStructure& structure);
    void eliminate_timing_artifacts(PDFStructure& structure);
    void scrub_memory_artifacts(PDFStructure& structure);
    
    // Validation and cleanup
    void validate_scrubbed_structure(const PDFStructure& structure);
    void optimize_object_layout(PDFStructure& structure);
    void ensure_pdf_compliance(PDFStructure& structure);
    
    // Utility functions
    bool is_info_object(const PDFObject& obj);
    bool is_metadata_object(const PDFObject& obj);
    bool contains_javascript(const PDFObject& obj);
    bool is_annotation_object(const PDFObject& obj);
    bool is_form_field_object(const PDFObject& obj);
    bool has_embedded_file(const PDFObject& obj);
    bool is_ghost_object(const PDFObject& obj);
    bool is_system_generated(const PDFObject& obj);
    
    std::vector<int> get_objects_to_remove(const PDFStructure& structure);
    std::vector<int> get_objects_to_modify(const PDFStructure& structure);
    std::map<std::string, std::string> get_safe_dictionary_entries(const std::map<std::string, std::string>& dict);
    
    // Configuration enhancements
    IntensityLevel intensity_level_;
    ScrubbingProfile scrubbing_profile_;
    std::vector<std::string> metadata_whitelist_;
    std::vector<std::string> metadata_blacklist_;
    
    // Configuration
    bool preserve_visual_content_;
    bool aggressive_scrubbing_;
    bool remove_all_metadata_;
    bool neutralize_javascript_;
    bool remove_form_data_;
    bool clean_embedded_files_;
    bool remove_annotations_;
    bool scrub_creation_info_;
    
    // Secure entropy state
    bool secure_random_initialized_;
    std::vector<uint8_t> entropy_pool_;
    std::mutex entropy_mutex_;
    std::mutex config_mutex_;
    
    // Advanced Engine Pointers - Integration Complete
    MLEvasionEngine* ml_evasion_engine_;
    DocumentLifecycleSimulator* lifecycle_simulator_;
    ProfessionalMetadataEngine* metadata_engine_;
    StatisticalPatternMasker* pattern_masker_;
    AdvancedPatternRecognizer* pattern_recognizer_;
    FormatMigrationManager* format_manager_;
    PDFVersionConverter* version_converter_;
    EntropyAnalysis* entropy_analyzer_;
    PerformanceOptimizer* performance_optimizer_;
    TemporalConsistencyManager* temporal_manager_;
    FormatValidationEngine* validation_engine_;
    AntiFingerprintEngine* anti_fingerprint_engine_;
    
    // Security and Stealth Component Pointers - Integration Complete
    StealthScrubber* stealth_scrubber_;
    TraceCleaner* trace_cleaner_;
    MetadataCleaner* metadata_cleaner_;
    MemoryGuard* memory_guard_;
    MemorySanitizer* memory_sanitizer_;
    LightweightMemoryScrubber* lightweight_scrubber_;
    PDFIntegrityChecker* pdf_integrity_checker_;
    IntegrityChecker* integrity_checker_;
    
    // Advanced anti-forensic features
    void advanced_entropy_manipulation(PDFStructure& structure);
    void remove_temporal_artifacts(PDFStructure& structure);
    void enhanced_ghost_object_detection(PDFStructure& structure);
    
    // Performance optimizations
    void parallel_process_objects(PDFStructure& structure);
    void optimize_memory_usage(PDFStructure& structure);
    
    // Validation and recovery
    bool pre_scrubbing_validation(const PDFStructure& structure);
    bool post_scrubbing_integrity_check(const PDFStructure& structure);
    void create_rollback_point(const PDFStructure& structure);
    bool rollback_on_failure();
    
    // Backup for rollback
    PDFStructure backup_structure_;
    bool has_backup_;
    
    // Thread-safe statistics using atomic operations
    std::atomic<int> objects_removed_;
    std::atomic<int> objects_modified_;
    std::atomic<int> streams_cleaned_;
    std::atomic<int> references_updated_;
    
    // Thread synchronization
    mutable std::shared_mutex structure_mutex_;     // For PDFStructure access
    mutable std::mutex config_mutex_;               // For configuration changes
    mutable std::mutex stats_mutex_;                // For statistics updates
    mutable std::mutex backup_mutex_;               // For backup operations
    
    // Timing (thread-local or protected)
    std::chrono::steady_clock::time_point start_time_;
    std::chrono::steady_clock::time_point end_time_;
    
    // Thread-safe helper methods
    void safe_increment_stat(std::atomic<int>& stat, int value = 1);
    void thread_safe_remove_object(PDFStructure& structure, int obj_number);
    void thread_safe_modify_object(PDFStructure& structure, int obj_number, 
                                   const std::function<void(PDFObject&)>& modifier);
    
    // Parallel processing with thread safety
    void parallel_process_objects_threadsafe(PDFStructure& structure);
    void process_object_batch(std::vector<PDFObject*>& batch, 
                              const std::string& object_type);
    
    // Memory management and optimization
    void optimize_stream_memory_usage(PDFObject& obj);
    bool check_memory_bounds(size_t current_size, size_t additional_size);
    void prevent_memory_fragmentation(std::vector<uint8_t>& stream_data, 
                                     const std::vector<uint8_t>& pattern);
    void safe_entropy_insertion(PDFObject& obj, const std::vector<uint8_t>& pattern);
    size_t calculate_safe_pattern_size(size_t stream_size, const std::string& object_type);
    
    // Memory limits and monitoring
    static constexpr size_t MAX_STREAM_SIZE = 100 * 1024 * 1024; // 100MB limit
    static constexpr size_t MAX_PATTERN_SIZE = 1024; // 1KB pattern limit
    static constexpr size_t MEMORY_SAFETY_THRESHOLD = 0.8; // 80% of available memory
    std::atomic<size_t> total_memory_usage_;
    mutable std::mutex memory_mutex_;
    
    // Integer overflow protection
    static constexpr int MAX_SAFE_OBJECT_NUMBER = INT_MAX - 1000; // Safety margin
    static constexpr int MIN_OBJECT_NUMBER = 1;
    bool check_object_number_overflow(int current_max, int additional_objects);
    int safe_increment_object_number(int current_number);
    bool validate_object_number_range(const PDFStructure& structure);
    void fix_object_number_overflow(PDFStructure& structure);
    
    // Reference validation and circular dependency detection
    bool detect_circular_references(const PDFStructure& structure);
    bool validate_reference_integrity(const PDFStructure& structure);
    std::set<int> get_object_references(const PDFObject& obj);
    bool has_circular_dependency(const PDFStructure& structure, int start_obj, 
                                std::set<int>& visited, std::set<int>& recursion_stack);
    void fix_circular_references(PDFStructure& structure);
    bool is_valid_reference_format(const std::string& reference);
    void validate_and_fix_references(PDFStructure& structure);
    
    // Regex performance and ReDoS protection
    static constexpr size_t MAX_REGEX_INPUT_SIZE = 1024 * 1024; // 1MB limit
    static constexpr std::chrono::milliseconds REGEX_TIMEOUT{100}; // 100ms timeout
    bool safe_regex_replace(std::string& input, const std::regex& pattern, 
                           const std::string& replacement);
    std::string safe_normalize_whitespace(const std::string& input);
    std::string safe_remove_comment_blocks(const std::string& input);
    bool check_regex_complexity(const std::string& input);
    std::string sanitize_regex_input(const std::string& input);
    
    // Configuration state validation and consistency
    struct ConfigurationState {
        IntensityLevel intensity_level;
        ScrubbingProfile scrubbing_profile;
        bool preserve_visual_content;
        bool aggressive_scrubbing;
        bool remove_all_metadata;
        bool neutralize_javascript;
        bool remove_form_data;
        bool clean_embedded_files;
        bool remove_annotations;
        bool scrub_creation_info;
        bool enable_parallel_processing;
        bool enable_incremental_scrubbing;
        std::vector<std::string> metadata_whitelist;
        std::vector<std::string> metadata_blacklist;
    };
    
    bool validate_configuration_consistency();
    void resolve_configuration_conflicts();
    void apply_intensity_level_settings(IntensityLevel level);
    void apply_scrubbing_profile_settings(ScrubbingProfile profile);
    bool is_configuration_combination_valid(IntensityLevel level, ScrubbingProfile profile);
    ConfigurationState get_current_configuration() const;
    void log_configuration_changes(const std::string& operation, const std::string& details);
    
    // Backup recovery race condition protection
    struct BackupState {
        PDFStructure backup_structure;
        std::atomic<bool> has_backup;
        std::chrono::steady_clock::time_point backup_timestamp;
        std::string backup_context;
        
        BackupState() : has_backup(false) {}
    };
    
    mutable std::mutex backup_state_mutex_;
    BackupState backup_state_;
    
    bool atomic_create_rollback_point(const PDFStructure& structure, const std::string& context);
    bool atomic_rollback_on_failure(PDFStructure& structure);
    bool is_backup_valid() const;
    void clear_backup_safely();
    std::chrono::milliseconds get_backup_age() const;
    
    // Stream data type safety and validation
    enum class StreamType {
        TEXT,
        BINARY,
        IMAGE,
        FONT,
        UNKNOWN
    };
    
    StreamType detect_stream_type(const PDFObject& obj) const;
    bool is_safe_for_string_conversion(const std::vector<uint8_t>& data) const;
    std::vector<uint8_t> safe_string_to_bytes(const std::string& str) const;
    std::string safe_bytes_to_string(const std::vector<uint8_t>& bytes) const;
    bool validate_stream_content_type(const PDFObject& obj) const;
    void preserve_binary_stream_integrity(PDFObject& obj) const;
    
    // Resource exhaustion protection
    struct ResourceLimits {
        static constexpr size_t MAX_DECOY_OBJECTS = 10;
        static constexpr size_t MAX_ENTROPY_INSERTIONS_PER_OBJECT = 5;
        static constexpr size_t MAX_TOTAL_ENTROPY_INSERTIONS = 100;
        static constexpr size_t MAX_PROCESSING_TIME_MS = 300000; // 5 minutes
        static constexpr size_t MAX_MEMORY_USAGE_MB = 512; // 512MB
        static constexpr size_t MAX_OBJECT_COUNT = 10000;
    };
    
    std::atomic<size_t> decoy_objects_created_;
    std::atomic<size_t> entropy_insertions_count_;
    std::atomic<size_t> total_objects_processed_;
    std::chrono::steady_clock::time_point processing_start_time_;
    mutable std::mutex resource_tracking_mutex_;
    
    bool check_resource_limits();
    bool can_create_decoy_objects(size_t count) const;
    bool can_perform_entropy_insertion() const;
    void track_decoy_object_creation(size_t count);
    void track_entropy_insertion();
    void reset_resource_counters();
    size_t get_current_memory_usage_mb() const;
    std::chrono::milliseconds get_processing_time() const;
};
