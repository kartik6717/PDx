#include "secure_exceptions.hpp"
#include "stealth_macros.hpp"
#include "secure_memory.hpp"
#include "scrubber.hpp"
#include "utils.hpp"
#include "complete_silence_enforcer.hpp"
#include "memory_guard.hpp"
#include "memory_sanitizer.hpp"
#include "metadata_cleaner.hpp"
#include "stealth_scrubber.hpp"
#include "trace_cleaner.hpp"
#include "strict_trace_cleaner.hpp"
#include "lightweight_memory_scrubber.hpp"
#include "pdf_integrity_checker.hpp"
#include "format_validation_engine.hpp"
#include "final_security_implementations.hpp"
#include <algorithm>
#include <random>
#include <chrono>
#include <regex>
#include <iostream>

PDFScrubber::PDFScrubber() 
    : intensity_level_(IntensityLevel::STANDARD)
    , scrubbing_profile_(ScrubbingProfile::DEFAULT)
    , preserve_visual_content_(true)
    , aggressive_scrubbing_(true)
    , remove_all_metadata_(true)
    , neutralize_javascript_(true)
    , remove_form_data_(false)
    , clean_embedded_files_(true)
    , remove_annotations_(false)
    , scrub_creation_info_(true)
    , enable_parallel_processing_(false)
    , enable_incremental_scrubbing_(false)
    , secure_random_initialized_(false)
    // MISSING ENGINE INITIALIZATION - Integration Fix
    , ml_evasion_engine_(nullptr)
    , lifecycle_simulator_(nullptr)
    , metadata_engine_(nullptr)
    , pattern_masker_(nullptr)
    , pattern_recognizer_(nullptr)
    , format_manager_(nullptr)
    , version_converter_(nullptr)
    , entropy_analyzer_(nullptr)
    , performance_optimizer_(nullptr)
    , temporal_manager_(nullptr)
    , validation_engine_(nullptr)
    , anti_fingerprint_engine_(nullptr)
    // Security and Stealth Component Initialization
    , stealth_scrubber_(nullptr)
    , trace_cleaner_(nullptr)
    , metadata_cleaner_(nullptr)
    , memory_guard_(nullptr)
    , memory_sanitizer_(nullptr)
    , lightweight_scrubber_(nullptr)
    , pdf_integrity_checker_(nullptr)
    , integrity_checker_(nullptr)
    , has_backup_(false)
    , objects_removed_(0)
    , objects_modified_(0)
    , streams_cleaned_(0)
    , references_updated_(0)
    , total_memory_usage_(0)
    , backup_state_()
    , decoy_objects_created_(0)
    , entropy_insertions_count_(0)
    , total_objects_processed_(0) {

    // Initialize secure random number generation
    initialize_secure_random();
}

PDFScrubber::~PDFScrubber() {
    // Securely clear entropy pool
    secure_zero_memory(entropy_pool_);
}

PDFStructure PDFScrubber::scrub(const PDFStructure& input_structure) {
    // Thread-safe access to timing
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        start_time_ = std::chrono::steady_clock::now();
    }

    // Pre-scrubbing validation with read lock
    {
        std::shared_lock<std::shared_mutex> lock(structure_mutex_);
        if (!pre_scrubbing_validation(input_structure)) {
            SILENT_ERROR("[!] Pre-scrubbing validation failed. Aborting.\n");
            return input_structure;
        }
    }

    // Create rollback point with thread safety
    create_rollback_point(input_structure);

    // Activate security and stealth components before processing
    if (memory_guard_) {
        memory_guard_->activate_protection();
    }
    if (memory_sanitizer_) {
        memory_sanitizer_->activate_sanitization();
    }
    if (stealth_scrubber_) {
        stealth_scrubber_->activate_stealth_mode();
    }
    if (trace_cleaner_) {
        trace_cleaner_->activate_trace_cleaning();
    }
    if (metadata_cleaner_) {
        metadata_cleaner_->activate_cleaning();
    }

    // Deep copy with write lock protection
    PDFStructure structure;
    {
        std::unique_lock<std::shared_mutex> lock(structure_mutex_);
        structure = input_structure;
    }

    // Reset atomic statistics
    objects_removed_.store(0);
    objects_modified_.store(0);
    streams_cleaned_.store(0);
    references_updated_.store(0);

    // Core scrubbing operations
    scrub_info_object(structure);
    scrub_metadata_objects(structure);
    scrub_document_id(structure);
    scrub_encryption_data(structure);

    if (neutralize_javascript_) {
        scrub_javascript_actions(structure);
    }

    if (remove_form_data_) {
        scrub_form_data(structure);
    }

    if (clean_embedded_files_) {
        scrub_embedded_files(structure);
    }

    scrub_producer_information(structure);
    scrub_creation_dates(structure);
    scrub_modification_dates(structure);
    scrub_author_information(structure);
    scrub_application_data(structure);

    if (remove_annotations_) {
        scrub_annotations(structure);
    }

    scrub_bookmarks(structure);
    scrub_named_destinations(structure);
    scrub_optional_content(structure);
    scrub_digital_signatures(structure);
    scrub_usage_rights(structure);
    scrub_viewer_preferences(structure);
    scrub_thread_information(structure);
    scrub_web_capture_info(structure);
    scrub_structure_tree(structure);

    // Advanced scrubbing techniques
    remove_ghost_objects(structure);
    neutralize_hidden_streams(structure);
    clean_object_streams(structure);
    remove_incremental_updates(structure);
    scrub_whitespace_data(structure);
    remove_comment_blocks(structure);
    clean_xref_streams(structure);
    neutralize_linearization(structure);
    remove_page_thumbnails(structure);
    clean_resource_dictionaries(structure);

    // Anti-forensic techniques with security component integration
    if (aggressive_scrubbing_) {
        apply_entropy_neutralization(structure);
        randomize_object_order(structure);
        insert_decoy_objects(structure);
        normalize_whitespace(structure);
        remove_forensic_markers(structure);
        eliminate_timing_artifacts(structure);
        scrub_memory_artifacts(structure);

        // Apply stealth scrubbing
        if (stealth_scrubber_) {
            std::vector<uint8_t> pdf_data = structure_to_bytes(structure);
            stealth_scrubber_->perform_stealth_scrub(pdf_data);
            structure = bytes_to_structure(pdf_data);
        }

        // Clean traces
        if (trace_cleaner_) {
            std::vector<uint8_t> pdf_data = structure_to_bytes(structure);
            trace_cleaner_->clean_pdf_traces(pdf_data);
            structure = bytes_to_structure(pdf_data);
        }

        // Clean metadata with specialized cleaner
        if (metadata_cleaner_) {
            std::vector<uint8_t> pdf_data = structure_to_bytes(structure);
            metadata_cleaner_->clean_pdf_metadata(pdf_data);
            structure = bytes_to_structure(pdf_data);
        }
    }

    // Advanced anti-forensic techniques based on intensity level
    if (intensity_level_ >= IntensityLevel::AGGRESSIVE) {
        advanced_entropy_manipulation(structure);
        remove_temporal_artifacts(structure);
        enhanced_ghost_object_detection(structure);
    }

    // Performance optimizations with thread safety
    if (enable_parallel_processing_) {
        parallel_process_objects_threadsafe(structure);
    }

    // Incremental scrubbing for real-time applications
    if (enable_incremental_scrubbing_) {
        compact_object_numbers(structure);
    }

    optimize_memory_usage(structure);

    // Cleanup and validation
    remove_dangling_references(structure);
    rebuild_xref_table(structure);
    scrub_trailer_dictionary(structure);
    optimize_object_layout(structure);
    ensure_pdf_compliance(structure);

    // Comprehensive integrity checking with security components
    if (pdf_integrity_checker_) {
        std::vector<uint8_t> pdf_data = structure_to_bytes(structure);
        if (!pdf_integrity_checker_->verify_pdf_structure(pdf_data)) {
            SILENT_ERROR("[!] PDF integrity check failed. Rolling back...\n");
            return rollback_on_failure() ? backup_structure_ : structure;
        }
    }

    if (integrity_checker_) {
        std::vector<uint8_t> pdf_data = structure_to_bytes(structure);
        if (!integrity_checker_->verify_pdf_structure_integrity(pdf_data)) {
            SILENT_ERROR("[!] Structure integrity check failed. Rolling back...\n");
            return rollback_on_failure() ? backup_structure_ : structure;
        }
    }

    // Post-scrubbing integrity check
    if (!post_scrubbing_integrity_check(structure)) {
        SILENT_ERROR("[!] Integrity check failed. Rolling back...\n");
        return rollback_on_failure() ? backup_structure_ : structure;
    }

    validate_scrubbed_structure(structure);

    // Thread-safe timing and statistics reporting
    long duration;
    int removed, modified, cleaned;
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        end_time_ = std::chrono::steady_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time_ - start_time_).count();
        removed = objects_removed_.load();
        modified = objects_modified_.load();
        cleaned = streams_cleaned_.load();
    }

    SILENT_LOG("[+] Scrubbing completed in ") << duration << "ms: " 
              << removed << " objects removed, " 
              << modified << " objects modified, "
              << cleaned << " streams cleaned\n";

    return structure;
}

// Secure entropy generation implementation
bool PDFScrubber::initialize_secure_random() {
    std::lock_guard<std::mutex> lock(entropy_mutex_);

    // Test OpenSSL random generation
    unsigned char test_bytes[32];
    if (RAND_bytes(test_bytes, sizeof(test_bytes)) != 1) {
        SILENT_ERROR("[!] Failed to initialize secure random generation\n");
        return false;
    }

    // Initialize entropy pool with secure random data
    entropy_pool_.resize(256);
    if (RAND_bytes(entropy_pool_.data(), entropy_pool_.size()) != 1) {
        SILENT_ERROR("[!] Failed to initialize entropy pool\n");
        return false;
    }

    secure_random_initialized_ = true;
    return true;
}

std::vector<uint8_t> PDFScrubber::generate_secure_random_bytes(size_t length) {
    std::vector<uint8_t> random_bytes(length);

    if (!secure_random_initialized_) {
        if (!initialize_secure_random()) {
            throw SecureExceptions::SecurityViolationException("Failed to initialize secure random generation");
        }
    }

    // Use OpenSSL's cryptographically secure random number generator
    if (RAND_bytes(random_bytes.data(), length) != 1) {
        throw SecureExceptions::SecurityViolationException("Failed to generate secure random bytes");
    }

    // Mix with entropy pool for additional security
    {
        std::lock_guard<std::mutex> lock(entropy_mutex_);
        for (size_t i = 0; i < length && i < entropy_pool_.size(); ++i) {
            random_bytes[i] ^= entropy_pool_[i % entropy_pool_.size()];
        }

        // Refresh entropy pool periodically
        if (length >= 32) {
            // SECURITY FIX: Use secure vector allocation with proper size validation
            std::vector<uint8_t> new_entropy;
            new_entropy.resize(32);
            if (RAND_bytes(new_entropy.data(), 32) == 1) {
                for (size_t i = 0; i < 32; ++i) {
                    entropy_pool_[i % entropy_pool_.size()] ^= new_entropy[i];
                }
            }
        }
    }

    return random_bytes;
}

void PDFScrubber::secure_zero_memory(std::vector<uint8_t>& data) {
    if (!data.empty()) {
        OPENSSL_cleanse(data.data(), data.size());
        data.clear();
    }
}

void PDFScrubber::secure_zero_memory(std::string& str) {
    if (!str.empty()) {
        OPENSSL_cleanse(&str[0], str.size());
        str.clear();
    }
}

void PDFScrubber::scrub_info_object(PDFStructure& structure) {
    if (structure.info_object_ref.empty()) return;

    std::regex ref_regex(R"((\d+)\s+(\d+)\s+R)");
    std::smatch match;

    if (std::regex_search(structure.info_object_ref, match, ref_regex)) {
        int obj_num = std::stoi(match[1].str());

        for (auto& obj : structure.objects) {
            if (obj.number == obj_num) {
                if (remove_all_metadata_) {
                    // Remove the entire Info object
                    thread_safe_remove_object(structure, obj_num);
                    structure.info_object_ref.clear();
                    safe_increment_stat(objects_removed_);
                } else {
                    // Clean sensitive information but keep basic metadata
                    std::map<std::string, std::string> clean_dict;
                    for (const auto& pair : obj.dictionary) {
                        bool keep_entry = false;

                        // Check whitelist first
                        if (!metadata_whitelist_.empty()) {
                            for (const auto& whitelist_key : metadata_whitelist_) {
                                if (pair.first == whitelist_key) {
                                    keep_entry = true;
                                    break;
                                }
                            }
                        } else {
                            // Default behavior - keep basic non-sensitive metadata
                            if (pair.first == "/Title" || pair.first == "/Subject") {
                                keep_entry = true;
                            }
                        }

                        // Check blacklist - overrides whitelist
                        for (const auto& blacklist_key : metadata_blacklist_) {
                            if (pair.first == blacklist_key) {
                                keep_entry = false;
                                break;
                            }
                        }

                        if (keep_entry) {
                            clean_dict[pair.first] = pair.second;
                        }
                    }
                    obj.dictionary = clean_dict;
                    safe_increment_stat(objects_modified_);
                }
                break;
            }
        }
    }
}

void PDFScrubber::scrub_metadata_objects(PDFStructure& structure) {
    std::vector<int> metadata_objects;

    for (const auto& obj : structure.objects) {
        if (is_metadata_object(obj)) {
            metadata_objects.push_back(obj.number);
        }
    }

    for (int obj_num : metadata_objects) {
        thread_safe_remove_object(structure, obj_num);
        safe_increment_stat(objects_removed_);
    }

    structure.metadata_object_ref.clear();
}

void PDFScrubber::scrub_document_id(PDFStructure& structure) {
    // Clear the document ID - will be replaced during cloning
    structure.document_id.clear();
}

void PDFScrubber::scrub_encryption_data(PDFStructure& structure) {
    // Remove encryption dictionary reference from trailer
    structure.trailer.dictionary.erase("/Encrypt");
    structure.encrypt_object_ref.clear();

    // Remove encryption objects
    std::vector<int> encrypt_objects;

    for (const auto& obj : structure.objects) {
        auto type_it = obj.dictionary.find("/Type");
        if (type_it != obj.dictionary.end() && type_it->second == "/Encrypt") {
            encrypt_objects.push_back(obj.number);
        }
    }

    for (int obj_num : encrypt_objects) {
        thread_safe_remove_object(structure, obj_num);
        safe_increment_stat(objects_removed_);
    }
}

void PDFScrubber::scrub_javascript_actions(PDFStructure& structure) {
    for (auto& obj : structure.objects) {
        bool modified = false;

        // Remove JavaScript-related dictionary entries
        if (obj.dictionary.erase("/JS") > 0) modified = true;
        if (obj.dictionary.erase("/JavaScript") > 0) modified = true;
        if (obj.dictionary.erase("/OpenAction") > 0) modified = true;
        if (obj.dictionary.erase("/AA") > 0) modified = true;
        if (obj.dictionary.erase("/Names") > 0) modified = true;

        // Clean Actions in annotations
        auto a_it = obj.dictionary.find("/A");
        if (a_it != obj.dictionary.end()) {
            obj.dictionary.erase("/A");
            modified = true;
        }

        if (modified) {
            safe_increment_stat(objects_modified_);
        }
    }

    structure.javascript_actions.clear();
}

void PDFScrubber::scrub_form_data(PDFStructure& structure) {
    for (auto& obj : structure.objects) {
        if (is_form_field_object(obj)) {
            bool modified = false;

            // Remove form field values
            if (obj.dictionary.erase("/V") > 0) modified = true;
            if (obj.dictionary.erase("/DV") > 0) modified = true;
            if (obj.dictionary.erase("/AS") > 0) modified = true;

            if (modified) {
                safe_increment_stat(objects_modified_);
            }
        }
    }

    structure.form_fields.clear();
}

void PDFScrubber::scrub_embedded_files(PDFStructure& structure) {
    std::vector<int> embedded_file_objects;

    for (const auto& obj : structure.objects) {
        if (has_embedded_file(obj)) {
            embedded_file_objects.push_back(obj.number);
        }
    }

    for (int obj_num : embedded_file_objects) {
        thread_safe_remove_object(structure, obj_num);
        safe_increment_stat(objects_removed_);
    }

    structure.embedded_files.clear();
}

void PDFScrubber::scrub_producer_information(PDFStructure& structure) {
    structure.producer_info.clear();

    for (auto& obj : structure.objects) {
        if (is_info_object(obj)) {
            bool modified = false;

            if (obj.dictionary.erase("/Producer") > 0) modified = true;
            if (obj.dictionary.erase("/Creator") > 0) modified = true;
            if (obj.dictionary.erase("/CreationDate") > 0) modified = true;
            if (obj.dictionary.erase("/ModDate") > 0) modified = true;

            if (modified) {
                safe_increment_stat(objects_modified_);
            }
        }
    }
}

void PDFScrubber::scrub_creation_dates(PDFStructure& structure) {
    for (auto& obj : structure.objects) {
        bool modified = false;

        if (obj.dictionary.erase("/CreationDate") > 0) modified = true;
        if (obj.dictionary.erase("/Created") > 0) modified = true;

        if (modified) {
            safe_increment_stat(objects_modified_);
        }
    }
}

void PDFScrubber::scrub_modification_dates(PDFStructure& structure) {
    for (auto& obj : structure.objects) {
        bool modified = false;

        if (obj.dictionary.erase("/ModDate") > 0) modified = true;
        if (obj.dictionary.erase("/Modified") > 0) modified = true;
        if (obj.dictionary.erase("/LastModified") > 0) modified = true;

        if (modified) {
            safe_increment_stat(objects_modified_);
        }
    }
}

void PDFScrubber::scrub_author_information(PDFStructure& structure) {
    for (auto& obj : structure.objects) {
        bool modified = false;

        if (obj.dictionary.erase("/Author") > 0) modified = true;
        if (obj.dictionary.erase("/Keywords") > 0) modified = true;

        if (modified) {
            safe_increment_stat(objects_modified_);
        }
    }
}

void PDFScrubber::scrub_application_data(PDFStructure& structure) {
    for (auto& obj : structure.objects) {
        bool modified = false;

        // Remove application-specific data
        if (obj.dictionary.erase("/PieceInfo") > 0) modified = true;
        if (obj.dictionary.erase("/PrivateData") > 0) modified = true;
        if (obj.dictionary.erase("/LastChar") > 0) modified = true;

        if (modified) {
            safe_increment_stat(objects_modified_);
        }
    }
}

void PDFScrubber::scrub_annotations(PDFStructure& structure) {
    std::vector<int> annotation_objects;

    for (const auto& obj : structure.objects) {
        if (is_annotation_object(obj)) {
            annotation_objects.push_back(obj.number);
        }
    }

    for (int obj_num : annotation_objects) {
        remove_object(structure, obj_num);
        objects_removed_++;
    }
}

void PDFScrubber::scrub_bookmarks(PDFStructure& structure) {
    for (auto& obj : structure.objects) {
        bool modified = false;

        if (obj.dictionary.erase("/Outlines") > 0) modified = true;
        if (obj.dictionary.erase("/First") > 0) modified = true;
        if (obj.dictionary.erase("/Last") > 0) modified = true;
        if (obj.dictionary.erase("/Next") > 0) modified = true;
        if (obj.dictionary.erase("/Prev") > 0) modified = true;
        if (obj.dictionary.erase("/Parent") > 0) modified = true;
        if (obj.dictionary.erase("/Count") > 0) modified = true;
        if (obj.dictionary.erase("/Dest") > 0) modified = true;

        if (modified) {
            safe_increment_stat(objects_modified_);
        }
    }
}

void PDFScrubber::scrub_named_destinations(PDFStructure& structure) {
    for (auto& obj : structure.objects) {
        bool modified = false;

        if (obj.dictionary.erase("/Dests") > 0) modified = true;
        if (obj.dictionary.erase("/Names") > 0) modified = true;

        if (modified) {
            safe_increment_stat(objects_modified_);
        }
    }
}

void PDFScrubber::scrub_optional_content(PDFStructure& structure) {
    for (auto& obj : structure.objects) {
        bool modified = false;

        if (obj.dictionary.erase("/OCProperties") > 0) modified = true;
        if (obj.dictionary.erase("/OCGs") > 0) modified = true;
        if (obj.dictionary.erase("/OCMDs") > 0) modified = true;

        if (modified) {
            safe_increment_stat(objects_modified_);
        }
    }
}

void PDFScrubber::scrub_digital_signatures(PDFStructure& structure) {
    std::vector<int> signature_objects;

    for (const auto& obj : structure.objects) {
        auto type_it = obj.dictionary.find("/Type");
        if (type_it != obj.dictionary.end() && type_it->second == "/Sig") {
            signature_objects.push_back(obj.number);
        }

        auto ft_it = obj.dictionary.find("/FT");
        if (ft_it != obj.dictionary.end() && ft_it->second == "/Sig") {
            signature_objects.push_back(obj.number);
        }
    }

    for (int obj_num : signature_objects) {
        remove_object(structure, obj_num);
        objects_removed_++;
    }
}

void PDFScrubber::scrub_usage_rights(PDFStructure& structure) {
    for (auto& obj : structure.objects) {
        bool modified = false;

        if (obj.dictionary.erase("/Perms") > 0) modified = true;
        if (obj.dictionary.erase("/UR") > 0) modified = true;
        if (obj.dictionary.erase("/UR3") > 0) modified = true;

        if (modified) {
            safe_increment_stat(objects_modified_);
        }
    }
}

void PDFScrubber::scrub_viewer_preferences(PDFStructure& structure) {
    for (auto& obj : structure.objects) {
        bool modified = false;

        if (obj.dictionary.erase("/ViewerPreferences") > 0) modified = true;

        if (modified) {
            safe_increment_stat(objects_modified_);
        }
    }
}

void PDFScrubber::scrub_thread_information(PDFStructure& structure) {
    for (auto& obj : structure.objects) {
        bool modified = false;

        if (obj.dictionary.erase("/Threads") > 0) modified = true;
        if (obj.dictionary.erase("/B") > 0) modified = true;

        if (modified) {
            safe_increment_stat(objects_modified_);
        }
    }
}

void PDFScrubber::scrub_web_capture_info(PDFStructure& structure) {
    for (auto& obj : structure.objects) {
        bool modified = false;

        if (obj.dictionary.erase("/SpiderInfo") > 0) modified = true;
        if (obj.dictionary.erase("/ID") > 0) modified = true;
        if (obj.dictionary.erase("/URLs") > 0) modified = true;

        if (modified) {
            safe_increment_stat(objects_modified_);
        }
    }
}

void PDFScrubber::scrub_structure_tree(PDFStructure& structure) {
    for (auto& obj : structure.objects) {
        bool modified = false;

        if (obj.dictionary.erase("/StructTreeRoot") > 0) modified = true;
        if (obj.dictionary.erase("/K") > 0) modified = true;
        if (obj.dictionary.erase("/ParentTree") > 0) modified = true;
        if (obj.dictionary.erase("/IDTree") > 0) modified = true;
        if (obj.dictionary.erase("/ClassMap") > 0) modified = true;
        if (obj.dictionary.erase("/RoleMap") > 0) modified = true;

        if (modified) {
            safe_increment_stat(objects_modified_);
        }
    }
}

void PDFScrubber::remove_ghost_objects(PDFStructure& structure) {
    std::vector<int> ghost_objects;

    for (const auto& obj : structure.objects) {
        if (is_ghost_object(obj)) {
            ghost_objects.push_back(obj.number);
        }
    }

    for (int obj_num : ghost_objects) {
        remove_object(structure, obj_num);
        objects_removed_++;
    }
}

void PDFScrubber::neutralize_hidden_streams(PDFStructure& structure) {
    for (auto& obj : structure.objects) {
        if (obj.has_stream && obj.stream_data.size() > 0) {
            scrub_stream_metadata(obj);

            // Check if stream contains suspicious data
            std::string stream_str = PDFUtils::bytes_to_string(obj.stream_data);
            if (stream_str.find("JavaScript") != std::string::npos ||
                stream_str.find("/JS") != std::string::npos ||
                stream_str.find("eval(") != std::string::npos) {
                neutralize_stream_data(obj);
                safe_increment_stat(streams_cleaned_);
            }
        }
    }
}

void PDFScrubber::clean_object_streams(PDFStructure& structure) {
    for (auto& obj : structure.objects) {
        auto type_it = obj.dictionary.find("/Type");
        if (type_it != obj.dictionary.end() && type_it->second == "/ObjStm") {
            // Object stream - needs special handling
            neutralize_stream_data(obj);
            safe_increment_stat(streams_cleaned_);
        }
    }
}

void PDFScrubber::remove_incremental_updates(PDFStructure& structure) {
    // Remove multiple xref sections - keep only the main one
    if (structure.trailer.has_prev) {
        structure.trailer.has_prev = false;
        structure.trailer.prev_xref_offset = 0;
        structure.trailer.dictionary.erase("/Prev");
    }
}

void PDFScrubber::scrub_whitespace_data(PDFStructure& structure) {
    for (auto& obj : structure.objects) {
        // Normalize whitespace in object content
        std::string& content = obj.content;

        // Remove excessive whitespace
        content = std::regex_replace(content, std::regex(R"(\s+)"), " ");

        // Remove trailing whitespace
        content = std::regex_replace(content, std::regex(R"(\s+$)"), "");

        safe_increment_stat(objects_modified_);
    }
}

void PDFScrubber::remove_comment_blocks(PDFStructure& structure) {
    for (auto& obj : structure.objects) {
        std::string& content = obj.content;

        // Remove PDF comments
        content = std::regex_replace(content, std::regex(R"(%.*)"), "");

        safe_increment_stat(objects_modified_);
    }
}

void PDFScrubber::clean_xref_streams(PDFStructure& structure) {
    std::vector<int> xref_stream_objects;

    for (const auto& obj : structure.objects) {
        auto type_it = obj.dictionary.find("/Type");
        if (type_it != obj.dictionary.end() && type_it->second == "/XRef") {
            xref_stream_objects.push_back(obj.number);
        }
    }

    // Remove XRef stream objects - we'll use traditional xref table
    for (int obj_num : xref_stream_objects) {
        remove_object(structure, obj_num);
        objects_removed_++;
    }
}

void PDFScrubber::neutralize_linearization(PDFStructure& structure) {
    // Remove linearization dictionary
    for (auto& obj : structure.objects) {
        auto linearized_it = obj.dictionary.find("/Linearized");
        if (linearized_it != obj.dictionary.end()) {
            obj.dictionary.clear();
            safe_increment_stat(objects_modified_);
            break;
        }
    }
}

void PDFScrubber::remove_page_thumbnails(PDFStructure& structure) {
    for (auto& obj : structure.objects) {
        bool modified = false;

        if (obj.dictionary.erase("/Thumb") > 0) modified = true;

        if (modified) {
            safe_increment_stat(objects_modified_);
        }
    }
}

void PDFScrubber::clean_resource_dictionaries(PDFStructure& structure) {
    for (auto& obj : structure.objects) {
        auto resources_it = obj.dictionary.find("/Resources");
        if (resources_it != obj.dictionary.end()) {
            // Clean resources dictionary
            std::string resources = resources_it->second;

            // Remove potentially suspicious entries
            resources = std::regex_replace(resources, std::regex(R"(/ProcSet\s*\[[^\]]*\])"), "");

            obj.dictionary["/Resources"] = resources;
            safe_increment_stat(objects_modified_);
        }
    }
}

void PDFScrubber::apply_entropy_neutralization(PDFStructure& structure) {
    // Randomize object content order to break entropy analysis
    std::random_device rd;
    std::mt19937 g(rd());

    for (auto& obj : structure.objects) {
        if (obj.has_stream) {
            // Add random padding to break entropy patterns
            std::vector<uint8_t> padding(g() % 16);
            for (auto& byte : padding) {
                byte = g() % 256;
            }

            // Insert padding at random position
            if (!obj.stream_data.empty()) {
                size_t pos = g() % obj.stream_data.size();
                obj.stream_data.insert(obj.stream_data.begin() + pos, padding.begin(), padding.end());
            }
        }
    }
}

void PDFScrubber::randomize_object_order(PDFStructure& structure) {
    std::random_device rd;
    std::mt19937 g(rd());

    std::shuffle(structure.objects.begin(), structure.objects.end(), g);
}

void PDFScrubber::insert_decoy_objects(PDFStructure& structure) {
    // Check resource limits before proceeding
    if (!check_resource_limits()) {
        SILENT_ERROR("[!] Resource limits exceeded, skipping decoy object insertion\n");
        return;
    }

    // Check if we can create decoy objects within limits
    const size_t desired_decoys = 3;
    if (!can_create_decoy_objects(desired_decoys)) {
        SILENT_ERROR("[!] Cannot create decoy objects - would exceed resource limits\n");
        return;
    }

    // Add some null objects to confuse forensic analysis
    int max_obj_num = 0;
    for (const auto& obj : structure.objects) {
        if (obj.number > max_obj_num && obj.number <= MAX_SAFE_OBJECT_NUMBER) {
            max_obj_num = obj.number;
        }
    }

    // Check if we can safely add decoy objects without overflow
    if (!check_object_number_overflow(max_obj_num, static_cast<int>(desired_decoys))) {
        SILENT_ERROR("[!] Cannot add decoy objects - would cause integer overflow\n");
        return;
    }

    size_t created_count = 0;
    for (int i = 0; i < static_cast<int>(desired_decoys); ++i) {
        // Check limits before each creation
        if (!can_create_decoy_objects(1)) {
            SILENT_ERROR("[!] Reached decoy object limit during creation\n");
            break;
        }

        int new_obj_num = safe_increment_object_number(max_obj_num + i);
        if (new_obj_num <= MAX_SAFE_OBJECT_NUMBER) {
            insert_null_object(structure, new_obj_num);
            created_count++;
            track_decoy_object_creation(1);
        } else {
            SILENT_ERROR("[!] Stopping decoy object insertion to prevent overflow\n");
            break;
        }
    }

    SILENT_LOG("[+] Created ") << created_count << " decoy objects\n";
}

void PDFScrubber::normalize_whitespace(PDFStructure& structure) {
    for (auto& obj : structure.objects) {
        std::string& content = obj.content;

        // Normalize line endings
        content = std::regex_replace(content, std::regex(R"(\r\n)"), "\n");
        content = std::regex_replace(content, std::regex(R"(\r)"), "\n");

        // Normalize spacing
        content = std::regex_replace(content, std::regex(R"([ \t]+)"), " ");

        safe_increment_stat(objects_modified_);
    }
}

void PDFScrubber::remove_forensic_markers(PDFStructure& structure) {
    for (auto& obj : structure.objects) {
        bool modified = false;

        // Remove common forensic markers
        if (obj.dictionary.erase("/AAPL:Keywords") > 0) modified = true;
        if (obj.dictionary.erase("/PTEX.Fullbanner") > 0) modified = true;
        if (obj.dictionary.erase("/PTEX.PageNumber") > 0) modified = true;
        if (obj.dictionary.erase("/GTS_PDFXVersion") > 0) modified = true;
        if (obj.dictionary.erase("/GTS_PDFXConformance") > 0) modified = true;

        if (modified) {
            safe_increment_stat(objects_modified_);
        }
    }
}

void PDFScrubber::eliminate_timing_artifacts(PDFStructure& structure) {
    // Remove timing-related information
    for (auto& obj : structure.objects) {
        bool modified = false;

        if (obj.dictionary.erase("/T") > 0) modified = true;
        if (obj.dictionary.erase("/M") > 0) modified = true;

        if (modified) {
            safe_increment_stat(objects_modified_);
        }
    }
}

void PDFScrubber::scrub_memory_artifacts(PDFStructure& structure) {
    // Clear any potential memory artifacts in stream data
    for (auto& obj : structure.objects) {
        if (obj.has_stream) {
            // Overwrite unused space in streams with zeros
            for (auto& byte : obj.stream_data) {
                if (byte == 0xFF) {  // Common uninitialized memory pattern
                    byte = 0x00;
                }
            }
            safe_increment_stat(streams_cleaned_);
        }
    }
}

void PDFScrubber::remove_object(PDFStructure& structure, int obj_number) {
    structure.objects.erase(
        std::remove_if(structure.objects.begin(), structure.objects.end(),
                      [obj_number](const PDFObject& obj) { return obj.number == obj_number; }),
        structure.objects.end());

    structure.xref_table.erase(obj_number);
}

void PDFScrubber::replace_object_content(PDFStructure& structure, int obj_number, const std::string& new_content) {
    for (auto& obj : structure.objects) {
        if (obj.number == obj_number) {
            obj.content = new_content;
            obj.dictionary.clear();
            obj.has_stream = false;
            obj.stream_data.clear();
            break;
        }
    }
}

void PDFScrubber::insert_null_object(PDFStructure& structure, int obj_number) {
    PDFObject null_obj;
    null_obj.number = obj_number;
    null_obj.generation = 0;
    null_obj.content = std::to_string(obj_number) + " 0 obj\nnull\nendobj";
    null_obj.has_stream = false;
    null_obj.is_compressed = false;

    structure.objects.push_back(null_obj);

    PDFXRefEntry entry;
    entry.offset = 0;  // Will be calculated later
    entry.generation = 0;
    entry.in_use = true;

    structure.xref_table[obj_number] = entry;
}

void PDFScrubber::modify_object_dictionary(PDFObject& obj, const std::string& key, const std::string& value) {
    obj.dictionary[key] = value;
}

void PDFScrubber::remove_dictionary_key(PDFObject& obj, const std::string& key) {
    obj.dictionary.erase(key);
}

void PDFScrubber::update_object_references(PDFStructure& structure, int old_obj_num, int new_obj_num) {
    std::string old_ref = std::to_string(old_obj_num) + " 0 R";
    std::string new_ref = std::to_string(new_obj_num) + " 0 R";

    for (auto& obj : structure.objects) {
        obj.content = std::regex_replace(obj.content, std::regex(old_ref), new_ref);

        for (auto& pair : obj.dictionary) {
            pair.second = std::regex_replace(pair.second, std::regex(old_ref), new_ref);
        }
    }

    // Update trailer references
    for (auto& pair : structure.trailer.dictionary) {
        pair.second = std::regex_replace(pair.second, std::regex(old_ref), new_ref);
    }

    safe_increment_stat(references_updated_);
}

void PDFScrubber::remove_dangling_references(PDFStructure& structure) {
    std::set<int> existing_objects;
    for (const auto& obj : structure.objects) {
        existing_objects.insert(obj.number);
    }

    // Remove xref entries for non-existent objects
    auto it = structure.xref_table.begin();
    while (it != structure.xref_table.end()) {
        if (existing_objects.find(it->first) == existing_objects.end()) {
            it = structure.xref_table.erase(it);
        } else {
            ++it;
        }
    }
}

std::set<int> PDFScrubber::find_referenced_objects(const PDFStructure& structure) {
    std::set<int> referenced;
    std::regex ref_regex(R"((\d+)\s+\d+\s+R)");

    // Check all object content for references
    for (const auto& obj : structure.objects) {
        std::sregex_iterator iter(obj.content.begin(), obj.content.end(), ref_regex);
        std::sregex_iterator end;

        for (; iter != end; ++iter) {
            const std::smatch& match = *iter;
            int obj_num = std::stoi(match[1].str());
            referenced.insert(obj_num);
        }
    }

    // Check trailer for references
    for (const auto& pair : structure.trailer.dictionary) {
        std::sregex_iterator iter(pair.second.begin(), pair.second.end(), ref_regex);
        std::sregex_iterator end;

        for (; iter != end; ++iter) {
            const std::smatch& match = *iter;
            int obj_num = std::stoi(match[1].str());
            referenced.insert(obj_num);
        }
    }

    return referenced;
}

// Configuration methods implementation
void PDFScrubber::set_intensity_level(IntensityLevel level) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    intensity_level_ = level;

    // Adjust settings based on intensity level
    switch (level) {
        case IntensityLevel::BASIC:
            aggressive_scrubbing_ = false;
            remove_all_metadata_ = false;
            neutralize_javascript_ = false;
            break;
        case IntensityLevel::STANDARD:
            aggressive_scrubbing_ = true;
            remove_all_metadata_ = true;
            neutralize_javascript_ = true;
            break;
        case IntensityLevel::AGGRESSIVE:
            aggressive_scrubbing_ = true;
            remove_all_metadata_ = true;
            neutralize_javascript_ = true;
            remove_form_data_ = true;
            remove_annotations_ = true;
            break;
        case IntensityLevel::MAXIMUM:
            aggressive_scrubbing_ = true;
            remove_all_metadata_ = true;
            neutralize_javascript_ = true;
            remove_form_data_ = true;
            remove_annotations_ = true;
            clean_embedded_files_ = true;
            enable_parallel_processing_ = true;
            break;
    }
}

void PDFScrubber::set_scrubbing_profile(ScrubbingProfile profile) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    scrubbing_profile_ = profile;

    switch (profile) {
        case ScrubbingProfile::DEFAULT:
            // Use current settings
            break;
        case ScrubbingProfile::ANONYMIZER:
            remove_all_metadata_ = true;
            scrub_creation_info_ = true;
            neutralize_javascript_ = true;
            remove_form_data_ = true;
            break;
        case ScrubbingProfile::FORENSIC_EVASION:
            aggressive_scrubbing_ = true;
            set_intensity_level(IntensityLevel::MAXIMUM);
            break;
        case ScrubbingProfile::COMPLIANCE:
            preserve_visual_content_ = true;
            remove_all_metadata_ = false;
            // Only remove sensitive metadata
            add_to_blacklist("/Author");
            add_to_blacklist("/Producer");
            add_to_blacklist("/Creator");
            break;
    }
}

void PDFScrubber::add_to_whitelist(const std::string& metadata_key) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    metadata_whitelist_.push_back(metadata_key);
}

void PDFScrubber::add_to_blacklist(const std::string& metadata_key) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    metadata_blacklist_.push_back(metadata_key);
}

void PDFScrubber::clear_whitelist() {
    std::lock_guard<std::mutex> lock(config_mutex_);
    metadata_whitelist_.clear();
}

void PDFScrubber::clear_blacklist() {
    std::lock_guard<std::mutex> lock(config_mutex_);
    metadata_blacklist_.clear();
}

// Advanced anti-forensic features
void PDFScrubber::advanced_entropy_manipulation(PDFStructure& structure) {
    // Use secure random generation instead of std::random_device

    for (auto& obj : structure.objects) {
        if (obj.has_stream && obj.stream_data.size() > 0) {
            // Memory safety check before manipulation
            if (!check_memory_bounds(obj.stream_data.size(), MAX_PATTERN_SIZE)) {
                SILENT_ERROR("[!] Skipping entropy manipulation for object ") << obj.number 
                          << " due to memory constraints\n";
                continue;
            }

            // Determine object type safely
            std::string type = "Unknown";
            auto type_it = obj.dictionary.find("/Type");
            if (type_it != obj.dictionary.end()) {
                type = type_it->second;
            }

            // Calculate safe pattern size based on stream size and type
            size_t pattern_size = calculate_safe_pattern_size(obj.stream_data.size(), type);
            if (pattern_size == 0) {
                continue; // Skip if pattern would be unsafe
            }

            // Create entropy pattern with bounds checking
            std::vector<uint8_t> entropy_pattern;
            entropy_pattern.reserve(pattern_size);

            if (type == "/Font") {
                // Font-specific entropy pattern (limited size)
                std::vector<uint8_t> random_bytes = generate_secure_random_bytes(std::min(pattern_size, size_t(8)));
                for (size_t i = 0; i < random_bytes.size(); ++i) {
                    entropy_pattern.push_back(0x20 + (random_bytes[i] % 32));
                }
            } else if (type == "/Image") {
                // Image-specific entropy pattern (more conservative)
                std::vector<uint8_t> random_bytes = generate_secure_random_bytes(std::min(pattern_size, size_t(12)));
                for (size_t i = 0; i < random_bytes.size(); ++i) {
                    entropy_pattern.push_back(random_bytes[i]);
                }
            } else {
                // Generic pattern (most conservative)
                std::vector<uint8_t> random_bytes = generate_secure_random_bytes(std::min(pattern_size, size_t(6)));
                for (size_t i = 0; i < random_bytes.size(); ++i) {
                    entropy_pattern.push_back(random_bytes[i] % 128);
                }
            }

            // Check resource limits before entropy insertion
            if (!can_perform_entropy_insertion()) {
                SILENT_ERROR("[!] Entropy insertion limit reached for object ") << obj.number << "\n";
                continue;
            }

            // Safe entropy insertion with memory optimization
            safe_entropy_insertion(obj, entropy_pattern);
            track_entropy_insertion();

            // Optimize memory usage after manipulation
            optimize_stream_memory_usage(obj);
        }
    }
}

void PDFScrubber::remove_temporal_artifacts(PDFStructure& structure) {
    // Remove timing-based artifacts that could indicate creation patterns
    for (auto& obj : structure.objects) {
        bool modified = false;

        // Remove temporal markers
        if (obj.dictionary.erase("/T") > 0) modified = true;
        if (obj.dictionary.erase("/M") > 0) modified = true;
        if (obj.dictionary.erase("/CreationDate") > 0) modified = true;
        if (obj.dictionary.erase("/ModDate") > 0) modified = true;

        // Remove sequence-based artifacts
        if (obj.dictionary.erase("/Order") > 0) modified = true;
        if (obj.dictionary.erase("/Index") > 0) modified = true;

        // Neutralize timing-sensitive stream content
        if (obj.has_stream) {
            std::string stream_str = PDFUtils::bytes_to_string(obj.stream_data);

            // Remove timestamp patterns
            stream_str = std::regex_replace(stream_str, std::regex(R"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"), "2000-01-01T00:00:00");
            stream_str = std::regex_replace(stream_str, std::regex(R"(D:\d{14})"), "D:20000101000000");

            obj.stream_data = PDFUtils::string_to_bytes(stream_str);
            modified = true;
        }

        if (modified) {
            safe_increment_stat(objects_modified_);
        }
    }
}

void PDFScrubber::enhanced_ghost_object_detection(PDFStructure& structure) {
    std::vector<int> suspected_ghosts;

    for (const auto& obj : structure.objects) {
        bool is_ghost = false;

        // Enhanced detection criteria
        if (obj.content.empty() || obj.content == "null") {
            is_ghost = true;
        }

        // Check for minimal dictionary with suspicious patterns
        if (obj.dictionary.size() <= 1 && !obj.has_stream) {
            is_ghost = true;
        }

        // Check for objects with only system-generated content
        if (obj.dictionary.size() == 1 && 
            obj.dictionary.find("/Length") != obj.dictionary.end() &&
            !obj.has_stream) {
            is_ghost = true;
        }

        // Check for objects that reference non-existent resources
        for (const auto& pair : obj.dictionary) {
            if (pair.second.find(" R") != std::string::npos) {
                std::regex ref_regex(R"((\d+)\s+\d+\s+R)");
                std::smatch match;
                if (std::regex_search(pair.second, match, ref_regex)) {
                    int ref_num = std::stoi(match[1].str());
                    bool ref_exists = false;
                    for (const auto& check_obj : structure.objects) {
                        if (check_obj.number == ref_num) {
                            ref_exists = true;
                            break;
                        }
                    }
                    if (!ref_exists) {
                        is_ghost = true;
                        break;
                    }
                }
            }
        }

        if (is_ghost) {
            suspected_ghosts.push_back(obj.number);
        }
    }

    // Remove detected ghost objects
    for (int ghost_num : suspected_ghosts) {
        thread_safe_remove_object(structure, ghost_num);
        safe_increment_stat(objects_removed_);
    }
}

// Performance optimizations
void PDFScrubber::parallel_process_objects(PDFStructure& structure) {
    // Note: This is a simplified parallel processing implementation
    // In a real implementation, you would use threading libraries

    // Group objects by type for efficient batch processing
    std::map<std::string, std::vector<size_t>> object_groups;

    for (size_t i = 0; i < structure.objects.size(); ++i) {
        const auto& obj = structure.objects[i];
        std::string type = "Unknown";

        auto type_it = obj.dictionary.find("/Type");
        if (type_it != obj.dictionary.end()) {
            type = type_it->second;
        }

        object_groups[type].push_back(i);
    }

    // Process each group
    for (const auto& group : object_groups) {
        for (size_t idx : group.second) {
            // Process object at index idx
            auto& obj = structure.objects[idx];

            // Optimize based on object type
            if (group.first == "/Font") {
                // Font-specific optimizations
                obj.dictionary.erase("/ToUnicode");
            } else if (group.first == "/Image") {
                // Image-specific optimizations
                obj.dictionary.erase("/ColorSpace");
            }
        }
    }
}

void PDFScrubber::optimize_memory_usage(PDFStructure& structure) {
    // Track total memory usage
    size_t initial_memory = total_memory_usage_.load();

    // Compress redundant data with memory monitoring
    std::map<std::string, std::string> content_cache;
    // Note: std::map doesn't have reserve(), using unordered_map would be better for performance

    for (auto& obj : structure.objects) {
        // Memory-efficient content deduplication
        auto content_it = content_cache.find(obj.content);
        if (content_it != content_cache.end()) {
            // Found duplicate content - optimize
            if (content_it->second.size() < obj.content.size()) {
                size_t memory_saved = obj.content.size() - content_it->second.size();
                obj.content = content_it->second;
                total_memory_usage_.fetch_sub(memory_saved, std::memory_order_relaxed);
                safe_increment_stat(objects_modified_);
            }
        } else {
            // Store content for future deduplication (memory-conscious)
            if (content_cache.size() < 1000) { // Limit cache size
                content_cache[obj.content] = obj.content;
            }
        }

        // Optimize stream data with memory safety
        optimize_stream_memory_usage(obj);
    }

    // Report memory optimization results
    size_t final_memory = total_memory_usage_.load();
    if (initial_memory > final_memory) {
        SILENT_LOG("[+] Memory optimization saved ") 
                  << (initial_memory - final_memory) / 1024 << " KB\n";
    }
}

// Validation and recovery
bool PDFScrubber::pre_scrubbing_validation(const PDFStructure& structure) {
    // Check basic PDF structure integrity
    if (structure.objects.empty()) {
        SILENT_ERROR("[!] No objects found in PDF structure\n");
        return false;
    }

    if (structure.version.empty()) {
        SILENT_ERROR("[!] No PDF version specified\n");
        return false;
    }

    // Check for required objects
    bool has_catalog = false;
    bool has_pages = false;

    for (const auto& obj : structure.objects) {
        auto type_it = obj.dictionary.find("/Type");
        if (type_it != obj.dictionary.end()) {
            if (type_it->second == "/Catalog") {
                has_catalog = true;
            } else if (type_it->second == "/Pages") {
                has_pages = true;
            }
        }
    }

    if (!has_catalog) {
        SILENT_ERROR("[!] No catalog object found\n");
        return false;
    }

    if (!has_pages) {
        SILENT_ERROR("[!] No pages object found\n");
        return false;
    }

    return true;
}

bool PDFScrubber::post_scrubbing_integrity_check(const PDFStructure& structure) {
    // Verify that essential PDF structure is maintained
    bool has_catalog = false;
    bool has_pages = false;

    for (const auto& obj : structure.objects) {
        auto type_it = obj.dictionary.find("/Type");
        if (type_it != obj.dictionary.end()) {
            if (type_it->second == "/Catalog") {
                has_catalog = true;
            } else if (type_it->second == "/Pages") {
                has_pages = true;
            }
        }
    }

    if (!has_catalog || !has_pages) {
        SILENT_ERROR("[!] Essential PDF objects missing after scrubbing\n");
        return false;
    }

    // Check trailer integrity
    auto size_it = structure.trailer.dictionary.find("/Size");
    if (size_it == structure.trailer.dictionary.end()) {
        SILENT_ERROR("[!] Trailer missing Size entry\n");
        return false;
    }

    // Verify object number consistency
    std::set<int> object_numbers;
    for (const auto& obj : structure.objects) {
        if (object_numbers.find(obj.number) != object_numbers.end()) {
            SILENT_ERROR("[!] Duplicate object number found: ") << obj.number << "\n";
            return false;
        }
        object_numbers.insert(obj.number);
    }

    return true;
}

void PDFScrubber::create_rollback_point(const PDFStructure& structure) {
    atomic_create_rollback_point(structure, "manual_rollback_point");
}

bool PDFScrubber::rollback_on_failure() {
    PDFStructure dummy_structure; // Will be overwritten if rollback succeeds
    return atomic_rollback_on_failure(dummy_structure);
}

void PDFScrubber::scrub_stream_metadata(PDFObject& obj) {
    if (obj.has_stream) {
        // Remove stream metadata
        obj.dictionary.erase("/CreationDate");
        obj.dictionary.erase("/ModDate");
        obj.dictionary.erase("/Producer");
        obj.dictionary.erase("/Creator");
    }
}

void PDFScrubber::remove_stream_filters(PDFObject& obj) {
    if (obj.has_stream) {
        obj.dictionary.erase("/Filter");
        obj.dictionary.erase("/DecodeParms");
        obj.is_compressed = false;
    }
}

void PDFScrubber::neutralize_stream_data(PDFObject& obj) {
    if (obj.has_stream) {
        // Replace suspicious stream data with neutral content
        std::string neutral = "% Neutralized stream content\n";
        obj.stream_data = PDFUtils::string_to_bytes(neutral);

        // Update length
        obj.dictionary["/Length"] = std::to_string(obj.stream_data.size());
    }
}

void PDFScrubber::scrub_trailer_dictionary(PDFStructure& structure) {
    // Clean trailer dictionary
    structure.trailer.dictionary.erase("/Info");
    structure.trailer.dictionary.erase("/ID");
    structure.trailer.dictionary.erase("/Encrypt");
    structure.trailer.dictionary.erase("/Prev");
    structure.trailer.has_prev = false;
}

void PDFScrubber::update_trailer_references(PDFStructure& structure) {
    // Update Size in trailer
    recalculate_trailer_size(structure);
}

void PDFScrubber::recalculate_trailer_size(PDFStructure& structure) {
    int max_obj_num = 0;
    for (const auto& obj : structure.objects) {
        // Check for potential overflow when comparing
        if (obj.number > max_obj_num && obj.number <= MAX_SAFE_OBJECT_NUMBER) {
            max_obj_num = obj.number;
        }
    }

    // Check for overflow when adding 1
    if (max_obj_num >= MAX_SAFE_OBJECT_NUMBER) {
        SILENT_ERROR("[!] Maximum object number too large for safe trailer size calculation\n");
        structure.trailer.dictionary["/Size"] = std::to_string(MAX_SAFE_OBJECT_NUMBER);
    } else {
        structure.trailer.dictionary["/Size"] = std::to_string(max_obj_num + 1);
    }
}

void PDFScrubber::rebuild_xref_table(PDFStructure& structure) {
    structure.xref_table.clear();

    for (const auto& obj : structure.objects) {
        PDFXRefEntry entry;
        entry.offset = obj.offset;
        entry.generation = obj.generation;
        entry.in_use = true;

        structure.xref_table[obj.number] = entry;
    }
}

void PDFScrubber::remove_unused_xref_entries(PDFStructure& structure) {
    std::set<int> used_objects = find_referenced_objects(structure);

    auto it = structure.xref_table.begin();
    while (it != structure.xref_table.end()) {
        if (used_objects.find(it->first) == used_objects.end()) {
            it = structure.xref_table.erase(it);
        } else {
            ++it;
        }
    }
}

void PDFScrubber::compact_object_numbers(PDFStructure& structure) {
    // Check for potential overflow before starting
    if (!validate_object_number_range(structure)) {
        SILENT_ERROR("[!] Object number range validation failed, applying fixes\n");
        fix_object_number_overflow(structure);
    }

    // Additional safety check for number of objects
    if (structure.objects.size() > static_cast<size_t>(MAX_SAFE_OBJECT_NUMBER)) {
        SILENT_ERROR("[!] Too many objects for safe renumbering: ") << structure.objects.size() << "\n";
        return; // Skip compacting to avoid overflow
    }

    // Renumber objects to be sequential starting from 1
    std::sort(structure.objects.begin(), structure.objects.end(),
              [](const PDFObject& a, const PDFObject& b) { return a.number < b.number; });

    std::map<int, int> renumber_map;
    int new_num = MIN_OBJECT_NUMBER;

    for (auto& obj : structure.objects) {
        // Check for overflow before assignment
        if (new_num > MAX_SAFE_OBJECT_NUMBER) {
            SILENT_ERROR("[!] Object number overflow detected during compacting at ") << new_num << "\n";
            break; // Stop renumbering to prevent overflow
        }

        renumber_map[obj.number] = new_num;
        obj.number = new_num;
        new_num = safe_increment_object_number(new_num);
    }

    // Update all references safely
    for (const auto& pair : renumber_map) {
        if (pair.first != pair.second) {
            update_object_references(structure, pair.first, pair.second);
        }
    }

    // Rebuild xref table
    rebuild_xref_table(structure);
}

void PDFScrubber::optimize_object_layout(PDFStructure& structure) {
    // Sort objects by number for optimal layout
    std::sort(structure.objects.begin(), structure.objects.end(),
              [](const PDFObject& a, const PDFObject& b) { return a.number < b.number; });
}

void PDFScrubber::ensure_pdf_compliance(PDFStructure& structure) {
    // Ensure required trailer entries exist
    if (structure.trailer.dictionary.find("/Size") == structure.trailer.dictionary.end()) {
        recalculate_trailer_size(structure);
    }

    // Ensure Root reference exists
    if (structure.trailer.dictionary.find("/Root") == structure.trailer.dictionary.end() && 
        !structure.root_object_ref.empty()) {
        structure.trailer.dictionary["/Root"] = structure.root_object_ref;
    }
}

void PDFScrubber::validate_scrubbed_structure(const PDFStructure& structure) {
    if (structure.objects.empty()) {
        throw SecureExceptions::SecurityViolationException("Scrubbing resulted in empty PDF structure");
    }

    if (structure.trailer.dictionary.empty()) {
        throw SecureExceptions::SecurityViolationException("Scrubbing removed essential trailer dictionary");
    }

    // Verify no sensitive data remains
    for (const auto& pair : structure.producer_info) {
        if (!pair.second.empty()) {
            SILENT_ERROR("Warning: Producer info not fully scrubbed: ") << pair.first << std::endl;
        }
    }

    if (!structure.javascript_actions.empty()) {
        SILENT_ERROR("Warning: JavaScript actions not fully scrubbed") << std::endl;
    }
}

bool PDFScrubber::is_info_object(const PDFObject& obj) {
    // Check if this is the Info object by looking for typical Info dictionary keys
    return obj.dictionary.find("/Producer") != obj.dictionary.end() ||
           obj.dictionary.find("/Creator") != obj.dictionary.end() ||
           obj.dictionary.find("/CreationDate") != obj.dictionary.end() ||
           obj.dictionary.find("/Author") != obj.dictionary.end();
}

bool PDFScrubber::is_metadata_object(const PDFObject& obj) {
    auto type_it = obj.dictionary.find("/Type");
    return type_it != obj.dictionary.end() && type_it->second == "/Metadata";
}

bool PDFScrubber::contains_javascript(const PDFObject& obj) {
    return obj.dictionary.find("/JS") != obj.dictionary.end() ||
           obj.dictionary.find("/JavaScript") != obj.dictionary.end() ||
           obj.content.find("JavaScript") != std::string::npos;
}

bool PDFScrubber::is_annotation_object(const PDFObject& obj) {
    auto type_it = obj.dictionary.find("/Type");
    return type_it != obj.dictionary.end() && type_it->second == "/Annot";
}

bool PDFScrubber::is_form_field_object(const PDFObject& obj) {
    auto ft_it = obj.dictionary.find("/FT");
    return ft_it != obj.dictionary.end() &&
           (ft_it->second == "/Tx" || ft_it->second == "/Ch" || 
            ft_it->second == "/Btn" || ft_it->second == "/Sig");
}

bool PDFScrubber::has_embedded_file(const PDFObject& obj) {
    auto type_it = obj.dictionary.find("/Type");
    return type_it != obj.dictionary.end() && type_it->second == "/EmbeddedFile";
}

bool PDFScrubber::is```cpp
_ghost_object(const PDFObject& obj) {
    // Objects with no meaningful content or references
    return obj.content.find("null") != std::string::npos && obj.dictionary.empty();
}

bool PDFScrubber::is_system_generated(const PDFObject& obj) {
    // Check for system-generated object indicators
    return obj.dictionary.find("/Producer") != obj.dictionary.end() ||
           obj.dictionary.find("/CreationDate") != obj.dictionary.end();
}

std::vector<int> PDFScrubber::get_objects_to_remove(const PDFStructure& structure) {
    std::vector<int> to_remove;

    for (const auto& obj : structure.objects) {
        if (is_metadata_object(obj) || 
            (neutralize_javascript_ && contains_javascript(obj)) ||
            (clean_embedded_files_ && has_embedded_file(obj)) ||
            (remove_annotations_ && is_annotation_object(obj))) {
            to_remove.push_back(obj.number);
        }
    }

    return to_remove;
}

std::vector<int> PDFScrubber::get_objects_to_modify(const PDFStructure& structure) {
    std::vector<int> to_modify;

    for (const auto& obj : structure.objects) {
        if ((scrub_creation_info_ && is_info_object(obj)) ||
            (remove_form_data_ && is_form_field_object(obj))) {
            to_modify.push_back(obj.number);
        }
    }

    return to_modify;
}

std::map<std::string, std::string> PDFScrubber::get_safe_dictionary_entries(const std::map<std::string, std::string>& dict) {
    std::map<std::string, std::string> safe_dict;

    // Only keep essential entries
    for (const auto& pair : dict) {
        if (pair.first == "/Type" || pair.first == "/Subtype" || 
            pair.first == "/Length" || pair.first == "/Filter" ||
            pair.first == "/Width" || pair.first == "/Height" ||
            pair.first == "/BitsPerComponent" || pair.first == "/ColorSpace") {
            safe_dict[pair.first] = pair.second;
        }
    }

    return safe_dict;
}

// Thread-safe helper method implementations
void PDFScrubber::safe_increment_stat(std::atomic<int>& stat, int value) {
    stat.fetch_add(value, std::memory_order_relaxed);
}

void PDFScrubber::thread_safe_remove_object(PDFStructure& structure, int obj_number) {
    std::unique_lock<std::shared_mutex> lock(structure_mutex_);

    structure.objects.erase(
        std::remove_if(structure.objects.begin(), structure.objects.end(),
                      [obj_number](const PDFObject& obj) { return obj.number == obj_number; }),
        structure.objects.end());

    structure.xref_table.erase(obj_number);
}

void PDFScrubber::thread_safe_modify_object(PDFStructure& structure, int obj_number, 
                                           const std::function<void(PDFObject&)>& modifier) {
    std::unique_lock<std::shared_mutex> lock(structure_mutex_);

    for (auto& obj : structure.objects) {
        if (obj.number == obj_number) {
            modifier(obj);
            break;
        }
    }
}

void PDFScrubber::parallel_process_objects_threadsafe(PDFStructure& structure) {
    // Group objects by type for efficient batch processing
    std::map<std::string, std::vector<PDFObject*>> object_groups;

    {
        std::shared_lock<std::shared_mutex> lock(structure_mutex_);
        for (auto& obj : structure.objects) {
            std::string type = "Unknown";

            auto type_it = obj.dictionary.find("/Type");
            if (type_it != obj.dictionary.end()) {
                type = type_it->second;
            }

            object_groups[type].push_back(&obj);
        }
    }

    // Process each group in parallel using futures
    std::vector<std::future<void>> futures;

    for (auto& group : object_groups) {
        futures.push_back(std::async(std::launch::async, 
            [this, &group]() {
                this->process_object_batch(group.second, group.first);
            }));
    }

    // Wait for all tasks to complete
    for (auto& future : futures) {
        future.wait();
    }
}

void PDFScrubber::process_object_batch(std::vector<PDFObject*>& batch, 
                                      const std::string& object_type) {
    std::unique_lock<std::shared_mutex> lock(structure_mutex_);

    for (auto* obj : batch) {
        // Optimize based on object type
        if (object_type == "/Font") {
            // Font-specific optimizations
            obj->dictionary.erase("/ToUnicode");
        } else if (object_type == "/Image") {
            // Image-specific optimizations
            obj->dictionary.erase("/ColorSpace");
        }
    }
}

// Memory management implementation
void PDFScrubber::optimize_stream_memory_usage(PDFObject& obj) {
    if (!obj.has_stream || obj.stream_data.empty()) {
        return;
    }

    size_t original_size = obj.stream_data.size();

    // Skip very large streams to prevent memory issues
    if (original_size > MAX_STREAM_SIZE) {
        SILENT_ERROR("[!] Warning: Stream size ") << original_size 
                  << " exceeds maximum safe size, skipping optimization\n";
        return;
    }

    // Validate stream content type before processing
    if (!validate_stream_content_type(obj)) {
        SILENT_ERROR("[!] Stream content validation failed for object ") << obj.number << "\n";
        return;
    }

    // Preserve binary stream integrity
    preserve_binary_stream_integrity(obj);

    // Check if stream is marked as binary
    auto binary_marker = obj.dictionary.find("/_BinaryStream");
    if (binary_marker != obj.dictionary.end() && binary_marker->second == "true") {
        SILENT_LOG("[+] Skipping text optimization for binary stream in object ") << obj.number << "\n";
        return;
    }

    // Only optimize text streams
    StreamType stream_type = detect_stream_type(obj);
    if (stream_type != StreamType::TEXT) {
        SILENT_LOG("[+] Skipping optimization for non-text stream type in object ") << obj.number << "\n";
        return;
    }

    // For large text streams, remove unnecessary whitespace and optimize
    if (original_size > 1024) {
        try {
            // Use safe conversion methods
            std::string stream_str = safe_bytes_to_string(obj.stream_data);

            if (stream_str.empty()) {
                SILENT_ERROR("[!] Cannot safely convert stream to string for object ") << obj.number << "\n";
                return;
            }

            // Remove excessive whitespace efficiently using safe regex
            stream_str = safe_normalize_whitespace(stream_str);

            std::vector<uint8_t> optimized_stream = safe_string_to_bytes(stream_str);

            if (optimized_stream.size() < original_size) {
                // Update memory tracking
                size_t memory_saved = original_size - optimized_stream.size();
                total_memory_usage_.fetch_sub(memory_saved, std::memory_order_relaxed);

                // Use move semantics to avoid extra copying
                obj.stream_data = std::move(optimized_stream);
                obj.dictionary["/Length"] = std::to_string(obj.stream_data.size());
                safe_increment_stat(streams_cleaned_);

                SILENT_LOG("[+] Optimized text stream for object ") << obj.number 
                          << ", saved " << memory_saved << " bytes\n";
            }
        } catch (const std::exception& e) {
            SILENT_ERROR("[!] Error optimizing stream for object ") << obj.number 
                      << ": " << e.what() << "\n";
        }
    }
}

bool PDFScrubber::check_memory_bounds(size_t current_size, size_t additional_size) {
    // Check if adding additional_size would exceed safe limits
    if (current_size > MAX_STREAM_SIZE || additional_size > MAX_PATTERN_SIZE) {
        return false;
    }

    if (current_size + additional_size > MAX_STREAM_SIZE) {
        return false;
    }

    // Check global memory usage
    size_t current_total = total_memory_usage_.load(std::memory_order_relaxed);
    size_t estimated_total = current_total + additional_size;

    // Simple heuristic: don't exceed reasonable memory limits
    constexpr size_t MAX_TOTAL_MEMORY = 500 * 1024 * 1024; // 500MB limit
    return estimated_total < MAX_TOTAL_MEMORY;
}

void PDFScrubber::prevent_memory_fragmentation(std::vector<uint8_t>& stream_data, 
                                              const std::vector<uint8_t>& pattern) {
    if (stream_data.empty() || pattern.empty()) {
        return;
    }

    // Reserve space to prevent multiple reallocations
    size_t estimated_final_size = stream_data.size() + (pattern.size() * 3); // 3 insertions max

    if (estimated_final_size <= MAX_STREAM_SIZE) {
        stream_data.reserve(estimated_final_size);
    }
}

void PDFScrubber::safe_entropy_insertion(PDFObject& obj, const std::vector<uint8_t>& pattern) {
    if (!obj.has_stream || obj.stream_data.empty() || pattern.empty()) {
        return;
    }

    // Check resource limits before proceeding
    if (!can_perform_entropy_insertion()) {
        SILENT_ERROR("[!] Entropy insertion limit reached, skipping object ") << obj.number << "\n";
        return;
    }

    // Prevent memory fragmentation
    prevent_memory_fragmentation(obj.stream_data, pattern);

    // Limit number of insertions based on stream size and resource limits
    size_t max_insertions = std::min({
        ResourceLimits::MAX_ENTROPY_INSERTIONS_PER_OBJECT,
        obj.stream_data.size() / 100,
        3UL
    });

    if (max_insertions == 0) {
        max_insertions = 1;
    }

    // Use secure random generation for insertion positions
    std::vector<uint8_t> position_bytes = generate_secure_random_bytes(max_insertions * 4);

    // Track memory usage increase
    size_t memory_increase = pattern.size() * max_insertions;
    total_memory_usage_.fetch_add(memory_increase, std::memory_order_relaxed);

    try {
        // Perform insertions from back to front to maintain position validity
        std::vector<size_t> positions;
        positions.reserve(max_insertions);

        for (size_t i = 0; i < max_insertions; ++i) {
            if (obj.stream_data.size() > pattern.size() + 10) {
                size_t max_pos = obj.stream_data.size() - pattern.size() - 5;
                // Use secure random bytes to determine position
                uint32_t random_val = 0;
                if (i * 4 + 3 < position_bytes.size()) {
                    random_val = (position_bytes[i*4] << 24) | (position_bytes[i*4+1] << 16) | 
                                (position_bytes[i*4+2] << 8) | position_bytes[i*4+3];
                }
                positions.push_back(random_val % max_pos);
            }
        }

        // Sort positions in descending order for back-to-front insertion
        std::sort(positions.rbegin(), positions.rend());

        for (size_t pos : positions) {
            if (pos < obj.stream_data.size()) {
                obj.stream_data.insert(obj.stream_data.begin() + pos, 
                                     pattern.begin(), pattern.end());
            }
        }

        // Update length dictionary entry
        obj.dictionary["/Length"] = std::to_string(obj.stream_data.size());

    } catch (const std::exception& e) {
        // Rollback memory tracking on failure
        total_memory_usage_.fetch_sub(memory_increase, std::memory_order_relaxed);
        SILENT_ERROR("[!] Error during entropy insertion for object ") << obj.number 
                  << ": " << e.what() << "\n";
    }
}

size_t PDFScrubber::calculate_safe_pattern_size(size_t stream_size, const std::string& object_type) {
    // Conservative sizing based on stream size and type
    size_t base_size = 0;

    if (object_type == "/Font") {
        base_size = 8;
    } else if (object_type == "/Image") {
        base_size = 12;
    } else {
        base_size = 6;
    }

    // Scale down for smaller streams
    if (stream_size < 1024) {
        base_size = std::min(base_size, stream_size / 100);
    } else if (stream_size < 10240) {
        base_size = std::min(base_size, size_t(8));
    }

    // Enforce absolute maximum
    base_size = std::min(base_size, size_t(MAX_PATTERN_SIZE));

    // Don't create patterns for very small streams
    if (stream_size < 50 || base_size == 0) {
        return 0;
    }

    return base_size;
}

// Integer overflow protection implementation
bool PDFScrubber::check_object_number_overflow(int current_max, int additional_objects) {
    // Check if adding additional_objects would cause overflow
    if (current_max < 0 || additional_objects < 0) {
        return false; // Invalid input
    }

    if (current_max > MAX_SAFE_OBJECT_NUMBER) {
        return false; // Already at or beyond safe limit
    }

    // Check if addition would overflow
    if (additional_objects > MAX_SAFE_OBJECT_NUMBER - current_max) {
        return false; // Would cause overflow
    }

    return true;
}

int PDFScrubber::safe_increment_object_number(int current_number) {
    if (current_number < 0) {
        return MIN_OBJECT_NUMBER; // Reset to safe minimum
    }

    if (current_number >= MAX_SAFE_OBJECT_NUMBER) {
        SILENT_ERROR("[!] Object number at maximum safe value, cannot increment\n");
        return MAX_SAFE_OBJECT_NUMBER;
    }

    return current_number + 1;
}

bool PDFScrubber::validate_object_number_range(const PDFStructure& structure) {
    for (const auto& obj : structure.objects) {
        // Check for invalid object numbers
        if (obj.number < MIN_OBJECT_NUMBER || obj.number > MAX_SAFE_OBJECT_NUMBER) {
            SILENT_ERROR("[!] Invalid object number detected: ") << obj.number << "\n";
            return false;
        }
    }

    // Check for duplicate object numbers
    std::set<int> seen_numbers;
    for (const auto& obj : structure.objects) {
        if (seen_numbers.find(obj.number) != seen_numbers.end()) {
            SILENT_ERROR("[!] Duplicate object number detected: ") << obj.number << "\n";
            return false;
        }
        seen_numbers.insert(obj.number);
    }

    return true;
}

void PDFScrubber::fix_object_number_overflow(PDFStructure& structure) {
    SILENT_LOG("[+] Fixing object number overflow issues...\n");

    // Remove objects with invalid numbers
    auto it = std::remove_if(structure.objects.begin(), structure.objects.end(),
        [this](const PDFObject& obj) {
            return obj.number < MIN_OBJECT_NUMBER || obj.number > MAX_SAFE_OBJECT_NUMBER;
        });

    if (it != structure.objects.end()) {
        size_t removed_count = std::distance(it, structure.objects.end());
        structure.objects.erase(it, structure.objects.end());
        SILENT_LOG("[+] Removed ") << removed_count << " objects with invalid numbers\n";
    }

    // Fix duplicate object numbers by renumbering
    std::set<int> used_numbers;
    int next_available = MIN_OBJECT_NUMBER;

    for (auto& obj : structure.objects) {
        if (used_numbers.find(obj.number) != used_numbers.end()) {
            // SECURITY FIX: Duplicate found, assign new number with safe bounds checking
            while (used_numbers.find(next_available) != used_numbers.end() && 
                   next_available <= MAX_SAFE_OBJECT_NUMBER) {
                next_available++;
            }

            if (next_available <= MAX_SAFE_OBJECT_NUMBER) {
                SILENT_LOG("[+] Renumbering duplicate object ") << obj.number 
                          << " to " << next_available << "\n";
                obj.number = next_available;
                used_numbers.insert(next_available);
                next_available++;
            } else {
                SILENT_ERROR("[!] Cannot fix duplicate - too many objects\n");
                break;
            }
        } else {
            used_numbers.insert(obj.number);
        }
    }

    // Rebuild xref table after fixes
    rebuild_xref_table(structure);
}

// Reference validation and circular dependency detection implementation
bool PDFScrubber::detect_circular_references(const PDFStructure& structure) {
    std::set<int> all_objects;
    for (const auto& obj : structure.objects) {
        all_objects.insert(obj.number);
    }

    // Check each object for circular dependencies
    for (int obj_num : all_objects) {
        std::set<int> visited;
        std::set<int> recursion_stack;

        if (has_circular_dependency(structure, obj_num, visited, recursion_stack)) {
            SILENT_ERROR("[!] Circular reference detected starting from object ") << obj_num << "\n";
            return true;
        }
    }

    return false;
}

bool PDFScrubber::validate_reference_integrity(const PDFStructure& structure) {
    // Check for circular references
    if (detect_circular_references(structure)) {
        return false;
    }

    // Validate all references point to existing objects
    std::set<int> valid_objects;
    for (const auto& obj : structure.objects) {
        valid_objects.insert(obj.number);
    }

    for (const auto& obj : structure.objects) {
        std::set<int> references = get_object_references(obj);

        for (int ref_num : references) {
            if (ref_num > 0 && valid_objects.find(ref_num) == valid_objects.end()) {
                SILENT_ERROR("[!] Invalid reference to non-existent object ") << ref_num 
                          << " from object " << obj.number << "\n";
                return false;
            }
        }
    }

    return true;
}

std::set<int> PDFScrubber::get_object_references(const PDFObject& obj) {
    std::set<int> references;

    // Extract references from dictionary values
    for (const auto& pair : obj.dictionary) {
        const std::string& value = pair.second;

        // Look for patterns like "123 0 R"
        std::regex ref_pattern(R"((\d+)\s+\d+\s+R)");
        std::sregex_iterator iter(value.begin(), value.end(), ref_pattern);
        std::sregex_iterator end;

        for (; iter != end; ++iter) {
            const std::smatch& match = *iter;
            try {
                int ref_num = std::stoi(match[1].str());
                if (ref_num > 0) {
                    references.insert(ref_num);
                }
            } catch (const std::exception&) {
                // Ignore invalid number formats
            }
        }
    }

    // Extract references from content
    std::regex ref_pattern(R"((\d+)\s+\d+\s+R)");
    std::sregex_iterator iter(obj.content.begin(), obj.content.end(), ref_pattern);
    std::sregex_iterator end;

    for (; iter != end; ++iter) {
        const std::smatch& match = *iter;
        try {
            int ref_num = std::stoi(match[1].str());
            if (ref_num > 0) {
                references.insert(ref_num);
            }
        } catch (const std::exception&) {
            // Ignore invalid number formats
        }
    }

    return references;
}

bool PDFScrubber::has_circular_dependency(const PDFStructure& structure, int start_obj, 
                                         std::set<int>& visited, std::set<int>& recursion_stack) {
    // If we've seen this object in the current path, we have a cycle
    if (recursion_stack.find(start_obj) != recursion_stack.end()) {
        return true;
    }

    // If we've already processed this object completely, no cycle here
    if (visited.find(start_obj) != visited.end()) {
        return false;
    }

    // Add to current path
    recursion_stack.insert(start_obj);

    // Find the object in the structure
    const PDFObject* current_obj = nullptr;
    for (const auto& obj : structure.objects) {
        if (obj.number == start_obj) {
            current_obj = &obj;
            break;
        }
    }

    if (current_obj) {
        // Get all references from this object
        std::set<int> references = get_object_references(*current_obj);

        // Recursively check each reference
        for (int ref_num : references) {
            if (has_circular_dependency(structure, ref_num, visited, recursion_stack)) {
                return true;
            }
        }
    }

    // Remove from current path and mark as visited
    recursion_stack.erase(start_obj);
    visited.insert(start_obj);

    return false;
}

void PDFScrubber::fix_circular_references(PDFStructure& structure) {
    SILENT_LOG("[+] Fixing circular references...\n");

    // Find all circular reference chains
    std::set<int> problematic_objects;
    std::set<int> all_objects;

    for (const auto& obj : structure.objects) {
        all_objects.insert(obj.number);
    }

    for (int obj_num : all_objects) {
        std::set<int> visited;
        std::set<int> recursion_stack;

        if (has_circular_dependency(structure, obj_num, visited, recursion_stack)) {
            // Add all objects in the recursion stack to problematic list
            problematic_objects.insert(recursion_stack.begin(), recursion_stack.end());
        }
    }

    if (problematic_objects.empty()) {
        SILENT_LOG("[+] No circular references found to fix\n");
        return;
    }

    SILENT_LOG("[+] Found ") << problematic_objects.size() << " objects involved in circular references\n";

    // Break circular references by removing problematic references
    for (auto& obj : structure.objects) {
        if (problematic_objects.find(obj.number) != problematic_objects.end()) {
            // Get references from this object
            std::set<int> references = get_object_references(obj);

            // Remove references to other problematic objects
            for (auto& pair : obj.dictionary) {
                std::string& value = pair.second;

                for (int prob_ref : problematic_objects) {
                    if (prob_ref != obj.number && references.find(prob_ref) != references.end()) {
                        std::string ref_str = std::to_string(prob_ref) + " 0 R";
                        size_t pos = value.find(ref_str);

                        if (pos != std::string::npos) {
                            // Replace with null reference
                            value.replace(pos, ref_str.length(), "null");
                            SILENT_LOG("[+] Removed circular reference from object ") 
                                      << obj.number << " to object " << prob_ref << "\n";
                        }
                    }
                }
            }

            // Also clean content
            for (int prob_ref : problematic_objects) {
                if (prob_ref != obj.number && references.find(prob_ref) != references.end()) {
                    std::string ref_str = std::to_string(prob_ref) + " 0 R";
                    size_t pos = obj.content.find(ref_str);

                    if (pos != std::string::npos) {
                        obj.content.replace(pos, ref_str.length(), "null");
                    }
                }
            }
        }
    }

    // Verify circular references are fixed
    if (!detect_circular_references(structure)) {
        SILENT_LOG("[+] Circular references successfully fixed\n");
    } else {
        SILENT_ERROR("[!] Some circular references remain after fixing attempt\n");
    }
}

bool PDFScrubber::is_valid_reference_format(const std::string& reference) {
    // Check if reference matches pattern "number generation R"
    std::regex ref_pattern(R"(^\d+\s+\d+\s+R$)");
    return std::regex_match(reference, ref_pattern);
}

void PDFScrubber::validate_and_fix_references(PDFStructure& structure) {
    SILENT_LOG("[+] Validating and fixing PDF reference integrity...\n");

    // First pass: detect and fix circular references
    if (detect_circular_references(structure)) {
        fix_circular_references(structure);
    }

    // Second pass: validate all references point to existing objects
    std::set<int> valid_objects;
    for (const auto& obj : structure.objects) {
        valid_objects.insert(obj.number);
    }

    int fixed_references = 0;

    for (auto& obj : structure.objects) {
        std::set<int> references = get_object_references(obj);

        for (int ref_num : references) {
            if (ref_num > 0 && valid_objects.find(ref_num) == valid_objects.end()) {
                // Invalid reference found - replace with null
                std::string invalid_ref = std::to_string(ref_num) + " 0 R";

                // Fix in dictionary
                for (auto& pair : obj.dictionary) {
                    std::string& value = pair.second;
                    size_t pos = value.find(invalid_ref);
                    if (pos != std::string::npos) {
                        value.replace(pos, invalid_ref.length(), "null");
                        fixed_references++;
                    }
                }

                // Fix in content
                size_t pos = obj.content.find(invalid_ref);
                if (pos != std::string::npos) {
                    obj.content.replace(pos, invalid_ref.length(), "null");
                    fixed_references++;
                }
            }
        }
    }

    if (fixed_references > 0) {
        SILENT_LOG("[+] Fixed ") << fixed_references << " invalid references\n";
    }

    // Final validation
    if (validate_reference_integrity(structure)) {
        SILENT_LOG("[+] PDF reference integrity validation passed\n");
    } else {
        SILENT_ERROR("[!] Reference integrity issues remain after fixing\n");
    }
}

// Regex performance and ReDoS protection implementation
bool PDFScrubber::safe_regex_replace(std::string& input, const std::regex& pattern, 
                                    const std::string& replacement) {
    // Check input size limit
    if (input.size() > MAX_REGEX_INPUT_SIZE) {
        SILENT_ERROR("[!] Input too large for regex operation: ") << input.size() << " bytes\n";
        return false;
    }

    // Check for complexity patterns that could cause ReDoS
    if (!check_regex_complexity(input)) {
        SILENT_ERROR("[!] Input complexity too high for safe regex operation\n");
        return false;
    }

    try {
        auto start_time = std::chrono::steady_clock::now();

        // Perform regex replacement with timeout check
        std::string result = std::regex_replace(input, pattern, replacement);

        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

        if (duration > REGEX_TIMEOUT) {
            SILENT_ERROR("[!] Regex operation exceeded timeout: ") << duration.count() << "ms\n";
            return false;
        }

        input = std::move(result);
        return true;

    } catch (const std::exception& e) {
        SILENT_ERROR("[!] Regex operation failed: ") << e.what() << "\n";
        return false;
    }
}

std::string PDFScrubber::safe_normalize_whitespace(const std::string& input) {
    std::string result = input;

    // Sanitize input first
    result = sanitize_regex_input(result);

    // Use simple, non-catastrophic regex patterns
    try {
        // Replace multiple whitespace with single space (safe pattern)
        std::regex safe_whitespace_pattern(R"([ \t]{2,})");
        if (!safe_regex_replace(result, safe_whitespace_pattern, " ")) {
            // Fallback to manual whitespace normalization
            std::string manual_result;
            manual_result.reserve(result.size());

            bool in_whitespace = false;
            for (char c : result) {
                if (c == ' ' || c == '\t') {
                    if (!in_whitespace) {
                        manual_result += ' ';
                        in_whitespace = true;
                    }
                } else {
                    manual_result += c;
                    in_whitespace = false;
                }
            }
            result = std::move(manual_result);
        }

        // Remove leading and trailing whitespace (safe pattern)
        std::regex safe_trim_pattern(R"(^[ \t]+|[ \t]+$)");
        if (!safe_regex_replace(result, safe_trim_pattern, "")) {
            // Fallback to manual trimming
            size_t start = result.find_first_not_of(" \t");
            if (start != std::string::npos) {
                size_t end = result.find_last_not_of(" \t");
                result = result.substr(start, end - start + 1);
            } else {
                result.clear();
            }
        }

    } catch (const std::exception& e) {
        SILENT_ERROR("[!] Safe whitespace normalization failed: ") << e.what() << "\n";
        // Return sanitized input as fallback
        return sanitize_regex_input(input);
    }

    return result;
}

std::string PDFScrubber::safe_remove_comment_blocks(const std::string& input) {
    std::string result = input;

    // Sanitize input first
    result = sanitize_regex_input(result);

    try {
        // Use simple, non-catastrophic regex for comment removal
        std::regex safe_comment_pattern(R"(%[^\r\n]*)");
        if (!safe_regex_replace(result, safe_comment_pattern, "")) {
            // Fallback to manual comment removal
            std::string manual_result;
            manual_result.reserve(result.size());

            std::istringstream iss(result);
            std::string line;
            while (std::getline(iss, line)) {
                // Find % not in a string literal
                size_t comment_pos = line.find('%');
                if (comment_pos != std::string::npos) {
                    // Simple heuristic: remove from % to end of line
                    line = line.substr(0, comment_pos);
                }
                manual_result += line + '\n';
            }
            result = std::move(manual_result);
        }

        // Remove excessive newlines (safe pattern)
        std::regex safe_newline_pattern(R"(\n{3,})");
        if (!safe_regex_replace(result, safe_newline_pattern, "\n\n")) {
            // Fallback to manual newline normalization
            std::string manual_result;
            manual_result.reserve(result.size());

            int consecutive_newlines = 0;
            for (char c : result) {
                if (c == '\n') {
                    consecutive_newlines++;
                    if (consecutive_newlines <= 2) {
                        manual_result += c;
                    }
                } else {
                    consecutive_newlines = 0;
                    manual_result += c;
                }
            }
            result = std::move(manual_result);
        }

    } catch (const std::exception& e) {
        SILENT_ERROR("[!] Safe comment removal failed: ") << e.what() << "\n";
        // Return sanitized input as fallback
        return sanitize_regex_input(input);
    }

    return result;
}

bool PDFScrubber::check_regex_complexity(const std::string& input) {
    // Check for patterns that could cause catastrophic backtracking

    // Limit on consecutive repeating characters
    int max_consecutive = 0;
    int current_consecutive = 1;
    char last_char = 0;

    for (char c : input) {
        if (c == last_char) {
            current_consecutive++;
            max_consecutive = std::max(max_consecutive, current_consecutive);
        } else {
            current_consecutive = 1;
            last_char = c;
        }
    }

    // Reject if too many consecutive characters (potential ReDoS)
    if (max_consecutive > 1000) {
        SILENT_ERROR("[!] Input has ") << max_consecutive << " consecutive characters - potential ReDoS\n";
        return false;
    }

    // Check for excessive nesting patterns
    int paren_depth = 0;
    int max_paren_depth = 0;
    int bracket_depth = 0;
    int max_bracket_depth = 0;

    for (char c : input) {
        switch (c) {
            case '(':
                paren_depth++;
                max_paren_depth = std::max(max_paren_depth, paren_depth);
                break;
            case ')':
                paren_depth = std::max(0, paren_depth - 1);
                break;
            case '[':
                bracket_depth++;
                max_bracket_depth = std::max(max_bracket_depth, bracket_depth);
                break;
            case ']':
                bracket_depth = std::max(0, bracket_depth - 1);
                break;
        }
    }

    // Reject if nesting too deep
    if (max_paren_depth > 100 || max_bracket_depth > 100) {
        SILENT_ERROR("[!] Input has excessive nesting - potential ReDoS\n");
        return false;
    }

    return true;
}

std::string PDFScrubber::sanitize_regex_input(const std::string& input) {
    std::string result;
    result.reserve(input.size());

    // Remove or escape potentially dangerous patterns
    for (size_t i = 0; i < input.size(); ++i) {
        char c = input[i];

        // Skip null bytes and other control characters that could cause issues
        if (c == '\0' || (c > 0 && c < 32 && c != '\t' && c != '\n' && c != '\r')) {
            continue;
        }

        // Limit consecutive special characters to prevent ReDoS
        if ((c == '*' || c == '+' || c == '?' || c == '{' || c == '}') && 
            i > 0 && input[i-1] == c) {
            // Skip excessive special characters
            continue;
        }

        result += c;

        // Limit total size during sanitization
        if (result.size() >= MAX_REGEX_INPUT_SIZE) {
            break;
        }
    }

    return result;
}

// MISSING SETTER IMPLEMENTATIONS - Integration Fix
void PDFScrubber::set_ml_evasion_engine(MLEvasionEngine* engine) {
    ml_evasion_engine_ = engine;
}

void PDFScrubber::set_lifecycle_simulator(DocumentLifecycleSimulator* simulator) {
    lifecycle_simulator_ = simulator;
}

void PDFScrubber::set_metadata_engine(ProfessionalMetadataEngine* engine) {
    metadata_engine_ = engine;
}

void PDFScrubber::set_pattern_masker(StatisticalPatternMasker* masker) {
    pattern_masker_ = masker;
}

void PDFScrubber::set_pattern_recognizer(AdvancedPatternRecognizer* recognizer) {
    pattern_recognizer_ = recognizer;
}

void PDFScrubber::set_format_manager(FormatMigrationManager* manager) {
    format_manager_ = manager;
}

void PDFScrubber::set_version_converter(PDFVersionConverter* converter) {
    version_converter_ = converter;
}

void PDFScrubber::set_entropy_analyzer(EntropyAnalysis* analyzer) {
    entropy_analyzer_ = analyzer;
}

void PDFScrubber::set_performance_optimizer(PerformanceOptimizer* optimizer) {
    performance_optimizer_ = optimizer;
}

void PDFScrubber::set_temporal_manager(TemporalConsistencyManager* manager) {
    temporal_manager_ = manager;
}

void PDFScrubber::set_validation_engine(FormatValidationEngine* engine) {
    validation_engine_ = engine;
}

void PDFScrubber::set_anti_fingerprint_engine(AntiFingerprintEngine* engine) {
    anti_fingerprint_engine_ = engine;
}

// Add missing scrub_pdf method with config
struct ScrubResult {
    bool success = false;
    std::vector<uint8_t> scrubbed_content;
    std::string error_message;
};

ScrubResult PDFScrubber::scrub_pdf(const std::string& pdf_content, const ScrubberConfig& config) {
    ScrubResult result;

    try {
        // Apply configuration settings
        remove_all_metadata_ = config.remove_metadata;
        neutralize_javascript_ = config.remove_javascript;
        clean_embedded_files_ = config.remove_embedded_files;
        aggressive_scrubbing_ = config.deep_clean;

        // Convert string to bytes
        std::vector<uint8_t> pdf_data(pdf_content.begin(), pdf_content.end());

        // Parse PDF
        PDFParser parser;
        PDFStructure structure = parser.parse(pdf_data);

        // Apply scrubbing
        PDFStructure scrubbed_structure = scrub(structure);

        // Convert back to bytes
        result.scrubbed_content = structure_to_bytes(scrubbed_structure);
        result.success = true;

    } catch (const std::exception& e) {
        result.success = false;
        result.error_message = e.what();
    }

    return result;
}

// File processing interface
bool PDFScrubber::scrub_pdf(const std::string& input_path, const std::string& output_path) {
    try {
        // Read input PDF
        std::ifstream file(input_path, std::ios::binary);
        if (!file) {
            return false;
        }

        std::vector<uint8_t> pdf_data((std::istreambuf_iterator<char>(file)),
                                     std::istreambuf_iterator<char>());
        file.close();

        // MISSING: ML evasion analysis
        if (ml_evasion_engine_) {
            ml_evasion_engine_->analyze_and_evade(pdf_data);
        }

        // MISSING: Document lifecycle simulation
        if (lifecycle_simulator_) {
            lifecycle_simulator_->simulate_professional_workflow(pdf_data);
        }

        // MISSING: Professional metadata processing
        if (metadata_engine_) {
            metadata_engine_->process_professional_metadata(pdf_data);
        }

        // MISSING: Statistical pattern masking
        if (pattern_masker_) {
            pattern_masker_->mask_statistical_patterns(pdf_data);
        }

        // MISSING: Advanced pattern recognition
        if (pattern_recognizer_) {
            pattern_recognizer_->recognize_and_neutralize_patterns(pdf_data);
        }

        // MISSING: Format migration
        if (format_manager_) {
            format_manager_->migrate_format(pdf_data);
        }

        // MISSING: Version conversion
        if (version_converter_) {
            version_converter_->convert_version(pdf_data);
        }

        // MISSING: Entropy analysis
        if (entropy_analyzer_) {
            entropy_analyzer_->analyze_entropy(pdf_data);
        }

        // MISSING: Performance optimization
        if (performance_optimizer_) {
            performance_optimizer_->optimize_performance(pdf_data);
        }

        // Advanced Engine Processing - Integration Complete
        if (temporal_manager_) {
            temporal_manager_->maintain_temporal_consistency(pdf_data);
        }

        if (validation_engine_) {
            validation_engine_->validate_format_integrity(pdf_data);
        }

        if (anti_fingerprint_engine_) {
            anti_fingerprint_engine_->apply_anti_fingerprint_techniques(pdf_data);
        }

        // Write output PDF
        std::ofstream output(output_path, std::ios::binary);
        if (!output) {
            return false;
        }

        output.write(reinterpret_cast<const char*>(pdf_data.data()), pdf_data.size());
        output.close();

        return true;

    } catch (...) {
        return false;
    }
}

// Security and Stealth Component Setter Methods - Integration Complete
void PDFScrubber::set_stealth_scrubber(StealthScrubber* scrubber) {
    ENFORCE_COMPLETE_SILENCE();
    stealth_scrubber_ = scrubber;
}

void PDFScrubber::set_trace_cleaner(TraceCleaner* cleaner) {
    ENFORCE_COMPLETE_SILENCE();
    trace_cleaner_ = cleaner;
}

void PDFScrubber::set_metadata_cleaner(MetadataCleaner* cleaner) {
    ENFORCE_COMPLETE_SILENCE();
    metadata_cleaner_ = cleaner;
}

void PDFScrubber::set_memory_guard(MemoryGuard* guard) {
    ENFORCE_COMPLETE_SILENCE();
    memory_guard_ = guard;
}

void PDFScrubber::set_memory_sanitizer(MemorySanitizer* sanitizer) {
    ENFORCE_COMPLETE_SILENCE();
    memory_sanitizer_ = sanitizer;
}

void PDFScrubber::set_pdf_integrity_checker(PDFIntegrityChecker* checker) {
    ENFORCE_COMPLETE_SILENCE();
    pdf_integrity_checker_ = checker;
}

void PDFScrubber::set_integrity_checker(IntegrityChecker* checker) {
    ENFORCE_COMPLETE_SILENCE();
    integrity_checker_ = checker;
}

// Helper functions for security component integration
std::vector<uint8_t> PDFScrubber::structure_to_bytes(const PDFStructure& structure) {
    ENFORCE_COMPLETE_SILENCE();

    // Convert PDFStructure to byte vector for security component processing
    std::vector<uint8_t> result;

    // Add PDF header
    std::string header = "%PDF-1.4\n";
    result.insert(result.end(), header.begin(), header.end());

    // Serialize objects
    for (const auto& obj : structure.objects) {
        std::string obj_str = std::to_string(obj.number) + " 0 obj\n";
        result.insert(result.end(), obj_str.begin(), obj_str.end());

        // Add dictionary entries
        if (!obj.dictionary.empty()) {
            std::string dict_start = "<<\n";
            result.insert(result.end(), dict_start.begin(), dict_start.end());

            for (const auto& entry : obj.dictionary) {
                std::string dict_entry = entry.first + " " + entry.second + "\n";
                result.insert(result.end(), dict_entry.begin(), dict_entry.end());
            }

            std::string dict_end = ">>\n";
            result.insert(result.end(), dict_end.begin(), dict_end.end());
        }

        // Add stream data if present
        if (!obj.stream_data.empty()) {
            std::string stream_start = "stream\n";
            result.insert(result.end(), stream_start.begin(), stream_start.end());
            result.insert(result.end(), obj.stream_data.begin(), obj.stream_data.end());
            std::string stream_end = "\nendstream\n";
            result.insert(result.end(), stream_end.begin(), stream_end.end());
        }

        std::string obj_end = "endobj\n";
        result.insert(result.end(), obj_end.begin(), obj_end.end());
    }

    // Add trailer
    std::string trailer = "trailer\n<<\n/Size " + std::to_string(structure.objects.size()) + "\n>>\n%%EOF\n";
    result.insert(result.end(), trailer.begin(), trailer.end());

    return result;
}

PDFStructure PDFScrubber::bytes_to_structure(const std::vector<uint8_t>& bytes) {
    ENFORCE_COMPLETE_SILENCE();

    // Convert byte vector back to PDFStructure after security component processing
    PDFStructure structure;

    // Simple parsing for security component integration
    std::string content(bytes.begin(), bytes.end());

    // Parse objects (simplified for security component compatibility)
    size_t pos = 0;
    int obj_number = 1;

    while ((pos = content.find(" 0 obj", pos)) != std::string::npos) {
        PDFObject obj;
        obj.number = obj_number++;

        // Find object end
        size_t obj_end = content.find("endobj", pos);
        if (obj_end != std::string::npos) {
            std::string obj_content = content.substr(pos, obj_end - pos);

            // Parse dictionary (simplified)
            size_t dict_start = obj_content.find("<<");
            size_t dict_end = obj_content.find(">>");
            if (dict_start != std::string::npos && dict_end != std::string::npos) {
                std::string dict_content = obj_content.substr(dict_start + 2, dict_end - dict_start - 2);
                // Simplified dictionary parsing for security integration
                obj.dictionary["/Type"] = "/Object";
            }

            // Parse stream data (simplified)
            size_t stream_start = obj_content.find("stream");
            size_t stream_end = obj_content.find("endstream");
            if (stream_start != std::string::npos && stream_end != std::string::npos) {
                stream_start += 6; // Skip "stream"
                obj.stream_data.assign(bytes.begin() + pos + stream_start, 
                                      bytes.begin() + pos + stream_end);
            }

            structure.objects.push_back(obj);
        }

        pos = obj_end + 6; // Skip "endobj"
    }

    return structure;
}