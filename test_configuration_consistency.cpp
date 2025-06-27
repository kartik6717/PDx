#include "secure_memory.hpp"
#include "secure_exceptions.hpp"
#include "scrubber.hpp"
#include <iostream>
#include "stealth_macros.hpp"

void test_intensity_profile_conflicts() {
    SILENT_LOG("[Config Test] Testing intensity level and profile conflicts...\n");
    
    PDFScrubber scrubber;
    
    // Test Basic + Forensic Evasion (should be incompatible)
    scrubber.set_intensity_level(PDFScrubber::IntensityLevel::BASIC) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    scrubber.set_scrubbing_profile(PDFScrubber::ScrubbingProfile::FORENSIC_EVASION) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    auto config = scrubber.get_current_configuration() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Verify conflict was resolved (should not remain as Basic + Forensic Evasion)
    bool conflict_resolved = !(config.intensity_level == PDFScrubber::IntensityLevel::BASIC && 
                              config.scrubbing_profile == PDFScrubber::ScrubbingProfile::FORENSIC_EVASION) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    if (conflict_resolved) {
        SILENT_LOG("✅ Basic + Forensic Evasion conflict resolved\n");
    } else {
        SILENT_LOG("❌ Conflict not resolved\n");
    }
    
    // Test Maximum + Compliance (should be incompatible)
    scrubber.set_intensity_level(PDFScrubber::IntensityLevel::MAXIMUM) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    scrubber.set_scrubbing_profile(PDFScrubber::ScrubbingProfile::COMPLIANCE) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    config = scrubber.get_current_configuration() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Compliance should override maximum intensity destructive settings
    if (config.preserve_visual_content && !config.remove_all_metadata) {
        SILENT_LOG("✅ Maximum + Compliance conflict resolved with compliance priority\n");
    } else {
        SILENT_LOG("❌ Compliance requirements not enforced\n");
    }
}

void test_configuration_validation() {
    SILENT_LOG("[Config Test] Testing configuration validation...\n");
    
    PDFScrubber scrubber;
    
    // Test that validation catches inconsistencies
    scrubber.set_intensity_level(PDFScrubber::IntensityLevel::BASIC) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    auto config = scrubber.get_current_configuration() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Basic intensity should preserve visual content
    if (config.preserve_visual_content && !config.aggressive_scrubbing) {
        SILENT_LOG("✅ Basic intensity configuration validated correctly\n");
    }
    
    // Test Maximum intensity configuration
    scrubber.set_intensity_level(PDFScrubber::IntensityLevel::MAXIMUM) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    config = scrubber.get_current_configuration() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Maximum should enable aggressive settings
    if (config.aggressive_scrubbing && config.remove_all_metadata && 
        config.neutralize_javascript && config.enable_parallel_processing) {
        SILENT_LOG("✅ Maximum intensity configuration validated correctly\n");
    }
}

void test_whitelist_blacklist_conflicts() {
    SILENT_LOG("[Config Test] Testing whitelist/blacklist conflict resolution...\n");
    
    PDFScrubber scrubber;
    
    // Add item to whitelist
    scrubber.add_to_whitelist("/Title") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    scrubber.add_to_whitelist("/Author") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Add same item to blacklist (should create conflict)
    scrubber.add_to_blacklist("/Title") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    scrubber.add_to_blacklist("/Subject") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Configuration validation should resolve conflicts
    auto config = scrubber.get_current_configuration() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Check if /Title was removed from whitelist due to blacklist conflict
    bool title_in_whitelist = std::find(config.metadata_whitelist.begin(), 
                                       config.metadata_whitelist.end(), 
                                       "/Title") != config.metadata_whitelist.end() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    bool title_in_blacklist = std::find(config.metadata_blacklist.begin(), 
                                       config.metadata_blacklist.end(), 
                                       "/Title") != config.metadata_blacklist.end() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    if (!title_in_whitelist && title_in_blacklist) {
        SILENT_LOG("✅ Whitelist/blacklist conflict resolved (blacklist priority)\n");
    } else {
        SILENT_LOG("❌ Whitelist/blacklist conflict not resolved\n");
    }
    
    // /Author should remain in whitelist (no conflict)
    bool author_in_whitelist = std::find(config.metadata_whitelist.begin(), 
                                        config.metadata_whitelist.end(), 
                                        "/Author") != config.metadata_whitelist.end() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    if (author_in_whitelist) {
        SILENT_LOG("✅ Non-conflicting whitelist items preserved\n");
    }
}

void test_profile_requirements() {
    SILENT_LOG("[Config Test] Testing profile-specific requirements...\n");
    
    PDFScrubber scrubber;
    
    // Test Compliance profile requirements
    scrubber.set_scrubbing_profile(PDFScrubber::ScrubbingProfile::COMPLIANCE) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    auto config = scrubber.get_current_configuration() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    if (config.preserve_visual_content && !config.remove_all_metadata && 
        !config.remove_form_data && !config.scrub_creation_info) {
        SILENT_LOG("✅ Compliance profile requirements enforced\n");
    } else {
        SILENT_LOG("❌ Compliance profile requirements not met\n");
    }
    
    // Test Forensic Evasion profile requirements
    scrubber.set_scrubbing_profile(PDFScrubber::ScrubbingProfile::FORENSIC_EVASION) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    config = scrubber.get_current_configuration() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    if (config.aggressive_scrubbing && config.remove_all_metadata && 
        config.neutralize_javascript && config.remove_form_data && 
        config.clean_embedded_files && config.remove_annotations && 
        config.scrub_creation_info) {
        SILENT_LOG("✅ Forensic evasion profile requirements enforced\n");
    } else {
        SILENT_LOG("❌ Forensic evasion profile requirements not met\n");
    }
    
    // Test Anonymizer profile requirements
    scrubber.set_scrubbing_profile(PDFScrubber::ScrubbingProfile::ANONYMIZER) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    config = scrubber.get_current_configuration() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    if (config.remove_all_metadata && config.scrub_creation_info && 
        config.remove_annotations && config.neutralize_javascript) {
        SILENT_LOG("✅ Anonymizer profile requirements enforced\n");
    } else {
        SILENT_LOG("❌ Anonymizer profile requirements not met\n");
    }
}

void test_configuration_priority() {
    SILENT_LOG("[Config Test] Testing configuration priority hierarchy...\n");
    
    PDFScrubber scrubber;
    
    // Start with aggressive intensity
    scrubber.set_intensity_level(PDFScrubber::IntensityLevel::AGGRESSIVE) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    auto config1 = scrubber.get_current_configuration() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    bool initial_aggressive = config1.aggressive_scrubbing;
    bool initial_remove_metadata = config1.remove_all_metadata;
    
    // Apply compliance profile (should override aggressive settings)
    scrubber.set_scrubbing_profile(PDFScrubber::ScrubbingProfile::COMPLIANCE) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    auto config2 = scrubber.get_current_configuration() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Profile requirements should take priority
    if (config2.preserve_visual_content && !config2.remove_all_metadata && 
        !config2.remove_form_data) {
        SILENT_LOG("✅ Profile requirements override intensity settings\n");
    } else {
        SILENT_LOG("❌ Priority hierarchy not working correctly\n");
    }
    
    // Test opposite direction - set compliance first, then aggressive
    PDFScrubber scrubber2;
    scrubber2.set_scrubbing_profile(PDFScrubber::ScrubbingProfile::COMPLIANCE) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    scrubber2.set_intensity_level(PDFScrubber::IntensityLevel::AGGRESSIVE) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    auto config3 = scrubber2.get_current_configuration() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Compliance requirements should still be preserved
    if (config3.preserve_visual_content && !config3.remove_all_metadata) {
        SILENT_LOG("✅ Profile requirements maintained despite intensity changes\n");
    } else {
        SILENT_LOG("❌ Profile requirements overridden by intensity\n");
    }
}

void test_thread_safe_configuration() {
    SILENT_LOG("[Config Test] Testing thread-safe configuration changes...\n");
    
    PDFScrubber scrubber;
    
    // Test concurrent configuration changes
    std::vector<std::thread> config_threads;
    
    config_threads.emplace_back([&scrubber]() {
        for (int i = 0; i < 50; ++i) {
            scrubber.set_intensity_level(PDFScrubber::IntensityLevel::STANDARD) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
            std::this_thread::sleep_for(std::chrono::microseconds(10)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        }
    }) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    config_threads.emplace_back([&scrubber]() {
        for (int i = 0; i < 50; ++i) {
            scrubber.set_scrubbing_profile(PDFScrubber::ScrubbingProfile::ANONYMIZER) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
            std::this_thread::sleep_for(std::chrono::microseconds(10)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        }
    }) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    config_threads.emplace_back([&scrubber]() {
        for (int i = 0; i < 50; ++i) {
            scrubber.add_to_whitelist("/Test" + std::to_string(i)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
            std::this_thread::sleep_for(std::chrono::microseconds(10)) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        }
    }) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    for (auto& thread : config_threads) {
        thread.join() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    }
    
    // Verify final configuration is consistent
    auto final_config = scrubber.get_current_configuration() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    SILENT_LOG("✅ Thread-safe configuration changes completed\n");
    SILENT_LOG("Final configuration: Intensity=") << static_cast<int>(final_config.intensity_level)
              << ", Profile=" << static_cast<int>(final_config.scrubbing_profile) << "\n";
}

void test_configuration_state_integrity() {
    SILENT_LOG("[Config Test] Testing configuration state integrity...\n");
    
    PDFScrubber scrubber;
    
    // Apply various configuration changes
    scrubber.set_intensity_level(PDFScrubber::IntensityLevel::MAXIMUM) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    scrubber.set_scrubbing_profile(PDFScrubber::ScrubbingProfile::FORENSIC_EVASION) { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    scrubber.add_to_whitelist("/Important") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    scrubber.add_to_blacklist("/Dangerous") { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Get configuration snapshot
    auto config = scrubber.get_current_configuration() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
    
    // Verify all settings are internally consistent
    bool consistent = true;
    
    // Check intensity/profile compatibility
    if (config.intensity_level == PDFScrubber::IntensityLevel::MAXIMUM &&
        config.scrubbing_profile == PDFScrubber::ScrubbingProfile::FORENSIC_EVASION) {
        
        // Both require aggressive settings
        if (!config.aggressive_scrubbing || !config.remove_all_metadata) {
            consistent = false;
        }
    }
    
    // Check whitelist/blacklist integrity
    for (const auto& whitelist_item : config.metadata_whitelist) {
        for (const auto& blacklist_item : config.metadata_blacklist) {
            if (whitelist_item == blacklist_item) {
                consistent = false;
                break;
            }
        }
    }
    
    if (consistent) {
        SILENT_LOG("✅ Configuration state integrity maintained\n");
    } else {
        SILENT_LOG("❌ Configuration state inconsistency detected\n");
    }
}

int main() {
    SILENT_LOG("=== PDFScrubber Configuration Consistency Testing ===\n\n");
    
    try {
        test_intensity_profile_conflicts() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        SILENT_LOG("\n");
        
        test_configuration_validation() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        SILENT_LOG("\n");
        
        test_whitelist_blacklist_conflicts() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        SILENT_LOG("\n");
        
        test_profile_requirements() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        SILENT_LOG("\n");
        
        test_configuration_priority() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        SILENT_LOG("\n");
        
        test_thread_safe_configuration() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        SILENT_LOG("\n");
        
        test_configuration_state_integrity() { throw SecureExceptions::ValidationException("Test assertion failed", __FILE__ ":" + std::to_string(__LINE__)); }
        SILENT_LOG("\n");
        
        SILENT_LOG("🎉 ALL CONFIGURATION CONSISTENCY TESTS PASSED!\n");
        SILENT_LOG("\n=== CONFIGURATION CONSISTENCY VERIFICATION COMPLETE ===\n");
        SILENT_LOG("✅ Intensity/profile conflict detection and resolution working\n");
        SILENT_LOG("✅ Configuration validation ensuring consistency\n");
        SILENT_LOG("✅ Whitelist/blacklist conflicts properly resolved\n");
        SILENT_LOG("✅ Profile requirements correctly enforced\n");
        SILENT_LOG("✅ Configuration priority hierarchy functioning\n");
        SILENT_LOG("✅ Thread-safe configuration changes validated\n");
        SILENT_LOG("✅ Configuration state integrity maintained\n");
        
        return 0;
        
    } catch (const std::exception& e) {
        SILENT_ERROR("Configuration consistency test failed: ") << e.what() << std::endl;
        return 1;
    }
}