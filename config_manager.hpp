#ifndef CONFIG_MANAGER_HPP
#define CONFIG_MANAGER_HPP
#include "stealth_macros.hpp"

#include <string>
#include <map>
#include <chrono>
#include <fstream>
#include <shared_mutex>
#include <iostream>
#include <stdexcept>

/**
 * Configuration Manager for PDF Forensic Validation System
 * Provides persistent configuration storage and validation
 */
class ConfigManager {
public:
    struct ValidationConfig {
        double validation_strictness = 0.8;
        bool enable_deep_analysis = true;
        bool enable_forensic_tool_testing = true;
        double statistical_threshold = 0.7;
        bool enable_timing_analysis = false;
        bool enable_steganographic_detection = false;
        bool enable_caching = true;
        int cache_max_size = 1000;
        double cache_ttl_hours = 24.0;

        // Performance settings
        int max_parallel_threads = 4;
        size_t max_pdf_size_mb = 100;
        double timeout_seconds = 30.0;

        // Reporting settings
        bool verbose_logging = false;
        bool save_detailed_reports = true;
        std::string report_output_dir = "./reports";

        // Security settings
        bool allow_javascript_analysis = true;
        bool allow_external_references = false;
        std::vector<std::string> trusted_domains;
    };

private:
    ValidationConfig config_;
    std::string config_file_path_;
    bool auto_save_;
    mutable std::shared_mutex config_mutex_;

public:
    ConfigManager(const std::string& config_file = "forensic_config.cfg", bool auto_save = true);

    // Configuration loading and saving
    bool load_config();
    bool save_config() const;
    void reset_to_defaults();

    // Configuration access
    const ValidationConfig& get_config() const { return config_; }
    ValidationConfig& get_mutable_config() { return config_; }

    // Individual setting access
    double get_validation_strictness() const { return config_.validation_strictness; }
    void set_validation_strictness(double value);

    bool get_enable_deep_analysis() const { return config_.enable_deep_analysis; }
    void set_enable_deep_analysis(bool enable);

    bool get_enable_forensic_tool_testing() const { return config_.enable_forensic_tool_testing; }
    void set_enable_forensic_tool_testing(bool enable);

    double get_statistical_threshold() const { return config_.statistical_threshold; }
    void set_statistical_threshold(double threshold);

    bool get_enable_caching() const { return config_.enable_caching; }
    void set_enable_caching(bool enable);

    int get_cache_max_size() const { return config_.cache_max_size; }
    void set_cache_max_size(int size);

    // Configuration validation
    bool validate_config() const;
    std::vector<std::string> get_validation_errors() const;
    bool validate_runtime_parameters() const;
    void apply_default_fallbacks();
    std::map<std::string, std::string> get_validation_report() const;

    // Configuration export/import
    bool export_config(const std::string& filename) const;
    bool import_config(const std::string& filename);

    // Profile management
    bool save_profile(const std::string& profile_name) const;
    bool load_profile(const std::string& profile_name);
    std::vector<std::string> list_profiles() const;
    bool delete_profile(const std::string& profile_name);

    // Preset configurations
    void load_high_security_preset();
    void load_performance_preset();
    void load_compatibility_preset();
    void load_development_preset();

private:
    std::string config_to_string() const;
    bool string_to_config(const std::string& config_str);
    bool validate_range(double value, double min, double max) const;
    bool validate_positive_int(int value) const;
    void ensure_directories_exist() const;
    std::string escape_string(const std::string& str) const;
    std::string unescape_string(const std::string& str) const;
};

#endif // CONFIG_MANAGER_HPP