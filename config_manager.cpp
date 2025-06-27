#include "secure_exceptions.hpp"
#include "stealth_macros.hpp"
#include "secure_memory.hpp"
#include "stealth_macros.hpp"
#include "config_manager.hpp"
#include "stealth_macros.hpp"
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <regex>
#include <iomanip>
#include "stealth_macros.hpp"
#include "stealth_macros.hpp"

ConfigManager::ConfigManager(const std::string& config_file, bool auto_save)
    : config_file_path_(config_file), auto_save_(auto_save) {

    // Try to load existing config, create default if it doesn't exist
    if (!load_config()) {
        reset_to_defaults();
        if (auto_save_) {
            save_config();
        }
    }
}

bool ConfigManager::load_config() {
    auto file = SecureExceptions::ExceptionHandler::safe_execute([std::ifstream file(]() { return std::ifstream(config_file_path_);
    if (!file.is_open()) {
        // Create default config if file doesn't exist
        create_default_config();
        return save_config();
    }

    try {
        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        // SECURITY FIX: Safe file close with error checking  
        if (file.is_open()) {
            try {
                file.close();
                if (file.fail() && !file.eof()) {
                    SecureExceptions::ExceptionHandler::handle_exception(
                        SecureExceptions::FileIOException("Failed to close config file properly", "read operation")
                    );
                }
            } catch (const std::exception& close_ex) {
                SecureExceptions::ExceptionHandler::handle_exception(
                    SecureExceptions::FileIOException("File close operation failed", close_ex.what())
                );
            }
        }

        return string_to_config(content);
    } catch (const std::exception& e) {
        // SECURITY FIX: Safe file close with error checking
        if (file.is_open()) {
            file.close();
            if (file.fail() && !file.eof()) {
                throw SecureExceptions::FileIOException("Failed to close config file properly", "exception handling");
            }
        }
        // Create default config on parse error
        create_default_config();
        return save_config();
    }
}

bool ConfigManager::save_config() const {
    ensure_directories_exist();

    std::ofstream file(config_file_path_);
    if (!file.is_open()) {
        throw SecureExceptions::SecurityViolationException("Cannot create config file: " + config_file_path_);
    }

    try {
        file << config_to_string();
        file.close();
        return file.good();
    } catch (const std::exception& e) {
        file.close();
        throw SecureExceptions::SecurityViolationException("Failed to write config file: " + std::string(e.what()));
    }

    file << config_to_string();
    file.close();

    return file.good();
}

void ConfigManager::reset_to_defaults() {
    config_ = ValidationConfig();
}

void ConfigManager::set_validation_strictness(double value) {
    if (validate_range(value, 0.0, 1.0)) {
        config_.validation_strictness = value;
        if (auto_save_) save_config();
    } else {
        throw SecureExceptions::InvalidInputException("Validation strictness must be between 0.0 and 1.0");
    }
}

void ConfigManager::set_enable_deep_analysis(bool enable) {
    config_.enable_deep_analysis = enable;
    if (auto_save_) save_config();
}

void ConfigManager::set_enable_forensic_tool_testing(bool enable) {
    config_.enable_forensic_tool_testing = enable;
    if (auto_save_) save_config();
}

void ConfigManager::set_statistical_threshold(double threshold) {
    if (validate_range(threshold, 0.0, 1.0)) {
        config_.statistical_threshold = threshold;
        if (auto_save_) save_config();
    } else {
        throw SecureExceptions::InvalidInputException("Statistical threshold must be between 0.0 and 1.0");
    }
}

void ConfigManager::set_enable_caching(bool enable) {
    config_.enable_caching = enable;
    if (auto_save_) save_config();
}

void ConfigManager::set_cache_max_size(int size) {
    if (validate_positive_int(size)) {
        config_.cache_max_size = size;
        if (auto_save_) save_config();
    } else {
        throw SecureExceptions::InvalidInputException("Cache max size must be positive");
    }
}

bool ConfigManager::validate_config() const {
    return get_validation_errors().empty();
}

std::vector<std::string> ConfigManager::get_validation_errors() const {
    std::vector<std::string> errors;

    if (!validate_range(config_.validation_strictness, 0.0, 1.0)) {
        errors.push_back("validation_strictness must be between 0.0 and 1.0");
    }

    if (!validate_range(config_.statistical_threshold, 0.0, 1.0)) {
        errors.push_back("statistical_threshold must be between 0.0 and 1.0");
    }

    if (!validate_positive_int(config_.cache_max_size)) {
        errors.push_back("cache_max_size must be positive");
    }

    if (!validate_positive_int(config_.max_parallel_threads)) {
        errors.push_back("max_parallel_threads must be positive");
    }

    if (config_.max_pdf_size_mb <= 0) {
        errors.push_back("max_pdf_size_mb must be positive");
    }

    if (config_.timeout_seconds <= 0) {
        errors.push_back("timeout_seconds must be positive");
    }

    if (config_.cache_ttl_hours <= 0) {
        errors.push_back("cache_ttl_hours must be positive");
    }

    return errors;
}

bool ConfigManager::export_config(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }

    file << "# Exported PDF Forensic Validation Configuration\n";
    file << "# Generated: " << std::time(nullptr) << "\n\n";
    file << config_to_string();
    file.close();

    return file.good();
}

bool ConfigManager::import_config(const std::string& filename) {
    auto file = SecureExceptions::ExceptionHandler::safe_execute([std::ifstream file(]() { return std::ifstream(filename);
    if (!file.is_open()) {
        throw SecureExceptions::SecurityViolationException("Cannot open config file for import: " + filename);
    }

    try {
        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        file.close();

        // Backup current config
        auto backup_config = config_;

        // Try to parse imported config
        if (string_to_config(content)) {
            return save_config();
        } else {
            // Restore backup on failure
            config_ = backup_config;
            throw SecureExceptions::SecurityViolationException("Invalid config format in imported file");
        }
    } catch (const std::exception& e) {
        file.close();
        throw SecureExceptions::SecurityViolationException("Failed to import config: " + std::string(e.what()));
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    file.close();

    ValidationConfig backup = config_;
    if (string_to_config(content) && validate_config()) {
        if (auto_save_) save_config();
        return true;
    } else {
        config_ = backup; // Restore on failure
        return false;
    }
}

bool ConfigManager::save_profile(const std::string& profile_name) const {
    std::string profile_path = "profiles/" + profile_name + ".cfg";
    return export_config(profile_path);
}

bool ConfigManager::load_profile(const std::string& profile_name) {
    std::string profile_path = "profiles/" + profile_name + ".cfg";
    return import_config(profile_path);
}

std::vector<std::string> ConfigManager::list_profiles() const {
    std::vector<std::string> profiles;

    try {
        if (std::filesystem::exists("profiles")) {
            for (const auto& entry : std::filesystem::directory_iterator("profiles")) {
                if (entry.is_regular_file() && entry.path().extension() == ".cfg") {
                    profiles.push_back(entry.path().stem().string());
                }
            }
        }
    } catch (const std::filesystem::filesystem_error&) {
        // Directory doesn't exist or access error
    }

    return profiles;
}

bool ConfigManager::delete_profile(const std::string& profile_name) {
    std::string profile_path = "profiles/" + profile_name + ".cfg";

    try {
        return std::filesystem::remove(profile_path);
    } catch (const std::filesystem::filesystem_error&) {
        return false;
    }
}

void ConfigManager::load_high_security_preset() {
    reset_to_defaults();
    config_.validation_strictness = 0.95;
    config_.enable_deep_analysis = true;
    config_.enable_forensic_tool_testing = true;
    config_.statistical_threshold = 0.9;
    config_.enable_timing_analysis = true;
    config_.enable_steganographic_detection = true;
    config_.allow_javascript_analysis = false;
    config_.allow_external_references = false;
    config_.timeout_seconds = 60.0;

    if (auto_save_) save_config();
}

void ConfigManager::load_performance_preset() {
    reset_to_defaults();
    config_.validation_strictness = 0.6;
    config_.enable_deep_analysis = false;
    config_.enable_forensic_tool_testing = false;
    config_.statistical_threshold = 0.5;
    config_.enable_timing_analysis = false;
    config_.enable_steganographic_detection = false;
    config_.enable_caching = true;
    config_.cache_max_size = 2000;
    config_.max_parallel_threads = 8;
    config_.timeout_seconds = 10.0;

    if (auto_save_) save_config();
}

void ConfigManager::load_compatibility_preset() {
    reset_to_defaults();
    config_.validation_strictness = 0.7;
    config_.enable_deep_analysis = true;
    config_.enable_forensic_tool_testing = true;
    config_.statistical_threshold = 0.6;
    config_.max_pdf_size_mb = 200;
    config_.timeout_seconds = 45.0;
    config_.allow_javascript_analysis = true;
    config_.allow_external_references = true;

    if (auto_save_) save_config();
}

void ConfigManager::load_development_preset() {
    reset_to_defaults();
    config_.verbose_logging = true;
    config_.save_detailed_reports = true;
    config_.enable_deep_analysis = true;
    config_.enable_forensic_tool_testing = true;
    config_.timeout_seconds = 120.0;
    config_.enable_caching = false; // For testing

    if (auto_save_) save_config();
}

std::string ConfigManager::config_to_string() const {
    std::stringstream ss;

    ss << "# PDF Forensic Validation Configuration\n\n";

    ss << "[Validation]\n";
    ss << "validation_strictness=" << config_.validation_strictness << "\n";
    ss << "enable_deep_analysis=" << (config_.enable_deep_analysis ? "true" : "false") << "\n";
    ss << "enable_forensic_tool_testing=" << (config_.enable_forensic_tool_testing ? "true" : "false") << "\n";
    ss << "statistical_threshold=" << config_.statistical_threshold << "\n";
    ss << "enable_timing_analysis=" << (config_.enable_timing_analysis ? "true" : "false") << "\n";
    ss << "enable_steganographic_detection=" << (config_.enable_steganographic_detection ? "true" : "false") << "\n\n";

    ss << "[Caching]\n";
    ss << "enable_caching=" << (config_.enable_caching ? "true" : "false") << "\n";
    ss << "cache_max_size=" << config_.cache_max_size << "\n";
    ss << "cache_ttl_hours=" << config_.cache_ttl_hours << "\n\n";

    ss << "[Performance]\n";
    ss << "max_parallel_threads=" << config_.max_parallel_threads << "\n";
    ss << "max_pdf_size_mb=" << config_.max_pdf_size_mb << "\n";
    ss << "timeout_seconds=" << config_.timeout_seconds << "\n\n";

    ss << "[Reporting]\n";
    ss << "verbose_logging=" << (config_.verbose_logging ? "true" : "false") << "\n";
    ss << "save_detailed_reports=" << (config_.save_detailed_reports ? "true" : "false") << "\n";
    ss << "report_output_dir=" << escape_string(config_.report_output_dir) << "\n\n";

    ss << "[Security]\n";
    ss << "allow_javascript_analysis=" << (config_.allow_javascript_analysis ? "true" : "false") << "\n";
    ss << "allow_external_references=" << (config_.allow_external_references ? "true" : "false") << "\n";
    ss << "trusted_domains=";
    for (size_t i = 0; i < config_.trusted_domains.size(); ++i) {
        if (i > 0) ss << ",";
        ss << escape_string(config_.trusted_domains[i]);
    }
    ss << "\n";

    return ss.str();
}

bool ConfigManager::string_to_config(const std::string& config_str) {
    std::istringstream stream(config_str);
    std::string line;
    std::string current_section;

    ValidationConfig new_config; // Work with temporary config

    while (std::getline(stream, line)) {
        // Remove comments and trim whitespace
        size_t comment_pos = line.find('#');
        if (comment_pos != std::string::npos) {
            line = line.substr(0, comment_pos);
        }

        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t") + 1);

        if (line.empty()) continue;

        // Check for section headers
        if (line.front() == '[' && line.back() == ']') {
            current_section = line.substr(1, line.length() - 2);
            continue;
        }

        // Parse key=value pairs
        size_t eq_pos = line.find('=');
        if (eq_pos == std::string::npos) continue;

        std::string key = line.substr(0, eq_pos);
        std::string value = line.substr(eq_pos + 1);

        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);

        // Parse values based on key
        try {
            if (key == "validation_strictness") {
                new_config.validation_strictness = std::stod(value);
            } else if (key == "enable_deep_analysis") {
                new_config.enable_deep_analysis = (value == "true");
            } else if (key == "enable_forensic_tool_testing") {
                new_config.enable_forensic_tool_testing = (value == "true");
            } else if (key == "statistical_threshold") {
                new_config.statistical_threshold = std::stod(value);
            } else if (key == "enable_timing_analysis") {
                new_config.enable_timing_analysis = (value == "true");
            } else if (key == "enable_steganographic_detection") {
                new_config.enable_steganographic_detection = (value == "true");
            } else if (key == "enable_caching") {
                new_config.enable_caching = (value == "true");
            } else if (key == "cache_max_size") {
                new_config.cache_max_size = std::stoi(value);
            } else if (key == "cache_ttl_hours") {
                new_config.cache_ttl_hours = std::stod(value);
            } else if (key == "max_parallel_threads") {
                new_config.max_parallel_threads = std::stoi(value);
            } else if (key == "max_pdf_size_mb") {
                new_config.max_pdf_size_mb = std::stoull(value);
            } else if (key == "timeout_seconds") {
                new_config.timeout_seconds = std::stod(value);
            } else if (key == "verbose_logging") {
                new_config.verbose_logging = (value == "true");
            } else if (key == "save_detailed_reports") {
                new_config.save_detailed_reports = (value == "true");
            } else if (key == "report_output_dir") {
                new_config.report_output_dir = unescape_string(value);
            } else if (key == "allow_javascript_analysis") {
                new_config.allow_javascript_analysis = (value == "true");
            } else if (key == "allow_external_references") {
                new_config.allow_external_references = (value == "true");
            } else if (key == "trusted_domains") {
                new_config.trusted_domains.clear();
                if (!value.empty()) {
                    std::stringstream domain_stream(value);
                    std::string domain;
                    while (std::getline(domain_stream, domain, ',')) {
                        domain.erase(0, domain.find_first_not_of(" \t"));
                        domain.erase(domain.find_last_not_of(" \t") + 1);
                        new_config.trusted_domains.push_back(unescape_string(domain));
                    }
                }
            }
        } catch (const std::exception&) {
            return false; // Invalid value format
        }
    }

    config_ = new_config;
    return true;
}

bool ConfigManager::validate_range(double value, double min, double max) const {
    return value >= min && value <= max;
}

bool ConfigManager::validate_positive_int(int value) const {
    return value > 0;
}

void ConfigManager::ensure_directories_exist() const {
    try {
        std::filesystem::path config_path(config_file_path_);
        if (config_path.has_parent_path()) {
            std::filesystem::create_directories(config_path.parent_path());
        }

        std::filesystem::create_directories("profiles");

        if (!config_.report_output_dir.empty()) {
            std::filesystem::create_directories(config_.report_output_dir);
        }
    } catch (const std::filesystem::filesystem_error&) {
        // Ignore directory creation errors
    }
}

std::string ConfigManager::escape_string(const std::string& str) const {
    std::string escaped;
    for (char c : str) {
        if (c == '\\' || c == '"' || c == '\n' || c == '\r' || c == '\t') {
            escaped += '\\';
            switch (c) {
                case '\\': escaped += '\\'; break;
                case '"': escaped += '"'; break;
                case '\n': escaped += 'n'; break;
                case '\r': escaped += 'r'; break;
                case '\t': escaped += 't'; break;
            }
        } else {
            escaped += c;
        }
    }
    return escaped;
}

std::string ConfigManager::unescape_string(const std::string& str) const {
    std::string unescaped;
    for (size_t i = 0; i < str.length(); ++i) {
        if (str[i] == '\\' && i + 1 < str.length()) {
            switch (str[i + 1]) {
                case '\\': unescaped += '\\'; break;
                case '"': unescaped += '"'; break;
                case 'n': unescaped += '\n'; break;
                case 'r': unescaped += '\r'; break;
                case 't': unescaped += '\t'; break;
                default: unescaped += str[i + 1]; break;
            }
            ++i; // Skip next character
        } else {
            unescaped += str[i];
        }
    }
    return unescaped;
}

void ConfigManager::set_config_value(const std::string& key, const std::string& value) {
    std::unique_lock<std::shared_mutex> lock(config_mutex_);

    config_values_[key] = value;

    // Mark as modified
    is_modified_ = true;
    last_modified_ = std::chrono::system_clock::now();
}

std::string ConfigManager::get_config_value(const std::string& key, const std::string& default_value) const {
    std::shared_lock<std::shared_mutex> lock(config_mutex_);

    auto it = config_values_.find(key);
    return (it != config_values_.end()) ? it->second : default_value;
}