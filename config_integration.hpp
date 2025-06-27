#pragma once

#include "config_system.hpp"
#include "logger.hpp"
#include "pdf_parser.hpp"
#include "entropy_shaper.hpp"

// Configuration integration for all PDF scrubber components
// This header provides easy integration between the configuration system
// and all other components in the PDF scrubber

namespace ConfigIntegration {

// PDF Parser configuration integration
class PDFParserConfigAdapter {
public:
    static PDFParserConfig create_from_configuration();
    static void update_from_configuration(PDFParserConfig& config);
    static void apply_to_configuration(const PDFParserConfig& config);
    
    static void setup_configuration_callbacks();
    
private:
    static void on_parser_config_change(const std::string& key, const ConfigValue& old_value, const ConfigValue& new_value);
};

// Logger configuration integration
class LoggerConfigAdapter {
public:
    static void configure_logger_from_config();
    static void setup_sinks_from_configuration();
    static void update_log_levels_from_configuration();
    
    static void setup_configuration_callbacks();
    
private:
    static void on_logging_config_change(const std::string& key, const ConfigValue& old_value, const ConfigValue& new_value);
    static LogLevel parse_log_level(const std::string& level_str);
    static std::shared_ptr<LogSink> create_file_sink();
    static std::shared_ptr<LogSink> create_console_sink();
    static std::shared_ptr<LogSink> create_syslog_sink();
    static std::shared_ptr<LogSink> create_network_sink();
};

// Performance configuration integration
class PerformanceConfigAdapter {
public:
    struct PerformanceSettings {
        bool parallel_processing_enabled;
        int max_threads;
        int thread_pool_size;
        bool optimization_enabled;
        size_t memory_pool_size;
        std::string cache_strategy;
    };
    
    static PerformanceSettings get_performance_settings();
    static void apply_performance_settings(const PerformanceSettings& settings);
    static void setup_configuration_callbacks();
    
private:
    static void on_performance_config_change(const std::string& key, const ConfigValue& old_value, const ConfigValue& new_value);
};

// Security configuration integration
class SecurityConfigAdapter {
public:
    struct SecuritySettings {
        bool sandbox_enabled;
        bool file_access_restricted;
        bool network_denied;
        size_t memory_limit_mb;
        int cpu_limit_percent;
        int max_open_files;
        bool audit_logging_enabled;
    };
    
    static SecuritySettings get_security_settings();
    static void apply_security_settings(const SecuritySettings& settings);
    static void setup_configuration_callbacks();
    
private:
    static void on_security_config_change(const std::string& key, const ConfigValue& old_value, const ConfigValue& new_value);
    static void configure_sandbox();
    static void configure_resource_limits();
    static void configure_file_restrictions();
};

// Runtime configuration manager that coordinates all adapters
class RuntimeConfigManager {
public:
    static RuntimeConfigManager& getInstance();
    
    // Initialize all configuration adapters
    void initialize(const std::string& config_file = "", Environment env = Environment::PRODUCTION);
    
    // Hot reload configuration
    void reload_configuration();
    
    // Apply environment-specific overrides
    void apply_environment_overrides(Environment env);
    
    // Configuration validation
    bool validate_runtime_configuration();
    std::vector<std::string> get_configuration_issues();
    
    // Configuration monitoring
    void start_configuration_monitoring();
    void stop_configuration_monitoring();
    
    // Emergency configuration reset
    void reset_to_safe_defaults();
    
    // Configuration backup and restore
    void backup_configuration(const std::string& backup_path);
    void restore_configuration(const std::string& backup_path);
    
    // Dynamic configuration updates
    void update_parser_limits(int max_file_size, int max_objects);
    void update_logging_level(const std::string& level);
    void update_security_settings(bool sandbox, bool network_deny);
    void update_performance_settings(int max_threads, bool parallel);
    
    // Configuration statistics
    struct ConfigStats {
        size_t total_parameters;
        size_t overridden_parameters;
        size_t validated_parameters;
        size_t hot_reloaded_count;
        std::chrono::system_clock::time_point last_update;
        std::vector<std::string> recent_changes;
    };
    
    ConfigStats get_statistics() const;

private:
    RuntimeConfigManager();
    ~RuntimeConfigManager();
    
    // Disable copy/move
    RuntimeConfigManager(const RuntimeConfigManager&) = delete;
    RuntimeConfigManager& operator=(const RuntimeConfigManager&) = delete;
    
    void setup_all_callbacks();
    void validate_critical_settings();
    void apply_emergency_limits();
    
    bool monitoring_active_;
    std::thread monitoring_thread_;
    std::atomic<bool> shutdown_requested_;
    
    mutable std::mutex stats_mutex_;
    ConfigStats stats_;
};

// Configuration-aware component base class
template<typename T>
class ConfigurableComponent {
public:
    ConfigurableComponent() {
        // Register for configuration updates
        auto& config_manager = ConfigurationManager::getInstance();
        config_manager.register_global_change_callback(
            [this](const std::string& key, const ConfigValue& old_val, const ConfigValue& new_val) {
                this->on_configuration_changed(key, old_val, new_val);
            });
    }
    
    virtual ~ConfigurableComponent() = default;
    
protected:
    // Override this method to handle configuration changes
    virtual void on_configuration_changed(const std::string& key, const ConfigValue& old_value, const ConfigValue& new_value) {
        // Default implementation does nothing
    }
    
    // Helper methods for configuration access
    template<typename ValueType>
    ValueType get_config(const std::string& key, const ValueType& default_value) const {
        return ConfigurationManager::getInstance().get<ValueType>(key, default_value);
    }
    
    void set_config(const std::string& key, const ConfigValue& value) {
        ConfigurationManager::getInstance().set(key, value, ConfigSource::RUNTIME, typeid(T).name());
    }
};

// Macros for easy configuration integration
#define DECLARE_CONFIGURABLE(ClassName) \
    class ClassName : public ConfigurableComponent<ClassName>

#define IMPLEMENT_CONFIG_CALLBACK(ClassName) \
    void ClassName::on_configuration_changed(const std::string& key, const ConfigValue& old_value, const ConfigValue& new_value)

#define CONFIG_CHANGE_HANDLER(key_pattern) \
    if (key.find(key_pattern) != std::string::npos)

#define GET_CONFIG_VALUE(key, type, default_val) \
    ConfigurationManager::getInstance().get<type>(key, default_val)

#define SET_CONFIG_VALUE(key, value) \
    ConfigurationManager::getInstance().set(key, value, ConfigSource::RUNTIME, __FUNCTION__)

// Configuration validation helpers
namespace ConfigValidation {
    bool validate_parser_configuration();
    bool validate_logging_configuration();
    bool validate_security_configuration();
    bool validate_performance_configuration();
    bool validate_network_configuration();
    bool validate_forensic_configuration();
    
    std::vector<std::string> get_all_validation_errors();
    void log_validation_results();
}

// Configuration migration helpers
namespace ConfigMigration {
    bool migrate_configuration_format(const std::string& old_file, const std::string& new_file);
    bool upgrade_configuration_version(const std::string& config_file, const std::string& from_version, const std::string& to_version);
    void backup_configuration_before_migration(const std::string& config_file);
}

} // namespace ConfigIntegration
