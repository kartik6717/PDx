#pragma once

#include "logger.hpp"
#include "config_system.hpp"
#include <string>
#include <map>
#include <vector>
#include <chrono>
#include <memory>
#include <atomic>
#include <mutex>
#include <thread>
#include <functional>

// Comprehensive monitoring and observability system for PDF scrubber
// Provides health checks, metrics collection, performance monitoring, and alerting

namespace Monitoring {

// Metric types for different kinds of measurements
enum class MetricType {
    COUNTER,        // Monotonically increasing values
    GAUGE,          // Current value that can go up or down
    HISTOGRAM,      // Distribution of values
    TIMER,          // Duration measurements
    RATE           // Rate of occurrence over time
};

// Health status levels
enum class HealthStatus {
    HEALTHY,
    DEGRADED,
    UNHEALTHY,
    CRITICAL
};

// Alert severity levels
enum class AlertSeverity {
    INFO,
    WARNING,
    CRITICAL,
    EMERGENCY
};

// Individual metric entry
struct Metric {
    std::string name;
    std::string description;
    MetricType type;
    double value;
    std::map<std::string, std::string> labels;
    std::chrono::system_clock::time_point timestamp;
    std::string unit;
};

// Health check result
struct HealthCheck {
    std::string component;
    std::string check_name;
    HealthStatus status;
    std::string message;
    std::chrono::milliseconds response_time;
    std::chrono::system_clock::time_point timestamp;
    std::map<std::string, std::string> details;
};

// Performance metrics aggregation
struct PerformanceMetrics {
    double cpu_usage_percent;
    double memory_usage_mb;
    double memory_peak_mb;
    double disk_usage_mb;
    size_t open_file_descriptors;
    size_t thread_count;
    double network_bytes_sent;
    double network_bytes_received;
    std::chrono::milliseconds uptime;
    double load_average_1min;
    double load_average_5min;
    double load_average_15min;
};

// Application-specific metrics
struct ApplicationMetrics {
    size_t pdfs_processed_total;
    size_t pdfs_processed_success;
    size_t pdfs_processed_failed;
    double average_processing_time_ms;
    double min_processing_time_ms;
    double max_processing_time_ms;
    size_t cache_hits;
    size_t cache_misses;
    double cache_hit_ratio;
    size_t security_events;
    size_t warnings_generated;
    size_t errors_generated;
    double throughput_pdfs_per_second;
};

// Alert definition
struct Alert {
    std::string id;
    std::string name;
    std::string description;
    AlertSeverity severity;
    std::string condition;
    std::chrono::seconds evaluation_interval;
    std::chrono::seconds for_duration;
    std::map<std::string, std::string> labels;
    std::vector<std::string> notification_channels;
    bool enabled;
};

// Alert event
struct AlertEvent {
    std::string alert_id;
    std::string alert_name;
    AlertSeverity severity;
    std::string message;
    std::chrono::system_clock::time_point triggered_at;
    std::chrono::system_clock::time_point resolved_at;
    bool active;
    std::map<std::string, std::string> context;
};

// Metrics collector interface
class MetricsCollector {
public:
    virtual ~MetricsCollector() = default;
    
    // Counter metrics
    virtual void increment_counter(const std::string& name, double value = 1.0, 
                                 const std::map<std::string, std::string>& labels = {}) = 0;
    virtual void set_counter(const std::string& name, double value, 
                           const std::map<std::string, std::string>& labels = {}) = 0;
    
    // Gauge metrics
    virtual void set_gauge(const std::string& name, double value, 
                         const std::map<std::string, std::string>& labels = {}) = 0;
    virtual void increment_gauge(const std::string& name, double delta = 1.0, 
                               const std::map<std::string, std::string>& labels = {}) = 0;
    virtual void decrement_gauge(const std::string& name, double delta = 1.0, 
                               const std::map<std::string, std::string>& labels = {}) = 0;
    
    // Histogram metrics
    virtual void observe_histogram(const std::string& name, double value, 
                                 const std::map<std::string, std::string>& labels = {}) = 0;
    
    // Timer metrics
    virtual void record_timer(const std::string& name, std::chrono::milliseconds duration, 
                            const std::map<std::string, std::string>& labels = {}) = 0;
    
    // Rate metrics
    virtual void record_rate(const std::string& name, double rate, 
                           const std::map<std::string, std::string>& labels = {}) = 0;
    
    // Get all metrics
    virtual std::vector<Metric> get_all_metrics() = 0;
    virtual std::string export_prometheus_format() = 0;
    virtual std::string export_json_format() = 0;
};

// In-memory metrics collector implementation
class InMemoryMetricsCollector : public MetricsCollector {
public:
    InMemoryMetricsCollector();
    ~InMemoryMetricsCollector();
    
    void increment_counter(const std::string& name, double value = 1.0, 
                         const std::map<std::string, std::string>& labels = {}) override;
    void set_counter(const std::string& name, double value, 
                   const std::map<std::string, std::string>& labels = {}) override;
    
    void set_gauge(const std::string& name, double value, 
                 const std::map<std::string, std::string>& labels = {}) override;
    void increment_gauge(const std::string& name, double delta = 1.0, 
                       const std::map<std::string, std::string>& labels = {}) override;
    void decrement_gauge(const std::string& name, double delta = 1.0, 
                       const std::map<std::string, std::string>& labels = {}) override;
    
    void observe_histogram(const std::string& name, double value, 
                         const std::map<std::string, std::string>& labels = {}) override;
    void record_timer(const std::string& name, std::chrono::milliseconds duration, 
                    const std::map<std::string, std::string>& labels = {}) override;
    void record_rate(const std::string& name, double rate, 
                   const std::map<std::string, std::string>& labels = {}) override;
    
    std::vector<Metric> get_all_metrics() override;
    std::string export_prometheus_format() override;
    std::string export_json_format() override;
    
    // Management
    void clear_metrics();
    void set_retention_period(std::chrono::hours period);

private:
    std::string generate_metric_key(const std::string& name, const std::map<std::string, std::string>& labels);
    void cleanup_old_metrics();
    
    mutable std::mutex metrics_mutex_;
    std::map<std::string, Metric> metrics_;
    std::chrono::hours retention_period_;
    std::thread cleanup_thread_;
    std::atomic<bool> cleanup_running_;
};

// Health check manager
class HealthCheckManager {
public:
    HealthCheckManager();
    ~HealthCheckManager();
    
    // Register health checks
    void register_check(const std::string& component, const std::string& check_name,
                       std::function<HealthCheck()> check_function,
                       std::chrono::seconds interval = std::chrono::seconds(30));
    
    // Execute health checks
    std::vector<HealthCheck> run_all_checks();
    HealthCheck run_check(const std::string& component, const std::string& check_name);
    
    // Overall health status
    HealthStatus get_overall_health();
    std::string get_health_summary();
    std::string get_health_json();
    
    // Enable/disable continuous monitoring
    void start_continuous_monitoring();
    void stop_continuous_monitoring();
    
    // Get check history
    std::vector<HealthCheck> get_check_history(const std::string& component = "", size_t limit = 100);

private:
    struct CheckDefinition {
        std::string component;
        std::string check_name;
        std::function<HealthCheck()> check_function;
        std::chrono::seconds interval;
        std::chrono::system_clock::time_point last_run;
    };
    
    void monitoring_thread();
    void run_scheduled_checks();
    
    mutable std::mutex checks_mutex_;
    std::map<std::string, CheckDefinition> registered_checks_;
    std::vector<HealthCheck> check_history_;
    
    std::thread monitoring_thread_;
    std::atomic<bool> monitoring_active_;
    std::chrono::seconds default_interval_;
};

// Performance monitor
class PerformanceMonitor {
public:
    PerformanceMonitor();
    ~PerformanceMonitor();
    
    // System metrics collection
    PerformanceMetrics collect_system_metrics();
    ApplicationMetrics collect_application_metrics();
    
    // Continuous monitoring
    void start_monitoring(std::chrono::seconds interval = std::chrono::seconds(60));
    void stop_monitoring();
    
    // Historical data
    std::vector<PerformanceMetrics> get_system_history(std::chrono::hours period = std::chrono::hours(24));
    std::vector<ApplicationMetrics> get_application_history(std::chrono::hours period = std::chrono::hours(24));
    
    // Thresholds and alerting
    void set_cpu_threshold(double threshold_percent);
    void set_memory_threshold(double threshold_mb);
    void set_disk_threshold(double threshold_mb);
    
    // Export capabilities
    std::string export_metrics_csv(std::chrono::hours period = std::chrono::hours(24));
    std::string export_metrics_json(std::chrono::hours period = std::chrono::hours(24));

private:
    void monitoring_loop();
    void collect_and_store_metrics();
    void check_thresholds(const PerformanceMetrics& metrics);
    
    double get_cpu_usage();
    double get_memory_usage();
    size_t get_file_descriptor_count();
    size_t get_thread_count();
    double get_load_average(int period); // 1, 5, or 15 minutes
    
    mutable std::mutex metrics_mutex_;
    std::vector<PerformanceMetrics> system_history_;
    std::vector<ApplicationMetrics> application_history_;
    
    std::thread monitoring_thread_;
    std::atomic<bool> monitoring_active_;
    std::chrono::seconds collection_interval_;
    
    // Thresholds
    double cpu_threshold_;
    double memory_threshold_;
    double disk_threshold_;
    
    std::chrono::system_clock::time_point start_time_;
};

// Alert manager
class AlertManager {
public:
    AlertManager();
    ~AlertManager();
    
    // Alert configuration
    void register_alert(const Alert& alert);
    void remove_alert(const std::string& alert_id);
    void enable_alert(const std::string& alert_id, bool enabled = true);
    
    // Alert evaluation
    void start_alert_evaluation();
    void stop_alert_evaluation();
    void evaluate_alerts();
    
    // Alert events
    std::vector<AlertEvent> get_active_alerts();
    std::vector<AlertEvent> get_alert_history(std::chrono::hours period = std::chrono::hours(24));
    void acknowledge_alert(const std::string& alert_id);
    void resolve_alert(const std::string& alert_id);
    
    // Notification channels
    void add_notification_channel(const std::string& name, const std::string& type, 
                                const std::map<std::string, std::string>& config);
    void send_notification(const AlertEvent& alert);

private:
    void evaluation_thread();
    bool evaluate_condition(const std::string& condition);
    void trigger_alert(const Alert& alert, const std::string& message);
    void send_webhook_notification(const AlertEvent& alert, const std::map<std::string, std::string>& config);
    void send_email_notification(const AlertEvent& alert, const std::map<std::string, std::string>& config);
    
    mutable std::mutex alerts_mutex_;
    std::map<std::string, Alert> registered_alerts_;
    std::map<std::string, AlertEvent> active_alerts_;
    std::vector<AlertEvent> alert_history_;
    
    std::thread evaluation_thread_;
    std::atomic<bool> evaluation_active_;
    std::chrono::seconds evaluation_interval_;
    
    std::map<std::string, std::map<std::string, std::string>> notification_channels_;
};

// Main monitoring coordinator
class MonitoringManager {
public:
    static MonitoringManager& getInstance();
    
    // Initialization
    void initialize(const std::string& service_name = "pdfscrubber");
    void configure_from_config();
    
    // Component access
    MetricsCollector& get_metrics_collector();
    HealthCheckManager& get_health_check_manager();
    PerformanceMonitor& get_performance_monitor();
    AlertManager& get_alert_manager();
    
    // Integrated operations
    void start_all_monitoring();
    void stop_all_monitoring();
    
    // HTTP endpoints for monitoring
    std::string handle_health_endpoint();
    std::string handle_metrics_endpoint();
    std::string handle_status_endpoint();
    
    // Dashboard data
    std::string get_dashboard_data();
    std::string get_real_time_metrics();
    
    // Default health checks
    void register_default_health_checks();
    void register_default_alerts();

private:
    MonitoringManager();
    ~MonitoringManager();
    
    // Disable copy/move
    MonitoringManager(const MonitoringManager&) = delete;
    MonitoringManager& operator=(const MonitoringManager&) = delete;
    
    HealthCheck check_system_health();
    HealthCheck check_memory_health();
    HealthCheck check_disk_health();
    HealthCheck check_configuration_health();
    HealthCheck check_logging_health();
    
    std::string service_name_;
    std::unique_ptr<InMemoryMetricsCollector> metrics_collector_;
    std::unique_ptr<HealthCheckManager> health_manager_;
    std::unique_ptr<PerformanceMonitor> performance_monitor_;
    std::unique_ptr<AlertManager> alert_manager_;
    
    mutable std::mutex manager_mutex_;
    bool initialized_;
};

// RAII performance timer for automatic metric recording
class PerformanceTimer {
public:
    PerformanceTimer(const std::string& metric_name, 
                    const std::map<std::string, std::string>& labels = {});
    ~PerformanceTimer();
    
    void add_label(const std::string& key, const std::string& value);
    void record_now();

private:
    std::string metric_name_;
    std::map<std::string, std::string> labels_;
    std::chrono::steady_clock::time_point start_time_;
    bool recorded_;
};

// Metrics helper macros
#define METRICS_COUNTER_INC(name) \
    MonitoringManager::getInstance().get_metrics_collector().increment_counter(name)

#define METRICS_COUNTER_INC_WITH_LABELS(name, labels) \
    MonitoringManager::getInstance().get_metrics_collector().increment_counter(name, 1.0, labels)

#define METRICS_GAUGE_SET(name, value) \
    MonitoringManager::getInstance().get_metrics_collector().set_gauge(name, value)

#define METRICS_TIMER(name) \
    PerformanceTimer _timer(name)

#define METRICS_TIMER_WITH_LABELS(name, labels) \
    PerformanceTimer _timer(name, labels)

#define METRICS_HISTOGRAM_OBSERVE(name, value) \
    MonitoringManager::getInstance().get_metrics_collector().observe_histogram(name, value)

// Health check helper macros
#define HEALTH_CHECK_REGISTER(component, name, function) \
    MonitoringManager::getInstance().get_health_check_manager().register_check(component, name, function)

// Alert helper macros
#define ALERT_REGISTER(alert_config) \
    MonitoringManager::getInstance().get_alert_manager().register_alert(alert_config)

// Utility functions
std::string to_string(HealthStatus status);
std::string to_string(AlertSeverity severity);
std::string to_string(MetricType type);

HealthStatus parse_health_status(const std::string& status_str);
AlertSeverity parse_alert_severity(const std::string& severity_str);

// Configuration helpers
void setup_default_monitoring_configuration();
void setup_production_monitoring();
void setup_development_monitoring();

} // namespace Monitoring
