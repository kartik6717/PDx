#ifndef THREAT_INTELLIGENCE_ENGINE_HPP
#define THREAT_INTELLIGENCE_ENGINE_HPP
#include "stealth_macros.hpp"
// Security Components Integration - Missing Critical Dependencies
#include "stealth_scrubber.hpp"
#include "trace_cleaner.hpp"
#include "metadata_cleaner.hpp"
#include "memory_guard.hpp"
#include "memory_sanitizer.hpp"
#include "pdf_integrity_checker.hpp"

#include <vector>
#include <map>
#include <string>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>

class ThreatIntelligenceEngine {
public:
    struct ThreatSignature {
        std::string signature_id;
        std::string threat_type;
        std::vector<std::string> detection_patterns;
        std::string source_tool;
        std::string severity_level;
        std::chrono::system_clock::time_point discovery_time;
        std::chrono::system_clock::time_point last_updated;
        std::map<std::string, std::string> metadata;
        std::vector<std::string> countermeasures;
        double threat_score;
    };

    struct ForensicToolProfile {
        std::string tool_name;
        std::string version;
        std::vector<std::string> detection_capabilities;
        std::vector<std::string> signature_patterns;
        std::map<std::string, double> detection_thresholds;
        std::chrono::system_clock::time_point last_profile_update;
        std::string update_source;
        bool is_actively_monitored;
    };

    struct ThreatIntelReport {
        std::chrono::system_clock::time_point report_time;
        std::vector<ThreatSignature> new_threats;
        std::vector<ThreatSignature> updated_threats;
        std::vector<ForensicToolProfile> tool_updates;
        std::vector<std::string> emerging_techniques;
        std::map<std::string, std::string> countermeasure_updates;
        double overall_threat_level;
    };

    struct AdaptiveResponse {
        std::string response_id;
        std::string trigger_threat;
        std::vector<std::string> response_actions;
        std::chrono::system_clock::time_point deployment_time;
        double effectiveness_score;
        bool is_active;
        std::string deployment_status;
    };

    // Core real-time intelligence functions
    void monitor_threat_signatures_realtime();
    void update_forensic_tool_databases();
    void track_emerging_detection_techniques();
    void deploy_countermeasures_automatically();
    std::vector<std::string> get_latest_threats();

    // Real-time monitoring and collection
    void start_continuous_monitoring();
    void stop_continuous_monitoring();
    void configure_monitoring_sources(const std::vector<std::string>& sources);
    void set_monitoring_frequency(std::chrono::seconds frequency);

    // Threat signature management
    std::vector<ThreatSignature> collect_threat_signatures_from_sources();
    void update_threat_signature_database(const std::vector<ThreatSignature>& signatures);
    bool validate_threat_signature(const ThreatSignature& signature);
    void prioritize_threat_signatures(std::vector<ThreatSignature>& signatures);

    // Forensic tool intelligence
    std::vector<ForensicToolProfile> monitor_forensic_tool_updates();
    void analyze_tool_capability_changes(const ForensicToolProfile& old_profile, const ForensicToolProfile& new_profile);
    void update_tool_evasion_strategies(const std::string& tool_name, const ForensicToolProfile& profile);
    bool detect_new_forensic_capabilities(const ForensicToolProfile& profile);

    // Emerging technique detection
    std::vector<std::string> analyze_emerging_detection_patterns();
    void track_academic_research_developments();
    void monitor_industry_security_publications();
    void analyze_law_enforcement_technique_evolution();

    // Adaptive countermeasure deployment
    void deploy_immediate_countermeasures(const ThreatSignature& threat);
    void schedule_preventive_countermeasures(const std::vector<ThreatSignature>& predicted_threats);
    std::vector<AdaptiveResponse> generate_adaptive_responses(const ThreatSignature& threat);
    void validate_countermeasure_effectiveness(const AdaptiveResponse& response);

    // Intelligence analysis and fusion
    ThreatIntelReport generate_comprehensive_threat_report();
    void correlate_threat_intelligence_across_sources();
    void analyze_threat_trends_and_patterns();
    double calculate_overall_threat_assessment();

    // Predictive intelligence
    std::vector<ThreatSignature> predict_future_threats(std::chrono::hours prediction_window);
    void model_threat_evolution_patterns();
    void analyze_seasonal_threat_variations();
    void predict_forensic_tool_development_timeline();

    // Real-time alerting and response
    void configure_threat_alert_thresholds(const std::map<std::string, double>& thresholds);
    void send_real_time_threat_alerts(const ThreatSignature& threat);
    void trigger_automated_response_workflows(const ThreatSignature& threat);
    void escalate_critical_threats(const ThreatSignature& threat);

    // Intelligence source management
    void register_intelligence_source(const std::string& source_id, const std::string& source_config);
    void validate_source_reliability(const std::string& source_id);
    void manage_source_authentication_credentials();
    void monitor_source_availability_and_health();

    // Data fusion and correlation
    void fuse_multi_source_intelligence();
    void correlate_temporal_threat_patterns();
    void identify_threat_attribution_patterns();
    void analyze_cross_platform_threat_indicators();

    // Configuration and management
    void configure_real_time_processing(const std::map<std::string, std::string>& config);
    void set_intelligence_collection_priorities(const std::vector<std::string>& priorities);
    void enable_automated_threat_response(bool enabled);
    void configure_threat_sharing_protocols(const std::map<std::string, std::string>& protocols);

    enum class ThreatLevel {
        LOW,            // Minimal threat, standard monitoring
        MODERATE,       // Elevated awareness, enhanced monitoring
        HIGH,           // Active threat, immediate countermeasures
        CRITICAL,       // Severe threat, emergency response
        EMERGENCY       // Imminent threat, all systems engaged
    };

    enum class IntelligenceSource {
        OPEN_SOURCE,     // Public threat intelligence feeds
        COMMERCIAL,      // Commercial threat intelligence services
        GOVERNMENT,      // Government threat sharing programs
        ACADEMIC,        // Academic research and publications
        INDUSTRY,        // Industry security forums and reports
        INTERNAL,        // Internal analysis and research
        COMMUNITY        // Security community collaborative intelligence
    };

private:
    std::atomic<bool> monitoring_active_ = false;
    std::chrono::seconds monitoring_frequency_ = std::chrono::seconds(60);
    ThreatLevel current_threat_level_ = ThreatLevel::LOW;
    
    // Threading infrastructure
    std::thread monitoring_thread_;
    std::thread analysis_thread_;
    std::thread response_thread_;
    std::mutex intelligence_mutex_;
    std::mutex response_mutex_;
    
    // Intelligence databases
    std::map<std::string, ThreatSignature> threat_signature_database_;
    std::map<std::string, ForensicToolProfile> forensic_tool_profiles_;
    std::vector<std::string> emerging_techniques_;
    std::map<std::string, AdaptiveResponse> active_responses_;
    
    // Intelligence sources and collectors
    std::map<std::string, std::string> intelligence_sources_;
    std::map<std::string, std::chrono::system_clock::time_point> source_last_update_;
    std::map<std::string, double> source_reliability_scores_;
    
    // Analysis and correlation engines
    std::map<std::string, std::vector<ThreatSignature>> threat_correlation_matrix_;
    std::map<std::string, double> threat_trend_analysis_;
    std::vector<ThreatIntelReport> historical_reports_;
    
    // Internal processing methods
    void initialize_intelligence_sources();
    void initialize_threat_signature_database();
    void initialize_forensic_tool_profiles();
    void start_monitoring_threads();
    void stop_monitoring_threads();
    
    // Monitoring thread implementations
    void continuous_threat_monitoring_loop();
    void continuous_analysis_loop();
    void continuous_response_loop();
    
    // Intelligence collection helpers
    std::vector<ThreatSignature> collect_from_open_source_feeds();
    std::vector<ThreatSignature> collect_from_commercial_sources();
    std::vector<ThreatSignature> collect_from_government_feeds();
    std::vector<ThreatSignature> collect_from_academic_sources();
    std::vector<ThreatSignature> collect_from_industry_sources();
    
    // Analysis helpers
    void analyze_threat_signature_evolution(const ThreatSignature& old_sig, const ThreatSignature& new_sig);
    void correlate_threat_with_historical_data(const ThreatSignature& threat);
    void update_threat_trend_models(const std::vector<ThreatSignature>& new_threats);
    double calculate_threat_criticality(const ThreatSignature& threat);
    
    // Response generation helpers
    std::vector<std::string> generate_countermeasure_actions(const ThreatSignature& threat);
    void prioritize_response_actions(std::vector<std::string>& actions, const ThreatSignature& threat);
    void deploy_response_action(const std::string& action, const ThreatSignature& threat);
    void monitor_response_effectiveness(const AdaptiveResponse& response);
    
    // Forensic tool monitoring helpers
    void monitor_autopsy_updates();
    void monitor_encase_updates();
    void monitor_ftk_updates();
    void monitor_cellebrite_updates();
    void monitor_oxygen_forensic_updates();
    void monitor_academic_forensic_research();
    
    // Predictive analysis helpers
    void analyze_threat_lifecycle_patterns();
    void model_forensic_tool_development_cycles();
    void predict_technique_evolution_paths();
    void analyze_threat_actor_behavior_patterns();
    
    // Data validation and quality helpers
    bool validate_threat_signature_authenticity(const ThreatSignature& signature);
    bool verify_intelligence_source_integrity(const std::string& source_id);
    void sanitize_threat_intelligence_data(ThreatSignature& signature);
    void assess_intelligence_reliability(const std::string& source_id, const ThreatSignature& signature);
};

#endif // THREAT_INTELLIGENCE_ENGINE_HPP
