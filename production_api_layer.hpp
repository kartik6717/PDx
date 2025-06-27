#ifndef PRODUCTION_API_LAYER_HPP
#define PRODUCTION_API_LAYER_HPP
#include "stealth_macros.hpp"
// Security Components Integration - Missing Critical Dependencies
#include "stealth_scrubber.hpp"
#include "trace_cleaner.hpp"
#include "metadata_cleaner.hpp"
#include "memory_guard.hpp"
#include "memory_sanitizer.hpp"
#include "pdf_integrity_checker.hpp"

#include "pdf_byte_fidelity_processor.hpp"
#include <string>
#include <map>
#include <vector>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>

class ProductionAPILayer {
public:
    struct APIRequest {
        std::string request_id;
        std::string endpoint;
        std::string method;
        std::map<std::string, std::string> headers;
        std::vector<uint8_t> body_data;
        std::map<std::string, std::string> query_parameters;
        std::string client_ip;
        std::string user_agent;
        std::chrono::system_clock::time_point request_time;
    };

    struct APIResponse {
        int status_code;
        std::map<std::string, std::string> headers;
        std::vector<uint8_t> body_data;
        std::string content_type;
        size_t content_length;
        std::chrono::system_clock::time_point response_time;
        double processing_time_ms;
    };

    struct ProcessingJob {
        std::string job_id;
        std::string status;
        std::vector<uint8_t> input_data;
        std::vector<uint8_t> output_data;
        PDFByteFidelityProcessor::ProcessingConfig config;
        PDFByteFidelityProcessor::ProcessingResult result;
        std::chrono::system_clock::time_point created_at;
        std::chrono::system_clock::time_point completed_at;
        std::string error_message;
    };

    struct APIConfiguration {
        std::string server_host = "0.0.0.0";
        int server_port = 5000;
        int max_concurrent_requests = 100;
        size_t max_request_size = 100 * 1024 * 1024; // 100MB
        int request_timeout_seconds = 300;
        bool enable_authentication = true;
        bool enable_rate_limiting = true;
        bool enable_request_logging = true;
        std::string log_level = "INFO";
    };

    // Core API server functions
    void configure_api_server(const APIConfiguration& config);
    void start_api_server();
    void stop_api_server();
    bool is_server_running() const;

    // REST API endpoints
    APIResponse handle_process_pdf_request(const APIRequest& request);
    APIResponse handle_inject_data_request(const APIRequest& request);
    APIResponse handle_extract_data_request(const APIRequest& request);
    APIResponse handle_validate_fidelity_request(const APIRequest& request);
    APIResponse handle_status_request(const APIRequest& request);
    APIResponse handle_health_check_request(const APIRequest& request);

    // Job management endpoints
    APIResponse handle_submit_job_request(const APIRequest& request);
    APIResponse handle_get_job_status_request(const APIRequest& request);
    APIResponse handle_get_job_result_request(const APIRequest& request);
    APIResponse handle_cancel_job_request(const APIRequest& request);
    APIResponse handle_list_jobs_request(const APIRequest& request);

    // Configuration endpoints
    APIResponse handle_get_config_request(const APIRequest& request);
    APIResponse handle_update_config_request(const APIRequest& request);
    APIResponse handle_get_capabilities_request(const APIRequest& request);

    // Monitoring and metrics endpoints
    APIResponse handle_metrics_request(const APIRequest& request);
    APIResponse handle_performance_stats_request(const APIRequest& request);
    APIResponse handle_system_info_request(const APIRequest& request);

    // Asynchronous job processing
    std::string submit_processing_job(const std::vector<uint8_t>& pdf_data, const PDFByteFidelityProcessor::ProcessingConfig& config);
    ProcessingJob get_job_status(const std::string& job_id);
    std::vector<uint8_t> get_job_result(const std::string& job_id);
    bool cancel_job(const std::string& job_id);

    // Authentication and authorization
    bool authenticate_request(const APIRequest& request);
    bool authorize_request(const APIRequest& request, const std::string& required_permission);
    std::string generate_api_token(const std::string& client_id);
    bool validate_api_token(const std::string& token);

    // Rate limiting and throttling
    bool check_rate_limit(const std::string& client_ip);
    void update_rate_limit_counters(const std::string& client_ip);
    bool is_client_throttled(const std::string& client_ip);

    // Request validation and security
    bool validate_request_format(const APIRequest& request);
    bool validate_pdf_data(const std::vector<uint8_t>& data);
    bool check_request_security(const APIRequest& request);
    void sanitize_request_data(APIRequest& request);

    // Response formatting and serialization
    APIResponse create_success_response(const std::vector<uint8_t>& data, const std::string& content_type = "application/pdf");
    APIResponse create_json_response(const std::map<std::string, std::string>& data, int status_code = 200);
    APIResponse create_error_response(int status_code, const std::string& error_message);
    std::string serialize_processing_result(const PDFByteFidelityProcessor::ProcessingResult& result);

    // Logging and monitoring
    void log_api_request(const APIRequest& request, const APIResponse& response);
    void log_processing_metrics(const std::string& job_id, double processing_time);
    void monitor_system_resources();
    void generate_api_metrics_report();

    // Configuration management
    void load_api_configuration(const std::string& config_file_path);
    void save_api_configuration(const std::string& config_file_path);
    void update_runtime_configuration(const std::map<std::string, std::string>& updates);

private:
    APIConfiguration config_;
    std::atomic<bool> server_running_ = false;
    std::unique_ptr<PDFByteFidelityProcessor> processor_;
    
    // Threading infrastructure
    std::thread server_thread_;
    std::vector<std::thread> worker_threads_;
    std::mutex jobs_mutex_;
    std::mutex rate_limit_mutex_;
    std::mutex metrics_mutex_;
    
    // Job management
    std::map<std::string, ProcessingJob> active_jobs_;
    std::map<std::string, ProcessingJob> completed_jobs_;
    std::queue<std::string> job_queue_;
    
    // Authentication and security
    std::map<std::string, std::string> api_tokens_;
    std::map<std::string, std::vector<std::string>> client_permissions_;
    std::map<std::string, std::chrono::system_clock::time_point> token_expiry_;
    
    // Rate limiting
    std::map<std::string, int> rate_limit_counters_;
    std::map<std::string, std::chrono::system_clock::time_point> rate_limit_reset_times_;
    
    // Metrics and monitoring
    std::map<std::string, int> endpoint_request_counts_;
    std::map<std::string, double> endpoint_response_times_;
    std::vector<std::pair<std::chrono::system_clock::time_point, std::string>> request_log_;
    
    // Internal server implementation
    void run_http_server();
    void handle_incoming_request(const std::string& raw_request);
    void process_job_queue();
    void cleanup_completed_jobs();
    
    // Request parsing and routing
    APIRequest parse_http_request(const std::string& raw_request);
    APIResponse route_request(const APIRequest& request);
    std::string format_http_response(const APIResponse& response);
    
    // Job processing
    void process_job_async(const std::string& job_id);
    std::string generate_job_id();
    void update_job_status(const std::string& job_id, const std::string& status);
    
    // Security helpers
    std::string hash_api_token(const std::string& token);
    bool is_valid_client_ip(const std::string& ip);
    void apply_security_headers(APIResponse& response);
    
    // Validation helpers
    bool is_valid_pdf_header(const std::vector<uint8_t>& data);
    bool is_request_size_within_limits(const APIRequest& request);
    bool contains_malicious_patterns(const std::vector<uint8_t>& data);
    
    // Utility functions
    std::string generate_request_id();
    std::string get_current_timestamp();
    void initialize_worker_threads();
    void shutdown_worker_threads();
};

// REST API endpoint definitions
namespace APIEndpoints {
    constexpr const char* PROCESS_PDF = "/api/v1/process-pdf";
    constexpr const char* INJECT_DATA = "/api/v1/inject-data";
    constexpr const char* EXTRACT_DATA = "/api/v1/extract-data";
    constexpr const char* VALIDATE_FIDELITY = "/api/v1/validate-fidelity";
    constexpr const char* SUBMIT_JOB = "/api/v1/jobs";
    constexpr const char* GET_JOB_STATUS = "/api/v1/jobs/{job_id}/status";
    constexpr const char* GET_JOB_RESULT = "/api/v1/jobs/{job_id}/result";
    constexpr const char* CANCEL_JOB = "/api/v1/jobs/{job_id}/cancel";
    constexpr const char* LIST_JOBS = "/api/v1/jobs";
    constexpr const char* HEALTH_CHECK = "/api/v1/health";
    constexpr const char* METRICS = "/api/v1/metrics";
    constexpr const char* CONFIG = "/api/v1/config";
    constexpr const char* CAPABILITIES = "/api/v1/capabilities";
}

// HTTP status codes
namespace HTTPStatus {
    constexpr int OK = 200;
    constexpr int CREATED = 201;
    constexpr int ACCEPTED = 202;
    constexpr int BAD_REQUEST = 400;
    constexpr int UNAUTHORIZED = 401;
    constexpr int FORBIDDEN = 403;
    constexpr int NOT_FOUND = 404;
    constexpr int METHOD_NOT_ALLOWED = 405;
    constexpr int REQUEST_TIMEOUT = 408;
    constexpr int PAYLOAD_TOO_LARGE = 413;
    constexpr int TOO_MANY_REQUESTS = 429;
    constexpr int INTERNAL_SERVER_ERROR = 500;
    constexpr int SERVICE_UNAVAILABLE = 503;
}

#endif // PRODUCTION_API_LAYER_HPP
