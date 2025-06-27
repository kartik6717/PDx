#include "production_api_layer.hpp"
#include "stealth_macros.hpp"
#include "complete_silence_enforcer.hpp"
#include "secure_memory.hpp"
#include "secure_exceptions.hpp"
#include "memory_guard.hpp"
#include "memory_sanitizer.hpp"
#include "metadata_cleaner.hpp"
#include "stealth_scrubber.hpp"
#include "trace_cleaner.hpp"
#include "pdf_integrity_checker.hpp"
#include "security_validation.hpp"
#include "format_migration_manager.hpp"
#include "format_validation_engine.hpp"
#include "monitoring_web_server.hpp"
#include "final_security_implementations.hpp"
#include <iostream>
#include <sstream>
#include <fstream>
#include <regex>
#include <chrono>
#include <algorithm>
#include <random>

ProductionAPILayer::ProductionAPILayer() {
    processor_ = std::make_unique<PDFByteFidelityProcessor>();
}

void ProductionAPILayer::configure_api_server(const APIConfiguration& config) {
    // CRITICAL METHOD IMPLEMENTATION - Called by main.cpp
    config_ = config;
    
    // Initialize server configuration
    server_running_ = false;
    
    // Configure authentication if enabled
    if (config_.enable_authentication) {
        initialize_authentication_system();
    }
    
    // Configure rate limiting if enabled
    if (config_.enable_rate_limiting) {
        initialize_rate_limiting_system();
    }
    
    // Configure request logging if enabled
    if (config_.enable_request_logging) {
        initialize_request_logging_system();
    }
    
    // Initialize worker thread pool
    worker_pool_size_ = config_.max_concurrent_requests;
    initialize_worker_threads();
    
    // Configure security headers
    configure_security_headers();
    
    // Setup metrics collection
    initialize_metrics_collection();
    
    // STEALTH MODE: No console output for forensic invisibility
    // Server configuration completed silently
}

void ProductionAPILayer::start_api_server() {
    if (server_running_) {
        return;
    }
    
    server_running_ = true;
    server_thread_ = std::thread(&ProductionAPILayer::run_http_server, this);
    
    // STEALTH MODE: Server started silently for forensic invisibility
}

void ProductionAPILayer::stop_api_server() {
    server_running_ = false;
    
    if (server_thread_.joinable()) {
        server_thread_.join();
    }
    
    shutdown_worker_threads();
    // STEALTH MODE: Server stopped silently
}

ProductionAPILayer::APIResponse ProductionAPILayer::handle_process_pdf_request(const APIRequest& request) {
    try {
        // Validate request
        if (!validate_request_format(request)) {
            return create_error_response(HTTPStatus::BAD_REQUEST, "Invalid request format");
        }
        
        if (!validate_pdf_data(request.body_data)) {
            return create_error_response(HTTPStatus::BAD_REQUEST, "Invalid PDF data");
        }
        
        // Check authentication and authorization
        if (!authenticate_request(request)) {
            return create_error_response(HTTPStatus::UNAUTHORIZED, "Authentication required");
        }
        
        if (!authorize_request(request, "process_pdf")) {
            return create_error_response(HTTPStatus::FORBIDDEN, "Insufficient permissions");
        }
        
        // Check rate limiting
        if (!check_rate_limit(request.client_ip)) {
            return create_error_response(HTTPStatus::TOO_MANY_REQUESTS, "Rate limit exceeded");
        }
        
        // Process PDF with byte fidelity
        PDFByteFidelityProcessor::ProcessingConfig config;
        config.enable_format_preservation = true;
        config.enable_forensic_resistance_mode = true;
        config.injection_only_mode = true;
        config.strict_validation_mode = true;
        
        auto result = processor_->process_pdf_with_byte_fidelity(request.body_data);
        
        if (result.success) {
            // Update rate limiting
            update_rate_limit_counters(request.client_ip);
            
            // Log metrics
            log_processing_metrics("sync_process", result.processing_time_ms);
            
            return create_success_response(result.processed_data);
        } else {
            return create_error_response(HTTPStatus::INTERNAL_SERVER_ERROR, 
                "Processing failed: " + (result.processing_log.empty() ? "Unknown error" : result.processing_log.back()));
        }
        
    } catch (const std::exception& e) {
        return create_error_response(HTTPStatus::INTERNAL_SERVER_ERROR, 
            "Internal server error: " + std::string(e.what()));
    }
}

ProductionAPILayer::APIResponse ProductionAPILayer::handle_inject_data_request(const APIRequest& request) {
    try {
        // Parse multipart request to extract PDF and injection data
        auto pdf_data = request.body_data; // Simplified - assume body contains PDF
        // Parse injection data from request parameters
        std::vector<uint8_t> injection_data;
        
        // Extract injection data from request body or parameters
        if (request.parameters.find("injection_data") != request.parameters.end()) {
            std::string hex_data = request.parameters.at("injection_data");
            // Convert hex string to bytes
            for (size_t i = 0; i < hex_data.length(); i += 2) {
                if (i + 1 < hex_data.length()) {
                    std::string byte_str = hex_data.substr(i, 2);
                    uint8_t byte_val = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
                    injection_data.push_back(byte_val);
                }
            }
        } else {
            // Default secure injection pattern
            injection_data = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA}; 
        }
        
        if (pdf_data.empty() || injection_data.empty()) {
            return create_error_response(HTTPStatus::BAD_REQUEST, "Missing PDF or injection data");
        }
        
        // Validate authentication
        if (!authenticate_request(request)) {
            return create_error_response(HTTPStatus::UNAUTHORIZED, "Authentication required");
        }
        
        // Process injection with strict validation
        auto result = processor_->inject_invisible_data_with_fidelity(pdf_data, injection_data);
        
        if (result.success) {
            return create_success_response(result.processed_data);
        } else {
            return create_error_response(HTTPStatus::INTERNAL_SERVER_ERROR, "Injection failed");
        }
        
    } catch (const std::exception& e) {
        return create_error_response(HTTPStatus::INTERNAL_SERVER_ERROR, e.what());
    }
}

ProductionAPILayer::APIResponse ProductionAPILayer::handle_extract_data_request(const APIRequest& request) {
    try {
        if (!validate_pdf_data(request.body_data)) {
            return create_error_response(HTTPStatus::BAD_REQUEST, "Invalid PDF data");
        }
        
        if (!authenticate_request(request)) {
            return create_error_response(HTTPStatus::UNAUTHORIZED, "Authentication required");
        }
        
        // Extract invisible data
        auto extracted_data = processor_->extract_invisible_data_with_validation(request.body_data);
        
        if (!extracted_data.empty()) {
            return create_success_response(extracted_data, "application/octet-stream");
        } else {
            return create_error_response(HTTPStatus::NOT_FOUND, "No extractable data found");
        }
        
    } catch (const std::exception& e) {
        return create_error_response(HTTPStatus::INTERNAL_SERVER_ERROR, e.what());
    }
}

ProductionAPILayer::APIResponse ProductionAPILayer::handle_validate_fidelity_request(const APIRequest& request) {
    try {
        // Parse multipart request to get original and processed PDFs
        auto original_data = request.body_data; // Simplified - assume first half is original
        auto processed_data = request.body_data; // Simplified - assume second half is processed
        
        if (original_data.empty() || processed_data.empty()) {
            return create_error_response(HTTPStatus::BAD_REQUEST, "Missing original or processed PDF data");
        }
        
        if (!authenticate_request(request)) {
            return create_error_response(HTTPStatus::UNAUTHORIZED, "Authentication required");
        }
        
        // Perform comprehensive validation
        auto validation_result = processor_->perform_comprehensive_validation(original_data, processed_data);
        
        std::map<std::string, std::string> response_data;
        response_data["fidelity_preserved"] = validation_result.success ? "true" : "false";
        response_data["fidelity_score"] = std::to_string(validation_result.fidelity_score);
        response_data["authenticity_score"] = std::to_string(validation_result.authenticity_score);
        response_data["evasion_score"] = std::to_string(validation_result.evasion_score);
        
        return create_json_response(response_data);
        
    } catch (const std::exception& e) {
        return create_error_response(HTTPStatus::INTERNAL_SERVER_ERROR, e.what());
    }
}

ProductionAPILayer::APIResponse ProductionAPILayer::handle_submit_job_request(const APIRequest& request) {
    try {
        if (!authenticate_request(request)) {
            return create_error_response(HTTPStatus::UNAUTHORIZED, "Authentication required");
        }
        
        if (!authorize_request(request, "submit_job")) {
            return create_error_response(HTTPStatus::FORBIDDEN, "Insufficient permissions");
        }
        
        // Parse job configuration from request
        PDFByteFidelityProcessor::ProcessingConfig config;
        config.enable_format_preservation = true;
        config.enable_forensic_resistance_mode = true;
        config.injection_only_mode = true;
        
        // Submit asynchronous job
        std::string job_id = submit_processing_job(request.body_data, config);
        
        std::map<std::string, std::string> response_data;
        response_data["job_id"] = job_id;
        response_data["status"] = "submitted";
        response_data["estimated_completion"] = "5-10 minutes";
        
        return create_json_response(response_data, HTTPStatus::ACCEPTED);
        
    } catch (const std::exception& e) {
        return create_error_response(HTTPStatus::INTERNAL_SERVER_ERROR, e.what());
    }
}

ProductionAPILayer::APIResponse ProductionAPILayer::handle_get_job_status_request(const APIRequest& request) {
    try {
        // Extract job ID from URL path
        std::string job_id = request.query_parameters.find("job_id") != request.query_parameters.end() ? 
            request.query_parameters.at("job_id") : "";
        
        if (job_id.empty()) {
            return create_error_response(HTTPStatus::BAD_REQUEST, "Invalid job ID");
        }
        
        if (!authenticate_request(request)) {
            return create_error_response(HTTPStatus::UNAUTHORIZED, "Authentication required");
        }
        
        auto job = get_job_status(job_id);
        
        std::map<std::string, std::string> response_data;
        response_data["job_id"] = job.job_id;
        response_data["status"] = job.status;
        response_data["created_at"] = format_timestamp(job.created_at);
        
        if (job.status == "completed") {
            response_data["completed_at"] = format_timestamp(job.completed_at);
            response_data["result_available"] = "true";
        } else if (job.status == "failed") {
            response_data["error_message"] = job.error_message;
        }
        
        return create_json_response(response_data);
        
    } catch (const std::exception& e) {
        return create_error_response(HTTPStatus::INTERNAL_SERVER_ERROR, e.what());
    }
}

ProductionAPILayer::APIResponse ProductionAPILayer::handle_get_job_result_request(const APIRequest& request) {
    try {
        std::string job_id = extract_job_id_from_path(request.endpoint);
        
        if (!authenticate_request(request)) {
            return create_error_response(HTTPStatus::UNAUTHORIZED, "Authentication required");
        }
        
        auto job = get_job_status(job_id);
        
        if (job.status != "completed") {
            return create_error_response(HTTPStatus::NOT_FOUND, "Job not completed or does not exist");
        }
        
        return create_success_response(job.output_data);
        
    } catch (const std::exception& e) {
        return create_error_response(HTTPStatus::INTERNAL_SERVER_ERROR, e.what());
    }
}

ProductionAPILayer::APIResponse ProductionAPILayer::handle_health_check_request(const APIRequest& request) {
    std::map<std::string, std::string> health_data;
    health_data["status"] = "healthy";
    health_data["timestamp"] = get_current_timestamp();
    health_data["server_version"] = "1.0.0";
    health_data["active_jobs"] = std::to_string(active_jobs_.size());
    health_data["completed_jobs"] = std::to_string(completed_jobs_.size());
    
    return create_json_response(health_data);
}

ProductionAPILayer::APIResponse ProductionAPILayer::handle_metrics_request(const APIRequest& request) {
    if (!authenticate_request(request)) {
        return create_error_response(HTTPStatus::UNAUTHORIZED, "Authentication required");
    }
    
    if (!authorize_request(request, "view_metrics")) {
        return create_error_response(HTTPStatus::FORBIDDEN, "Insufficient permissions");
    }
    
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    
    std::map<std::string, std::string> metrics_data;
    
    // Request counts by endpoint
    for (const auto& endpoint_pair : endpoint_request_counts_) {
        metrics_data["requests_" + endpoint_pair.first] = std::to_string(endpoint_pair.second);
    }
    
    // Average response times
    for (const auto& timing_pair : endpoint_response_times_) {
        metrics_data["avg_response_time_" + timing_pair.first] = std::to_string(timing_pair.second) + "ms";
    }
    
    metrics_data["total_requests"] = std::to_string(
        std::accumulate(endpoint_request_counts_.begin(), endpoint_request_counts_.end(), 0,
            [](int sum, const auto& pair) { return sum + pair.second; })
    );
    
    return create_json_response(metrics_data);
}

std::string ProductionAPILayer::submit_processing_job(const std::vector<uint8_t>& pdf_data, const PDFByteFidelityProcessor::ProcessingConfig& config) {
    std::string job_id = generate_job_id();
    
    std::lock_guard<std::mutex> lock(jobs_mutex_);
    
    ProcessingJob job;
    job.job_id = job_id;
    job.status = "queued";
    job.input_data = pdf_data;
    job.config = config;
    job.created_at = std::chrono::system_clock::now();
    
    active_jobs_[job_id] = job;
    job_queue_.push(job_id);
    
    return job_id;
}

ProductionAPILayer::ProcessingJob ProductionAPILayer::get_job_status(const std::string& job_id) {
    std::lock_guard<std::mutex> lock(jobs_mutex_);
    
    auto active_it = active_jobs_.find(job_id);
    if (active_it != active_jobs_.end()) {
        return active_it->second;
    }
    
    auto completed_it = completed_jobs_.find(job_id);
    if (completed_it != completed_jobs_.end()) {
        return completed_it->second;
    }
    
    // Return empty job if not found
    ProcessingJob empty_job;
    empty_job.job_id = job_id;
    empty_job.status = "not_found";
    return empty_job;
}

bool ProductionAPILayer::authenticate_request(const APIRequest& request) {
    if (!config_.enable_authentication) {
        return true;
    }
    
    auto auth_header = request.headers.find("Authorization");
    if (auth_header == request.headers.end()) {
        return false;
    }
    
    std::string auth_value = auth_header->second;
    if (!auth_value.starts_with("Bearer ")) {
        return false;
    }
    
    std::string token = auth_value.substr(7); // Remove "Bearer " prefix
    return validate_api_token(token);
}

bool ProductionAPILayer::validate_api_token(const std::string& token) {
    std::lock_guard<std::mutex> lock(jobs_mutex_);
    
    auto token_it = api_tokens_.find(token);
    if (token_it == api_tokens_.end()) {
        return false;
    }
    
    // Check token expiry
    auto expiry_it = token_expiry_.find(token);
    if (expiry_it != token_expiry_.end()) {
        if (std::chrono::system_clock::now() > expiry_it->second) {
            // Token expired
            api_tokens_.erase(token_it);
            token_expiry_.erase(expiry_it);
            return false;
        }
    }
    
    return true;
}

bool ProductionAPILayer::check_rate_limit(const std::string& client_ip) {
    if (!config_.enable_rate_limiting) {
        return true;
    }
    
    std::lock_guard<std::mutex> lock(rate_limit_mutex_);
    
    auto now = std::chrono::system_clock::now();
    auto& counter = rate_limit_counters_[client_ip];
    auto& reset_time = rate_limit_reset_times_[client_ip];
    
    // Reset counter if time window has passed
    if (now > reset_time) {
        counter = 0;
        reset_time = now + std::chrono::hours(1); // 1-hour window
    }
    
    const int MAX_REQUESTS_PER_HOUR = 100;
    return counter < MAX_REQUESTS_PER_HOUR;
}

void ProductionAPILayer::update_rate_limit_counters(const std::string& client_ip) {
    std::lock_guard<std::mutex> lock(rate_limit_mutex_);
    rate_limit_counters_[client_ip]++;
}

bool ProductionAPILayer::validate_pdf_data(const std::vector<uint8_t>& data) {
    if (data.size() < 8) {
        return false;
    }
    
    // Check PDF header
    std::string header(data.begin(), data.begin() + 8);
    return header.starts_with("%PDF-");
}

ProductionAPILayer::APIResponse ProductionAPILayer::create_success_response(const std::vector<uint8_t>& data, const std::string& content_type) {
    APIResponse response;
    response.status_code = HTTPStatus::OK;
    response.body_data = data;
    response.content_type = content_type;
    response.content_length = data.size();
    response.response_time = std::chrono::system_clock::now();
    
    // Add security headers
    apply_security_headers(response);
    
    return response;
}

ProductionAPILayer::APIResponse ProductionAPILayer::create_json_response(const std::map<std::string, std::string>& data, int status_code) {
    APIResponse response;
    response.status_code = status_code;
    response.content_type = "application/json";
    
    // Convert map to JSON string
    std::ostringstream json_stream;
    json_stream << "{";
    bool first = true;
    for (const auto& pair : data) {
        if (!first) json_stream << ",";
        json_stream << "\"" << pair.first << "\":\"" << pair.second << "\"";
        first = false;
    }
    json_stream << "}";
    
    std::string json_string = json_stream.str();
    response.body_data.assign(json_string.begin(), json_string.end());
    response.content_length = response.body_data.size();
    response.response_time = std::chrono::system_clock::now();
    
    apply_security_headers(response);
    
    return response;
}

ProductionAPILayer::APIResponse ProductionAPILayer::create_error_response(int status_code, const std::string& error_message) {
    std::map<std::string, std::string> error_data;
    error_data["error"] = error_message;
    error_data["timestamp"] = get_current_timestamp();
    
    auto response = create_json_response(error_data, status_code);
    return response;
}

void ProductionAPILayer::run_http_server() {
    // Simplified HTTP server implementation
    // In production, this would use a proper HTTP library like crow, beast, or similar
    
    while (server_running_) {
        try {
            // Simulate receiving HTTP requests
            // In real implementation, this would bind to a socket and listen for connections
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            
            // Process job queue
            process_job_queue();
            
            // Cleanup completed jobs periodically
            cleanup_completed_jobs();
            
        } catch (const std::exception& e) {
            // Complete silence - handle server errors internally only
            SilentErrorHandler::log_internal_error("HTTP_SERVER_ERROR", e.what(), 
                                                 SilentErrorHandler::ErrorSeverity::CRITICAL);
        }
    }
}

void ProductionAPILayer::process_job_queue() {
    std::lock_guard<std::mutex> lock(jobs_mutex_);
    
    while (!job_queue_.empty()) {
        std::string job_id = job_queue_.front();
        job_queue_.pop();
        
        // Process job asynchronously
        std::thread(&ProductionAPILayer::process_job_async, this, job_id).detach();
    }
}

void ProductionAPILayer::process_job_async(const std::string& job_id) {
    try {
        std::lock_guard<std::mutex> lock(jobs_mutex_);
        
        auto job_it = active_jobs_.find(job_id);
        if (job_it == active_jobs_.end()) {
            return;
        }
        
        ProcessingJob& job = job_it->second;
        job.status = "processing";
        
        // Unlock while processing
        lock.~lock_guard();
        
        // Process the PDF
        auto result = processor_->process_pdf_with_byte_fidelity(job.input_data);
        
        // Re-acquire lock to update job
        std::lock_guard<std::mutex> lock2(jobs_mutex_);
        
        if (result.success) {
            job.status = "completed";
            job.output_data = result.processed_data;
            job.result = result;
        } else {
            job.status = "failed";
            job.error_message = result.processing_log.empty() ? "Unknown error" : result.processing_log.back();
        }
        
        job.completed_at = std::chrono::system_clock::now();
        
        // Move to completed jobs
        completed_jobs_[job_id] = job;
        active_jobs_.erase(job_it);
        
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(jobs_mutex_);
        
        auto job_it = active_jobs_.find(job_id);
        if (job_it != active_jobs_.end()) {
            job_it->second.status = "failed";
            job_it->second.error_message = e.what();
            job_it->second.completed_at = std::chrono::system_clock::now();
            
            completed_jobs_[job_id] = job_it->second;
            active_jobs_.erase(job_it);
        }
    }
}

std::string ProductionAPILayer::generate_job_id() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    ss << "job_";
    for (int i = 0; i < 16; ++i) {
        ss << std::hex << dis(gen);
    }
    
    return ss.str();
}

std::string ProductionAPILayer::get_current_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%dT%H:%M:%S");
    return ss.str();
}

void ProductionAPILayer::apply_security_headers(APIResponse& response) {
    response.headers["X-Content-Type-Options"] = "nosniff";
    response.headers["X-Frame-Options"] = "DENY";
    response.headers["X-XSS-Protection"] = "1; mode=block";
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
    response.headers["Content-Security-Policy"] = "default-src 'self'";
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
}

void ProductionAPILayer::initialize_worker_threads() {
    size_t thread_count = std::thread::hardware_concurrency();
    worker_threads_.reserve(thread_count);
    
    for (size_t i = 0; i < thread_count; ++i) {
        worker_threads_.emplace_back([this]() {
            while (server_running_) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                // Worker thread processing loop
            }
        });
    }
}

void ProductionAPILayer::shutdown_worker_threads() {
    for (auto& thread : worker_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    worker_threads_.clear();
}