#include "monitoring_web_server.hpp"
#include "stealth_macros.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <iostream>

MonitoringWebServer::MonitoringWebServer() : server_running_(false), port_(8080) {
    ENFORCE_COMPLETE_SILENCE();
}

MonitoringWebServer::~MonitoringWebServer() {
    ENFORCE_COMPLETE_SILENCE();
    stop_server();
    eliminate_server_traces();
}

void MonitoringWebServer::start_server(int port) {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    try {
        port_ = port;
        server_running_ = true;
        server_thread_ = std::thread(&MonitoringWebServer::server_loop, this);
        
        // Initialize basic metrics
        add_metric("server_status", "running");
        add_metric("start_time", std::to_string(std::time(nullptr)));
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

void MonitoringWebServer::stop_server() {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        server_running_ = false;
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
        
        eliminate_server_traces();
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

bool MonitoringWebServer::is_running() const {
    return server_running_;
}

void MonitoringWebServer::add_metric(const std::string& name, const std::string& value) {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        metrics_[name] = value;
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

void MonitoringWebServer::update_status(const std::string& component, const std::string& status) {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        component_status_[component] = status;
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

void MonitoringWebServer::server_loop() {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    try {
        SecureMemory server_buffer(4096);
        
        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd == -1) {
            return;
        }
        
        struct sockaddr_in address;
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port_);
        
        int opt = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
            close(server_fd);
            return;
        }
        
        if (listen(server_fd, 3) < 0) {
            close(server_fd);
            return;
        }
        
        while (server_running_) {
            struct sockaddr_in client_address;
            socklen_t client_len = sizeof(client_address);
            
            int client_socket = accept(server_fd, (struct sockaddr*)&client_address, &client_len);
            if (client_socket >= 0) {
                handle_request(client_socket);
                close(client_socket);
            }
        }
        
        close(server_fd);
        eliminate_server_traces();
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

std::string MonitoringWebServer::generate_status_page() {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        
        std::ostringstream html;
        html << "HTTP/1.1 200 OK\r\n";
        html << "Content-Type: text/html\r\n";
        html << "Connection: close\r\n";
        html << "\r\n";
        html << "<!DOCTYPE html><html><head><title>PDF Processor Status</title></head><body>";
        html << "<h1>PDF Processing System Status</h1>";
        
        html << "<h2>System Metrics</h2><ul>";
        for (const auto& [key, value] : metrics_) {
            html << "<li><strong>" << key << ":</strong> " << value << "</li>";
        }
        html << "</ul>";
        
        html << "<h2>Component Status</h2><ul>";
        for (const auto& [component, status] : component_status_) {
            html << "<li><strong>" << component << ":</strong> " << status << "</li>";
        }
        html << "</ul>";
        
        html << "</body></html>";
        
        return html.str();
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
        return "HTTP/1.1 500 Internal Server Error\r\n\r\nError";
    }
}

void MonitoringWebServer::handle_request(int client_socket) {
    ENFORCE_COMPLETE_SILENCE();
    
    try {
        SecureMemory request_buffer(1024);
        char* buffer = static_cast<char*>(request_buffer.get_buffer());
        
        recv(client_socket, buffer, 1023, 0);
        
        std::string response = generate_status_page();
        send(client_socket, response.c_str(), response.length(), 0);
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}

void MonitoringWebServer::eliminate_server_traces() {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    try {
        SecureMemory cleanup_buffer(512);
        
        // Clear all metrics and status data
        {
            std::lock_guard<std::mutex> lock(metrics_mutex_);
            metrics_.clear();
            component_status_.clear();
        }
        
        // Zero out any cached data
        cleanup_buffer.secure_zero();
        
    } catch (const std::exception& e) {
        SecureException::handle_silent_exception(e);
    }
}