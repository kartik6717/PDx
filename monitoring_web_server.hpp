#ifndef MONITORING_WEB_SERVER_HPP
#define MONITORING_WEB_SERVER_HPP

#include "stealth_macros.hpp"
#include "secure_memory.hpp"
#include "secure_exceptions.hpp"
#include <string>
#include <map>
#include <thread>
#include <atomic>
#include <mutex>

class MonitoringWebServer {
public:
    MonitoringWebServer();
    ~MonitoringWebServer();
    
    void start_server(int port = 8080);
    void stop_server();
    bool is_running() const;
    
    void add_metric(const std::string& name, const std::string& value);
    void update_status(const std::string& component, const std::string& status);
    
private:
    std::atomic<bool> server_running_;
    std::thread server_thread_;
    int port_;
    std::mutex metrics_mutex_;
    std::map<std::string, std::string> metrics_;
    std::map<std::string, std::string> component_status_;
    
    void server_loop();
    std::string generate_status_page();
    void handle_request(int client_socket);
    void eliminate_server_traces();
};

#endif // MONITORING_WEB_SERVER_HPP