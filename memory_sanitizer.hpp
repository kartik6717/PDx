#ifndef MEMORY_SANITIZER_HPP
#define MEMORY_SANITIZER_HPP

#include <unordered_map>
#include <vector>
#include <string>
#include <cstdint>
#include <cstddef>
#include <chrono>
#include <atomic>

class MemorySanitizer {
public:
    static constexpr size_t WORKSPACE_SIZE = 8192;
    static constexpr int MAX_SANITIZATION_PASSES = 10;
    
    struct SanitizationRecord {
        void* ptr;
        size_t size;
        std::chrono::steady_clock::time_point timestamp;
        int passes_applied;
    };
    
    MemorySanitizer();
    ~MemorySanitizer();
    
    void activate_sanitization();
    void deactivate_sanitization();
    bool sanitize_memory_region(void* ptr, size_t size);
    bool sanitize_vector(std::vector<uint8_t>& data);
    bool sanitize_string(std::string& str);
    bool deep_sanitize_pdf_data(std::vector<uint8_t>& pdf_data);
    void emergency_sanitize_all();
    bool verify_sanitization_integrity();
    void set_sanitization_passes(int passes);
    int get_sanitization_passes() const;
    size_t get_total_sanitized_bytes() const;
    size_t get_deep_sanitization_count() const;
    bool is_sanitization_active() const;
    void reset_statistics();
    bool perform_maintenance_sanitization();
    
    static MemorySanitizer& getInstance();
    
private:
    bool is_active_;
    int sanitization_passes_;
    void* secure_workspace_;
    std::unordered_map<void*, SanitizationRecord> sanitization_history_;
    std::atomic<size_t> total_sanitized_bytes_{0};
    std::atomic<size_t> deep_sanitization_count_{0};
};

#endif // MEMORY_SANITIZER_HPP