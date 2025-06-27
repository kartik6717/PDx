#ifndef STRICT_TRACE_CLEANER_HPP
#define STRICT_TRACE_CLEANER_HPP

#include <vector>
#include <string>
#include <cstdint>
#include <cstddef>

class StrictTraceCleaner {
public:
    enum class CleaningLevel {
        STANDARD,
        ENHANCED,
        FORENSIC,
        MAXIMUM
    };
    
    enum class PatternType {
        METADATA,
        TIMESTAMP,
        FILESYSTEM,
        NETWORK,
        SYSTEM,
        HARDWARE,
        SOFTWARE
    };
    
    struct TracePattern {
        PatternType type;
        std::string regex_pattern;
        std::string replacement;
    };
    
    static constexpr size_t BUFFER_SIZE = 8192;
    
    StrictTraceCleaner();
    ~StrictTraceCleaner();
    
    void activate_strict_cleaning();
    void deactivate_strict_cleaning();
    bool clean_all_traces(std::vector<uint8_t>& pdf_data);
    bool remove_forensic_traces(std::vector<uint8_t>& data);
    bool eliminate_processing_artifacts(std::vector<uint8_t>& data);
    bool clean_temporal_traces(std::vector<uint8_t>& data);
    bool remove_system_traces(std::vector<uint8_t>& data);
    bool perform_deep_trace_cleaning(std::vector<uint8_t>& data);
    bool validate_trace_free_status(const std::vector<uint8_t>& data);
    std::vector<TracePattern> initialize_trace_patterns();
    bool apply_trace_pattern(std::vector<uint8_t>& data, const TracePattern& pattern);
    void secure_wipe_vector(std::vector<uint8_t>& data);
    void emergency_trace_cleanup();
    void set_cleaning_level(CleaningLevel level);
    CleaningLevel get_cleaning_level() const;
    size_t get_cleaning_operations_count() const;
    void reset_cleaning_operations_count();
    bool is_strict_cleaning_active() const;
    bool analyze_trace_vulnerabilities(const std::vector<uint8_t>& data);
    
    static StrictTraceCleaner& getInstance();
    
private:
    bool is_active_;
    CleaningLevel cleaning_level_;
    void* secure_buffer_;
    std::vector<TracePattern> trace_patterns_;
    size_t cleaning_operations_count_;
};

#endif // STRICT_TRACE_CLEANER_HPP