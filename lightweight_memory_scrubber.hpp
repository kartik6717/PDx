#ifndef LIGHTWEIGHT_MEMORY_SCRUBBER_HPP
#define LIGHTWEIGHT_MEMORY_SCRUBBER_HPP

#include <vector>
#include <string>
#include <cstdint>
#include <atomic>

class LightweightMemoryScrubber {
public:
    static constexpr size_t SCRUB_BUFFER_SIZE = 4096;
    
    LightweightMemoryScrubber();
    ~LightweightMemoryScrubber();
    
    void activate_scrubbing();
    void deactivate_scrubbing();
    void scrub_memory_region(void* ptr, size_t size);
    void secure_scrub_vector(std::vector<uint8_t>& data);
    void secure_scrub_string(std::string& str);
    void emergency_scrub_all();
    bool is_scrubbing_active() const;
    void set_scrub_pattern(uint8_t pattern);
    size_t get_scrub_count() const;
    void reset_scrub_count();
    void perform_maintenance_scrub();
    
    static LightweightMemoryScrubber& getInstance();
    
private:
    bool is_active_;
    uint8_t scrub_pattern_;
    void* secure_buffer_;
    std::atomic<size_t> scrub_count_{0};
};

#endif // LIGHTWEIGHT_MEMORY_SCRUBBER_HPP