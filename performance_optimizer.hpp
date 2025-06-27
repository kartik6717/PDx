#ifndef PERFORMANCE_OPTIMIZER_HPP
#define PERFORMANCE_OPTIMIZER_HPP
#include "stealth_macros.hpp"

#include <vector>
#include <map>
#include <string>
#include <memory>
#include <thread>
#include <mutex>
#include <future>

class PerformanceOptimizer {
public:
    struct PerformanceMetrics {
        size_t file_size;
        double processing_time_seconds;
        size_t memory_usage_bytes;
        size_t peak_memory_usage;
        double throughput_mbps;
        size_t cpu_cycles_used;
        size_t cache_hits;
        size_t cache_misses;
        double compression_ratio;
        size_t io_operations;
    };

    struct OptimizationProfile {
        std::string profile_name;
        size_t chunk_size;
        size_t thread_count;
        size_t memory_limit;
        bool enable_streaming;
        bool enable_parallel_processing;
        bool enable_memory_mapping;
        bool enable_compression_optimization;
        double quality_vs_speed_ratio;
    };

    struct LargePDFHandlingConfig {
        size_t max_memory_usage;
        size_t streaming_buffer_size;
        size_t parallel_chunk_size;
        bool enable_progressive_processing;
        bool enable_memory_mapped_io;
        bool enable_disk_based_operations;
        size_t temp_file_threshold;
    };

    // Core performance optimization
    void optimize_for_large_pdfs(std::vector<uint8_t>& pdf_data);
    void configure_memory_efficient_processing(size_t max_memory_mb);
    void enable_streaming_processing(size_t buffer_size_mb);
    void setup_parallel_processing(size_t thread_count);

    // Memory optimization for large files
    void implement_memory_mapped_processing(const std::string& file_path, std::vector<uint8_t>& output);
    void use_streaming_buffer_processing(std::vector<uint8_t>& pdf_data, size_t buffer_size);
    void enable_progressive_chunk_processing(std::vector<uint8_t>& pdf_data, size_t chunk_size);
    void implement_disk_based_processing(std::vector<uint8_t>& pdf_data, const std::string& temp_dir);

    // Parallel processing optimization
    void process_pdf_chunks_parallel(std::vector<uint8_t>& pdf_data, size_t chunk_count);
    void implement_producer_consumer_pattern(std::vector<uint8_t>& pdf_data);
    void use_thread_pool_processing(std::vector<uint8_t>& pdf_data, size_t pool_size);
    void enable_async_io_operations(std::vector<uint8_t>& pdf_data);

    // Cache optimization
    void implement_intelligent_caching(std::vector<uint8_t>& pdf_data);
    void optimize_memory_access_patterns(std::vector<uint8_t>& pdf_data);
    void enable_prefetch_optimization(std::vector<uint8_t>& pdf_data);
    void implement_lru_cache_strategy();

    // I/O optimization
    void optimize_file_io_operations(const std::string& input_path, const std::string& output_path);
    void implement_sequential_access_optimization(std::vector<uint8_t>& pdf_data);
    void enable_direct_io_when_possible(const std::string& file_path);
    void optimize_buffer_alignment(std::vector<uint8_t>& pdf_data);

    // Algorithm optimization
    void use_optimized_format_detection(std::vector<uint8_t>& pdf_data);
    void implement_fast_pattern_matching(std::vector<uint8_t>& pdf_data);
    void optimize_validation_algorithms(std::vector<uint8_t>& pdf_data);
    void use_simd_optimized_operations(std::vector<uint8_t>& pdf_data);

    // Memory management optimization
    void implement_smart_memory_allocation(size_t estimated_size);
    void use_memory_pools_for_frequent_operations();
    void enable_garbage_collection_optimization();
    void implement_memory_pressure_handling();

    // Performance monitoring and profiling
    PerformanceMetrics measure_processing_performance(const std::vector<uint8_t>& pdf_data);
    void profile_memory_usage_patterns(const std::vector<uint8_t>& pdf_data);
    void benchmark_processing_speed(const std::vector<uint8_t>& pdf_data);
    void analyze_bottlenecks(const std::vector<uint8_t>& pdf_data);

    // Adaptive optimization
    void auto_configure_for_file_size(size_t file_size);
    void adapt_to_available_system_resources();
    void optimize_based_on_content_complexity(const std::vector<uint8_t>& pdf_data);
    void tune_parameters_dynamically(const PerformanceMetrics& metrics);

    // Configuration and tuning
    void set_optimization_profile(const OptimizationProfile& profile);
    void configure_for_large_pdf_handling(const LargePDFHandlingConfig& config);
    void set_performance_priority(PerformancePriority priority);
    void enable_performance_monitoring(bool enabled);

    enum class PerformancePriority {
        SPEED_OPTIMIZED,        // Maximum processing speed
        MEMORY_OPTIMIZED,       // Minimum memory usage
        BALANCED,               // Balance between speed and memory
        QUALITY_OPTIMIZED,      // Maximum quality preservation
        RESOURCE_EFFICIENT      // Optimal resource utilization
    };

    enum class ProcessingMode {
        SINGLE_THREADED,        // Single-threaded processing
        MULTI_THREADED,         // Multi-threaded parallel processing
        STREAMING,              // Streaming processing for large files
        MEMORY_MAPPED,          // Memory-mapped file processing
        HYBRID                  // Adaptive hybrid approach
    };

private:
    PerformancePriority performance_priority_ = PerformancePriority::BALANCED;
    ProcessingMode processing_mode_ = ProcessingMode::HYBRID;
    OptimizationProfile current_profile_;
    LargePDFHandlingConfig large_pdf_config_;
    
    // Performance monitoring
    PerformanceMetrics current_metrics_;
    std::map<std::string, double> benchmark_results_;
    std::vector<PerformanceMetrics> performance_history_;
    
    // Memory management
    std::unique_ptr<std::vector<uint8_t>> memory_pool_;
    size_t max_memory_usage_ = 0;
    size_t current_memory_usage_ = 0;
    
    // Lazy loading registry
    struct LazyLoadEntry {
        size_t offset;
        size_t size;
        std::string data;
    };
    std::unordered_map<size_t, LazyLoadEntry> lazy_load_registry;
    std::mutex memory_mutex_;
    
    // Threading infrastructure
    std::vector<std::thread> worker_threads_;
    std::mutex processing_mutex_;
    std::condition_variable processing_cv_;
    bool processing_complete_ = false;
    
    // Caching infrastructure
    std::map<std::string, std::vector<uint8_t>> operation_cache_;
    std::map<std::string, size_t> cache_access_count_;
    size_t cache_size_limit_ = 0;
    std::mutex cache_mutex_;
    
    // Internal optimization helpers
    void initialize_optimization_profiles();
    void setup_memory_management_system();
    void configure_threading_infrastructure();
    void initialize_caching_system();
    
    // Memory optimization helpers
    bool should_use_streaming(size_t file_size) const;
    bool should_use_memory_mapping(size_t file_size) const;
    size_t calculate_optimal_chunk_size(size_t file_size) const;
    size_t calculate_optimal_buffer_size(size_t available_memory) const;
    
    // Parallel processing helpers
    void distribute_work_across_threads(std::vector<uint8_t>& pdf_data, size_t thread_count);
    void synchronize_thread_results(std::vector<std::future<void>>& futures);
    void balance_thread_workload(const std::vector<size_t>& chunk_sizes);
    
    // I/O optimization helpers
    void optimize_read_operations(std::vector<uint8_t>& buffer, size_t read_size);
    void optimize_write_operations(const std::vector<uint8_t>& buffer, const std::string& output_path);
    void implement_read_ahead_strategy(std::vector<uint8_t>& pdf_data);
    void implement_write_behind_strategy(const std::vector<uint8_t>& pdf_data);
    
    // Cache management helpers
    void update_cache_entry(const std::string& key, const std::vector<uint8_t>& value);
    bool get_cache_entry(const std::string& key, std::vector<uint8_t>& value);
    void evict_least_recently_used_entries();
    void optimize_cache_size_for_workload();
    
    // Performance measurement helpers
    std::chrono::high_resolution_clock::time_point start_timer();
    double end_timer(std::chrono::high_resolution_clock::time_point start_time);
    size_t measure_memory_usage();
    double calculate_throughput(size_t bytes_processed, double time_seconds);
    
    // Adaptive optimization helpers
    void analyze_workload_characteristics(const std::vector<uint8_t>& pdf_data);
    void adjust_parameters_based_on_performance(const PerformanceMetrics& metrics);
    void select_optimal_processing_strategy(size_t file_size, size_t available_memory);
    
    // System resource detection
    size_t detect_available_memory();
    size_t detect_cpu_core_count();
    bool detect_ssd_vs_hdd_storage();
    size_t detect_cache_line_size();
    
    // Large PDF specific optimizations
    void implement_segmented_processing(std::vector<uint8_t>& pdf_data, size_t segment_size);
    void use_lazy_loading_for_large_objects(std::vector<uint8_t>& pdf_data);
    void implement_progressive_validation(std::vector<uint8_t>& pdf_data);
    void optimize_xref_table_processing(std::vector<uint8_t>& pdf_data);
    void implement_incremental_format_preservation(std::vector<uint8_t>& pdf_data);
    
    // Memory pressure handling for very large files
    void handle_memory_pressure_events(std::vector<uint8_t>& pdf_data);
    void implement_emergency_disk_spillover(std::vector<uint8_t>& pdf_data);
    void use_compressed_memory_buffers(std::vector<uint8_t>& pdf_data);
    void implement_memory_compaction_strategies(std::vector<uint8_t>& pdf_data);
};

#endif // PERFORMANCE_OPTIMIZER_HPP
