#ifndef CACHE_MANAGER_HPP
#define CACHE_MANAGER_HPP
#include "stealth_macros.hpp"

#include "forensic_validator.hpp"
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <thread>
#include <memory>
#include <list>
#include <atomic>

/**
 * Advanced Caching System for PDF Forensic Validation
 * Provides LRU caching with TTL, memory management, and statistics
 */
class CacheManager {
public:
    struct CacheEntry {
        ForensicFingerprint fingerprint;
        ValidationResult validation_result;
        std::chrono::steady_clock::time_point created_time;
        std::chrono::steady_clock::time_point last_accessed;
        size_t access_count;
        bool is_validation_cached;

        CacheEntry() : access_count(0), is_validation_cached(false) {
            auto now = std::chrono::steady_clock::now();
            created_time = now;
            last_accessed = now;
        }
    };

    struct CacheStatistics {
        size_t total_requests = 0;
        size_t cache_hits = 0;
        size_t cache_misses = 0;
        size_t evictions = 0;
        size_t expired_entries = 0;
        double hit_rate = 0.0;
        size_t memory_usage_bytes = 0;
        size_t current_entries = 0;
        std::chrono::steady_clock::time_point last_cleanup;
    };

private:
    mutable std::mutex cache_mutex_;
    std::unordered_map<std::string, std::shared_ptr<CacheEntry>> cache_;
    std::list<std::string> lru_list_; // Most recently used at front
    std::unordered_map<std::string, std::list<std::string>::iterator> lru_map_;

    size_t max_cache_size_;
    std::chrono::hours ttl_;
    CacheStatistics stats_;

    // Background cleanup
    std::thread cleanup_thread_;
    std::atomic<bool> cleanup_running_;
    std::chrono::minutes cleanup_interval_;

    // Memory management
    size_t max_memory_usage_;
    std::atomic<size_t> current_memory_usage_;

public:
    CacheManager(size_t max_size = 1000, 
                 std::chrono::hours ttl = std::chrono::hours(24),
                 size_t max_memory_mb = 500);

    ~CacheManager();

    // Lifecycle management (required by cloner module)
    bool initialize();
    void shutdown();

    // Core caching operations
    bool get_fingerprint(const std::vector<uint8_t>& pdf_data, ForensicFingerprint& fingerprint);
    void put_fingerprint(const std::vector<uint8_t>& pdf_data, const ForensicFingerprint& fingerprint);

    bool get_validation_result(const std::vector<uint8_t>& pdf_data, ValidationResult& result);
    void put_validation_result(const std::vector<uint8_t>& pdf_data, const ValidationResult& result);

    // Cache management
    void clear_cache();
    void cleanup_expired_entries();
    void resize_cache(size_t new_max_size);
    void set_ttl(std::chrono::hours new_ttl);

    // Statistics and monitoring
    CacheStatistics get_statistics() const;
    void reset_statistics();
    double get_hit_rate() const;
    size_t get_memory_usage() const;

    // Advanced operations
    bool preload_common_patterns();
    void optimize_cache_layout();
    std::vector<std::string> get_cache_keys() const;
    bool export_cache(const std::string& filename) const;
    bool import_cache(const std::string& filename);

    // Configuration
    void set_cleanup_interval(std::chrono::minutes interval);
    void set_max_memory_usage(size_t max_memory_mb);
    bool is_cache_healthy() const;

    // Additional compression cache methods
    std::vector<uint8_t> get_compressed_data(const std::string& key);
    void store_compressed_data(const std::string& key, const std::vector<uint8_t>& data);
    size_t get_cache_size() const;

private:
    std::string generate_cache_key(const std::vector<uint8_t>& pdf_data) const;
    void touch_entry(const std::string& key);
    void evict_lru_entry();
    bool is_entry_expired(const CacheEntry& entry) const;
    size_t estimate_entry_size(const CacheEntry& entry) const;
    void update_memory_usage();
    void cleanup_worker();
    void ensure_memory_limit();
    void evict_lru_entries();

    // Serialization helpers
    std::string serialize_fingerprint(const ForensicFingerprint& fp) const;
    bool deserialize_fingerprint(const std::string& data, ForensicFingerprint& fp) const;
    std::string serialize_validation_result(const ValidationResult& result) const;
    bool deserialize_validation_result(const std::string& data, ValidationResult& result) const;
};

/**
 * Smart Cache-Aware ForensicValidator
 * Integrates caching seamlessly with validation operations
 */
class CachedForensicValidator : public ForensicValidator {
private:
    std::unique_ptr<CacheManager> cache_manager_;
    bool caching_enabled_;

public:
    CachedForensicValidator(size_t cache_size = 1000, 
                           std::chrono::hours cache_ttl = std::chrono::hours(24));

    ~CachedForensicValidator() = default;

    // Override core methods to use caching
    ForensicFingerprint extract_fingerprint(const std::vector<uint8_t>& pdf_data);
    ValidationResult validate_evasion_techniques(const std::vector<uint8_t>& pdf_data);

    // Cache management
    void enable_caching(bool enable) { caching_enabled_ = enable; }
    bool is_caching_enabled() const { return caching_enabled_; }

    CacheManager::CacheStatistics get_cache_statistics() const;
    void clear_cache();
    void optimize_cache();

    // Batch operations with intelligent caching
    std::vector<ForensicFingerprint> extract_fingerprints_batch(
        const std::vector<std::vector<uint8_t>>& pdf_data_batch);

    std::vector<ValidationResult> validate_batch(
        const std::vector<std::vector<uint8_t>>& pdf_data_batch);

    // Cache warming and preloading
    void warm_cache_with_common_patterns();
    void preload_fingerprints(const std::vector<std::vector<uint8_t>>& pdf_data_batch);
};

#endif // CACHE_MANAGER_HPP

#ifndef CACHE_MANAGER_HPP
#define CACHE_MANAGER_HPP
#include "stealth_macros.hpp"

#include <unordered_map>
#include <vector>
#include <string>
#include <chrono>
#include <optional>
#include <cstdint>
#include <shared_mutex>
#include "secure_memory.hpp"
#include "secure_exceptions.hpp"

class CacheManager {
private:
    struct CacheEntry {
        std::vector<uint8_t> fingerprint_data;
        std::vector<uint8_t> validation_data; 
        std::vector<uint8_t> compressed_data;
        std::chrono::steady_clock::time_point timestamp;
        std::chrono::steady_clock::time_point last_access;
        size_t access_count = 0;
    };

    std::unordered_map<std::string, std::shared_ptr<CacheEntry>> cache_;
    std::vector<std::string> lru_list_;
    mutable SecureMemory::SecureMutex cache_mutex_;
    size_t max_entries_ = 1000;
    size_t max_memory_ = 50 * 1024 * 1024; // 50MB

public:
    CacheManager() = default;
    ~CacheManager() = default;

    bool initialize() {
        return true;
    }

    void shutdown() {
        SecureMemory::SecureLockGuard lock(cache_mutex_);
        cache_.clear();
        lru_list_.clear();
    }

    std::vector<uint8_t> get_compressed_data(const std::string& key) {
        SecureMemory::SecureLockGuard lock(cache_mutex_);
        auto it = cache_.find(key);
        if (it != cache_.end() && it->second) {
            it->second->last_access = std::chrono::steady_clock::now();
            it->second->access_count++;
            return it->second->compressed_data;
        }
        return {};
    }

    void store_compressed_data(const std::string& key, const std::vector<uint8_t>& data) {
        SecureMemory::SecureLockGuard lock(cache_mutex_);

        if (cache_.size() >= max_entries_) {
            evict_lru_entry();
        }

        auto entry = std::make_shared<CacheEntry>();
        entry->compressed_data = data;
        entry->timestamp = std::chrono::steady_clock::now();
        entry->last_access = entry->timestamp;

        cache_[key] = entry;
        lru_list_.push_back(key);
    }

private:
    void evict_lru_entry() {
        if (!lru_list_.empty()) {
            std::string oldest_key = lru_list_.front();
            lru_list_.erase(lru_list_.begin());
            cache_.erase(oldest_key);
        }
    }
};

#endif // CACHE_MANAGER_HPP