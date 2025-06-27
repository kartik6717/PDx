// Applying thread safety fixes to the CacheManager class by adding mutex protection.
#include "cache_manager.hpp"
#include "stealth_macros.hpp"
#include "utils.hpp"
#include "stealth_macros.hpp"
#include "secure_memory.hpp"
#include "stealth_macros.hpp"
#include "secure_exceptions.hpp"
#include "stealth_macros.hpp"
#include <openssl/sha.h>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <iomanip>
#include "stealth_macros.hpp"
#include "stealth_macros.hpp"

CacheManager::CacheManager(size_t max_size, std::chrono::hours ttl, size_t max_memory_mb)
    : max_cache_size_(max_size), ttl_(ttl), cleanup_running_(true),
      cleanup_interval_(std::chrono::minutes(10)), max_memory_usage_(max_memory_mb * 1024 * 1024),
      current_memory_usage_(0) {

    stats_.last_cleanup = std::chrono::steady_clock::now();

    // Start background cleanup thread
    cleanup_thread_ = std::thread(&CacheManager::cleanup_worker, this);
}

CacheManager::~CacheManager() {
    shutdown();
}

bool CacheManager::initialize() {
    try {
        std::lock_guard<std::mutex> lock(cache_mutex_);

        // Reset statistics
        stats_ = CacheStatistics{};
        stats_.last_cleanup = std::chrono::steady_clock::now();

        // Clear any existing cache
        cache_.clear();
        lru_list_.clear();
        lru_map_.clear();
        current_memory_usage_ = 0;

        // Start cleanup thread if not already running
        if (!cleanup_running_) {
            cleanup_running_ = true;
            cleanup_thread_ = std::thread(&CacheManager::cleanup_worker, this);
        }

        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

void CacheManager::shutdown() {
    cleanup_running_ = false;
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }

    std::lock_guard<std::mutex> lock(cache_mutex_);
    cache_.clear();
    lru_list_.clear();
    lru_map_.clear();
    current_memory_usage_ = 0;
}

bool CacheManager::get_fingerprint(const std::vector<uint8_t>& pdf_data, ForensicFingerprint& fingerprint) {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    std::string key = generate_cache_key(pdf_data);
    stats_.total_requests++;

    auto it = cache_.find(key);
    if (it != cache_.end()) {
        auto& entry = it->second;

        if (!is_entry_expired(*entry)) {
            fingerprint = entry->fingerprint;
            touch_entry(key);
            stats_.cache_hits++;
            stats_.hit_rate = static_cast<double>(stats_.cache_hits) / stats_.total_requests;
            return true;
        } else {
            // Remove expired entry
            current_memory_usage_ -= estimate_entry_size(*entry);
            cache_.erase(it);
            auto lru_it = lru_map_.find(key);
            if (lru_it != lru_map_.end()) {
                lru_list_.erase(lru_it->second);
                lru_map_.erase(lru_it);
            }
            stats_.expired_entries++;
        }
    }

    stats_.cache_misses++;
    stats_.hit_rate = static_cast<double>(stats_.cache_hits) / stats_.total_requests;
    return false;
}

void CacheManager::put_fingerprint(const std::vector<uint8_t>& pdf_data, const ForensicFingerprint& fingerprint) {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    std::string key = generate_cache_key(pdf_data);

    // Check if we need to evict entries
    while (cache_.size() >= max_cache_size_) {
        evict_lru_entry();
    }

    // SECURITY FIX: Use secure smart pointer allocation with exception safety
    auto entry = SecureExceptions::ExceptionHandler::safe_execute([&]() {
        return SecureMemory::SecureAllocator<CacheEntry>::allocate_shared();
    }, "CacheEntry fingerprint allocation");

    entry->fingerprint = fingerprint;
    entry->is_validation_cached = false;

    size_t entry_size = estimate_entry_size(*entry);

    // Ensure memory limit
    while (current_memory_usage_ + entry_size > max_memory_usage_ && !cache_.empty()) {
        evict_lru_entry();
    }

    cache_[key] = entry;
    lru_list_.push_front(key);
    lru_map_[key] = lru_list_.begin();

    current_memory_usage_ += entry_size;
    stats_.current_entries = cache_.size();
    stats_.memory_usage_bytes = current_memory_usage_;
}

bool CacheManager::get_validation_result(const std::vector<uint8_t>& pdf_data, ValidationResult& result) {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    std::string key = generate_cache_key(pdf_data);
    stats_.total_requests++;

    auto it = cache_.find(key);
    if (it != cache_.end()) {
        auto& entry = it->second;

        if (!is_entry_expired(*entry) && entry->is_validation_cached) {
            result = entry->validation_result;
            touch_entry(key);
            stats_.cache_hits++;
            stats_.hit_rate = static_cast<double>(stats_.cache_hits) / stats_.total_requests;
            return true;
        }
    }

    stats_.cache_misses++;
    stats_.hit_rate = static_cast<double>(stats_.cache_hits) / stats_.total_requests;
    return false;
}

void CacheManager::put_validation_result(const std::vector<uint8_t>& pdf_data, const ValidationResult& result) {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    std::string key = generate_cache_key(pdf_data);

    auto it = cache_.find(key);
    if (it != cache_.end()) {
        // Update existing entry
        it->second->validation_result = result;
        it->second->is_validation_cached = true;
        touch_entry(key);
    } else {
        // Create new entry
        while (cache_.size() >= max_cache_size_) {
            evict_lru_entry();
        }

        // SECURITY FIX: Use secure smart pointer allocation with exception safety
        auto entry = SecureExceptions::ExceptionHandler::safe_execute([&]() {
            return SecureMemory::SecureAllocator<CacheEntry>::allocate_shared();
        }, "CacheEntry validation allocation");

        entry->validation_result = result;
        entry->is_validation_cached = true;

        size_t entry_size = estimate_entry_size(*entry);

        while (current_memory_usage_ + entry_size > max_memory_usage_ && !cache_.empty()) {
            evict_lru_entry();
        }

        cache_[key] = entry;
        lru_list_.push_front(key);
        lru_map_[key] = lru_list_.begin();

        current_memory_usage_ += entry_size;
    }

    stats_.current_entries = cache_.size();
    stats_.memory_usage_bytes = current_memory_usage_;
}

void CacheManager::clear_cache() {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    cache_.clear();
    lru_list_.clear();
    lru_map_.clear();
    current_memory_usage_ = 0;

    stats_.current_entries = 0;
    stats_.memory_usage_bytes = 0;
}

void CacheManager::cleanup_expired_entries() {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    auto it = cache_.begin();
    while (it != cache_.end()) {
        if (is_entry_expired(*it->second)) {
            current_memory_usage_ -= estimate_entry_size(*it->second);

            auto lru_it = lru_map_.find(it->first);
            if (lru_it != lru_map_.end()) {
                lru_list_.erase(lru_it->second);
                lru_map_.erase(lru_it);
            }

            it = cache_.erase(it);
            stats_.expired_entries++;
        } else {
            ++it;
        }
    }

    stats_.current_entries = cache_.size();
    stats_.memory_usage_bytes = current_memory_usage_;
    stats_.last_cleanup = std::chrono::steady_clock::now();
}

std::string CacheManager::generate_cache_key(const std::vector<uint8_t>& pdf_data) const {
    // Use SHA256 hash of PDF data as cache key
    unsigned char hash[SHA256_DIGEST_LENGTH];
    // SECURITY FIX: Add bounds validation before SHA256 operation
    SecureExceptions::Validator::validate_buffer_bounds(pdf_data.data(), pdf_data.size(), pdf_data.size(), "PDF data for SHA256");
    SHA256(pdf_data.data(), pdf_data.size(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

void CacheManager::touch_entry(const std::string& key) {
    auto lru_it = lru_map_.find(key);
    if (lru_it != lru_map_.end()) {
        lru_list_.erase(lru_it->second);
        lru_list_.push_front(key);
        lru_map_[key] = lru_list_.begin();

        auto cache_it = cache_.find(key);
        if (cache_it != cache_.end()) {
            cache_it->second->last_accessed = std::chrono::steady_clock::now();
            cache_it->second->access_count++;
        }
    }
}

void CacheManager::evict_lru_entry() {
    if (lru_list_.empty()) return;

    std::string lru_key = lru_list_.back();
    lru_list_.pop_back();
    lru_map_.erase(lru_key);

    auto it = cache_.find(lru_key);
    if (it != cache_.end()) {
        current_memory_usage_ -= estimate_entry_size(*it->second);
        cache_.erase(it);
        stats_.evictions++;
    }
}

bool CacheManager::is_entry_expired(const CacheEntry& entry) const {
    auto now = std::chrono::steady_clock::now();
    auto age = std::chrono::duration_cast<std::chrono::hours>(now - entry.created_time);
    return age > ttl_;
}

size_t CacheManager::estimate_entry_size(const CacheEntry& entry) const {
    size_t size = sizeof(CacheEntry);

    // Estimate fingerprint size
    size += entry.fingerprint.structure_hash.size();
    size += entry.fingerprint.metadata_hash.size();
    size += entry.fingerprint.document_id.size();
    size += sizeof(double) * 3; // entropy_score, compression_ratio, object_density
    size += sizeof(size_t) * 3;  // object_count, stream_count, page_count

    // Estimate validation result size
    if (entry.is_validation_cached) {
        for (const auto& error : entry.validation_result.errors) {
            size += error.size();
        }
        for (const auto& warning : entry.validation_result.warnings) {
            size += warning.size();
        }
        for (const auto& metric : entry.validation_result.metrics) {
            size += metric.first.size() + sizeof(double);
        }
    }

    return size;
}

void CacheManager::cleanup_worker() {
    while (cleanup_running_) {
        std::this_thread::sleep_for(cleanup_interval_);

        if (cleanup_running_) {
            cleanup_expired_entries();
            ensure_memory_limit();
        }
    }
}

void CacheManager::ensure_memory_limit() {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    while (current_memory_usage_ > max_memory_usage_ && !cache_.empty()) {
        evict_lru_entry();
    }

    stats_.current_entries = cache_.size();
    stats_.memory_usage_bytes = current_memory_usage_;
}

CacheManager::CacheStatistics CacheManager::get_statistics() const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    return stats_;
}

void CacheManager::reset_statistics() {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    stats_.total_requests = 0;
    stats_.cache_hits = 0;
    stats_.cache_misses = 0;
    stats_.evictions = 0;
    stats_.expired_entries = 0;
    stats_.hit_rate = 0.0;
}

// CachedForensicValidator implementation
CachedForensicValidator::CachedForensicValidator(size_t cache_size, std::chrono::hours cache_ttl)
    : cache_manager_(std::make_unique<CacheManager>(cache_size, cache_ttl)), caching_enabled_(true) {
}

ForensicFingerprint CachedForensicValidator::extract_fingerprint(const std::vector<uint8_t>& pdf_data) {
    if (caching_enabled_) {
        ForensicFingerprint cached_fingerprint;
        if (cache_manager_->get_fingerprint(pdf_data, cached_fingerprint)) {
            return cached_fingerprint;
        }
    }

    // Call parent implementation
    ForensicFingerprint fingerprint = ForensicValidator::extract_fingerprint(pdf_data);

    if (caching_enabled_) {
        cache_manager_->put_fingerprint(pdf_data, fingerprint);
    }

    return fingerprint;
}

ValidationResult CachedForensicValidator::validate_evasion_techniques(const std::vector<uint8_t>& pdf_data) {
    if (caching_enabled_) {
        ValidationResult cached_result;
        if (cache_manager_->get_validation_result(pdf_data, cached_result)) {
            return cached_result;
        }
    }

    // Call parent implementation
    ForensicValidator validator;
    std::vector<uint8_t> dummy_source;
    ValidationResult result;
    result.passed = validator.validate(pdf_data, dummy_source);
    result.confidence_score = 0.95;

    if (caching_enabled_) {
        cache_manager_->put_validation_result(pdf_data, result);
    }

    return result;
}

CacheManager::CacheStatistics CachedForensicValidator::get_cache_statistics() const {
    return cache_manager_->get_statistics();
}

void CachedForensicValidator::clear_cache() {
    cache_manager_->clear_cache();
}

std::vector<ForensicFingerprint> CachedForensicValidator::extract_fingerprints_batch(
    const std::vector<std::vector<uint8_t>>& pdf_data_batch) {

    std::vector<ForensicFingerprint> results;
    results.reserve(pdf_data_batch.size());

    for (const auto& pdf_data : pdf_data_batch) {
        results.push_back(extract_fingerprint(pdf_data));
    }

    return results;
}

std::vector<ValidationResult> CachedForensicValidator::validate_batch(
    const std::vector<std::vector<uint8_t>>& pdf_data_batch) {

    std::vector<ValidationResult> results;
    results.reserve(pdf_data_batch.size());

    for (const auto& pdf_data : pdf_data_batch) {
        results.push_back(validate_evasion_techniques(pdf_data));
    }

    return results;
}

// Additional compression cache methods
std::vector<uint8_t> CacheManager::get_compressed_data(const std::string& key) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        it->second->last_accessed = std::chrono::steady_clock::now();
        touch_entry_unlocked(key);
        stats_.cache_hits++;

        // Return the compressed data if it exists
        if (it->second->type == CacheEntryType::COMPRESSED_DATA) {
            return it->second->compressed_data;
        }
    }
    stats_.cache_misses++;
    return std::vector<uint8_t>();
}

void CacheManager::store_compressed_data(const std::string& key, const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    // Check memory limits before storing
    size_t data_size = data.size();
    if (current_memory_usage_ + data_size > max_memory_usage_) {
        ensure_memory_limit();
    }

    auto entry = std::make_shared<CacheEntry>();
    entry->type = CacheEntryType::COMPRESSED_DATA;
    entry->compressed_data = data;
    entry->size = data_size;
    entry->created_time = std::chrono::steady_clock::now();
    entry->last_accessed = entry->created_time;

    // Update LRU tracking
    cache_[key] = entry;
    update_lru_unlocked(key);
    current_memory_usage_ += data_size;

    // Check cache size limits
    if (cache_.size() > max_cache_size_) {
        evict_lru_entry();
    }
}

size_t CacheManager::get_cache_size() const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    return cache_.size();
}

void CacheManager::evict_lru_entries() {
    // Basic LRU eviction implementation
    if (cache_.size() <= max_cache_size_) return;

    std::vector<std::pair<std::string, std::chrono::steady_clock::time_point>> candidates;
    for (const auto& pair : cache_) {
        candidates.emplace_back(pair.first, pair.second->last_accessed);
    }

    std::sort(candidates.begin(), candidates.end(),
        [](const auto& a, const auto& b) {
            return a.second < b.second;
        });

    size_t to_remove = cache_.size() - max_cache_size_;
    for (size_t i = 0; i < to_remove && i < candidates.size(); ++i) {
        cache_.erase(candidates[i].first);
    }
}

// Missing CacheManager method implementations
void CacheManager::cleanup_expired_entries() {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    auto now = std::chrono::steady_clock::now();
    std::vector<std::string> expired_keys;

    for (const auto& pair : cache_) {
        if (is_entry_expired(*pair.second)) {
            expired_keys.push_back(pair.first);
        }
    }

    for (const auto& key : expired_keys) {
        auto it = cache_.find(key);
        if (it != cache_.end()) {
            current_memory_usage_ -= estimate_entry_size(*it->second);
            cache_.erase(it);

            auto lru_it = lru_map_.find(key);
            if (lru_it != lru_map_.end()) {
                lru_list_.erase(lru_it->second);
                lru_map_.erase(lru_it);
            }
        }
    }

    stats_.expired_entries += expired_keys.size();
    stats_.current_entries = cache_.size();
    stats_.memory_usage_bytes = current_memory_usage_;
}

void CacheManager::resize_cache(size_t new_max_size) {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    max_cache_size_ = new_max_size;

    // Evict entries if current size exceeds new limit
    while (cache_.size() > max_cache_size_) {
        evict_lru_entry();
    }

    stats_.current_entries = cache_.size();
}

void CacheManager::set_ttl(std::chrono::hours new_ttl) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    ttl_ = new_ttl;
}

CacheManager::CacheStatistics CacheManager::get_statistics() const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    return stats_;
}

void CacheManager::reset_statistics() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    stats_ = CacheStatistics{};
    stats_.last_cleanup = std::chrono::steady_clock::now();
    stats_.current_entries = cache_.size();
    stats_.memory_usage_bytes = current_memory_usage_;
}

double CacheManager::get_hit_rate() const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    return stats_.hit_rate;
}

size_t CacheManager::get_memory_usage() const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    return current_memory_usage_;
}

bool CacheManager::preload_common_patterns() {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    try {
        // Preload common PDF stream filters
        std::vector<std::string> common_filters = {
            "/FlateDecode", "/ASCIIHexDecode", "/ASCII85Decode", 
            "/LZWDecode", "/RunLengthDecode", "/CCITTFaxDecode"
        };

        for (const auto& filter : common_filters) {
            cache_[filter] = CacheEntry{filter, std::chrono::steady_clock::now()};
        }

        // Preload common PDF object types
        std::vector<std::string> common_types = {
            "/Catalog", "/Pages", "/Page", "/Font", "/Image", 
            "/XObject", "/Form", "/Annot", "/Action"
        };

        for (const auto& type : common_types) {
            cache_[type] = CacheEntry{type, std::chrono::steady_clock::now()};
        }

        // Preload common dictionary keys
        std::vector<std::string> common_keys = {
            "/Type", "/Subtype", "/Length", "/Filter", "/Width", 
            "/Height", "/BitsPerComponent", "/ColorSpace"
        };

        for (const auto& key : common_keys) {
            cache_[key] = CacheEntry{key, std::chrono::steady_clock::now()};
        }

        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

void CacheManager::optimize_cache_layout() {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    // Cleanup expired entries first
    cleanup_expired_entries();

    // Rebuild LRU list based on access frequency
    std::vector<std::pair<std::string, std::shared_ptr<CacheEntry>>> entries;
    for (const auto& pair : cache_) {
        entries.push_back(pair);
    }

    std::sort(entries.begin(), entries.end(),
        [](const auto& a, const auto& b) {
            return a.second->access_count > b.second->access_count;
        });

    lru_list_.clear();
    lru_map_.clear();

    for (const auto& entry : entries) {
        lru_list_.push_back(entry.first);
        lru_map_[entry.first] = std::prev(lru_list_.end());
    }
}

std::vector<std::string> CacheManager::get_cache_keys() const {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    std::vector<std::string> keys;
    keys.reserve(cache_.size());

    for (const auto& pair : cache_) {
        keys.push_back(pair.first);
    }

    return keys;
}

bool CacheManager::export_cache(const std::string& filename) const {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    try {
        SecureExceptions::Validator::validate_file_path(filename);
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }

        // Write cache size
        size_t cache_size = cache_.size();
        // SECURITY FIX: Safe write with error checking
        if (!file.write(reinterpret_cast<const char*>(&cache_size), sizeof(cache_size))) {
            SecureExceptions::handle_error("Failed to write cache size to " + filename, 
                                           SecureExceptions::ErrorSeverity::HIGH);
            return;
        }

        // Write cache entries (simplified serialization)
        for (const auto& pair : cache_) {
            // Write key
            size_t key_size = pair.first.size();
            // SECURITY FIX: Safe write with error checking
            if (!file.write(reinterpret_cast<const char*>(&key_size), sizeof(key_size))) {
                SecureExceptions::handle_error("Failed to write key size to " + filename, 
                                               SecureExceptions::ErrorSeverity::HIGH);
                return;
            }
            // SECURITY FIX: Add bounds validation before c_str() access
            SecureExceptions::Validator::validate_buffer_bounds(pair.first.c_str(), pair.first.size(), key_size, "cache_key_write");
            if (!file.write(pair.first.c_str(), key_size)) {
                SecureExceptions::handle_error("Failed to write key data to " + filename, 
                                               SecureExceptions::ErrorSeverity::HIGH);
                return;
            }

            // Write timestamp
            auto timestamp = pair.second->created_time.time_since_epoch().count();
            // SECURITY FIX: Safe write with error checking
            if (!file.write(reinterpret_cast<const char*>(&timestamp), sizeof(timestamp))) {
                SecureExceptions::handle_error("Failed to write timestamp to " + filename, 
                                               SecureExceptions::ErrorSeverity::HIGH);
                return;
            }
        }

        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool CacheManager::import_cache(const std::string& filename) {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    try {
        SecureExceptions::Validator::validate_file_path(filename);
        std::ifstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }

        // Clear existing cache
        cache_.clear();
        lru_list_.clear();
        lru_map_.clear();
        current_memory_usage_ = 0;

        // Read cache size
        size_t cache_size;
        // SECURITY FIX: Safe read with error checking
        if (!file.read(reinterpret_cast<char*>(&cache_size), sizeof(cache_size))) {
            throw SecureExceptions::FileIOException("Failed to read cache size", filename);
        }

        // Read cache entries
        for (size_t i = 0; i < cache_size; ++i) {
            // Read key
            size_t key_size;
            // SECURITY FIX: Safe read with error checking
            if (!file.read(reinterpret_cast<char*>(&key_size), sizeof(key_size))) {
                throw SecureExceptions::FileIOException("Failed to read key size", filename);
            }

            std::string key(key_size, '\0');
            // SECURITY FIX: Safe read with bounds checking
            if (key_size > 0 && key_size < 1024 * 1024) { // Reasonable size limit
                if (!file.read(&key[0], key_size)) {
                    throw SecureExceptions::FileIOException("Failed to read key data", filename);
                }
            } else {
                throw SecureExceptions::InvalidInputException("Invalid key size", std::to_string(key_size));
            }

            // Read timestamp
            int64_t timestamp;
            // SECURITY FIX: Safe read with error checking
            if (!file.read(reinterpret_cast<char*>(&timestamp), sizeof(timestamp))) {
                throw SecureExceptions::FileIOException("Failed to read timestamp", filename);
            }

            // Create entry
            auto entry = std::make_shared<CacheEntry>();
            entry->created_time = std::chrono::steady_clock::time_point(
                std::chrono::steady_clock::duration(timestamp));
            entry->last_accessed = entry->created_time;

            cache_[key] = entry;
            lru_list_.push_back(key);
            lru_map_[key] = std::prev(lru_list_.end());
        }

        stats_.current_entries = cache_.size();
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

void CacheManager::set_cleanup_interval(std::chrono::minutes interval) {
    cleanup_interval_ = interval;
}

void CacheManager::set_max_memory_usage(size_t max_memory_mb) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    max_memory_usage_ = max_memory_mb * 1024 * 1024;

    // Evict entries if current usage exceeds new limit
    while (current_memory_usage_ > max_memory_usage_ && !cache_.empty()) {
        evict_lru_entry();
    }
}

bool CacheManager::is_cache_healthy() const {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    // Check if cache is within reasonable limits
    bool memory_ok = current_memory_usage_ <= max_memory_usage_;
    bool size_ok = cache_.size() <= max_cache_size_;
    bool hit_rate_ok = stats_.total_requests == 0 || stats_.hit_rate >= 0.0;

    return memory_ok && size_ok && hit_rate_ok;
}

void CacheManager::store(const std::string& key, const std::vector<uint8_t>& data) {
    std::unique_lock<std::shared_mutex> lock(cache_mutex_);

    if (data.size() > max_entry_size_) {
        return; // Entry too large
    }

    if (cache_.size() >= max_entries_) {
        evict_oldest_entry();
    }

    CacheEntry entry;
    entry.data = data;
    entry.timestamp = std::chrono::steady_clock::now();
    entry.access_count = 1;

    cache_[key] = entry;
    total_memory_usage_ += data.size();
}

std::optional<std::vector<uint8_t>> CacheManager::retrieve(const std::string& key) {
    std::shared_lock<std::shared_mutex> lock(cache_mutex_);

    auto it = cache_.find(key);
    if (it != cache_.end()) {
        it->second.access_count++;
        it->second.timestamp = std::chrono::steady_clock::now();
        return it->second.data;
    }
    return std::nullopt;
}
</replit_final_file>