#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <memory>
#include <map>
#include <thread>
#include <chrono>
#include <functional>
#include <random>

// Forward declaration
struct EncryptionParams;

// Forward declarations for implementation functions
std::vector<uint8_t> hex_to_bytes_impl(const std::string& hex);
std::vector<uint8_t> derive_encryption_key_impl(const std::vector<uint8_t>& password, const EncryptionParams& params);

// PDFUtils class for all PDF processing utilities
class PDFUtils {
public:
    // String conversion utilities
    static std::string bytes_to_string(const std::vector<uint8_t>& bytes);
    static std::string bytes_to_hex(const std::vector<uint8_t>& data);
    
    // Hash calculation utilities
    static std::string calculate_md5(const std::vector<uint8_t>& data);
    static std::string calculate_sha256(const std::vector<uint8_t>& data);
    
    // Conversion utilities for encryption
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
        return hex_to_bytes_impl(hex);
    }
    static std::vector<uint8_t> derive_encryption_key(const std::vector<uint8_t>& password, const EncryptionParams& params) {
        return derive_encryption_key_impl(password, params);
    }
    
    // Compression utilities
    static std::vector<uint8_t> inflate_stream(const std::vector<uint8_t>& compressed_data);
    static std::vector<uint8_t> deflate_stream(const std::vector<uint8_t>& raw_data);
    
    // PDF validation utilities
    static bool is_valid_pdf_header(const std::vector<uint8_t>& data);
    static bool has_valid_eof(const std::vector<uint8_t>& data);
    static size_t find_startxref_offset(const std::vector<uint8_t>& data);
    
    // Safe integer conversion utilities - addresses memory safety violations
    static int safe_stoi(const std::string& str, bool& success);
    static long safe_stol(const std::string& str, bool& success);
    static size_t safe_stoull(const std::string& str, bool& success);
    static std::vector<uint8_t> string_to_bytes(const std::string& str);
    
    // Consistent hash extraction for ensuring all 3 hashes use same source data
    struct ConsistentHashSet {
        std::string md5_hash;
        std::string sha256_hash; 
        std::string structural_hash;
        std::vector<uint8_t> normalized_data;
    };
    
    static ConsistentHashSet extract_consistent_hashes(const std::vector<uint8_t>& pdf_data);
    static std::vector<uint8_t> normalize_pdf_for_hashing(const std::vector<uint8_t>& pdf_data);
    static std::string calculate_structural_hash_consistent(const std::vector<uint8_t>& normalized_data);
};

// Additional utilities namespace for advanced features
namespace PDFUtilsAdvanced {
    // Production-grade error handling
    enum class ErrorCode {
        SUCCESS = 0,
        INVALID_INPUT = 1000,
        BUFFER_OVERFLOW = 1001,
        MEMORY_ALLOCATION = 1002,
        COMPRESSION_FAILED = 2000,
        DECOMPRESSION_FAILED = 2001,
        CRYPTO_FAILED = 3000,
        HASH_FAILED = 3001,
        VALIDATION_FAILED = 4000,
        THREAD_SAFETY_VIOLATION = 5000,
        RESOURCE_EXHAUSTION = 5001,
        TIMEOUT = 5002
    };

    struct ErrorContext {
        ErrorCode code;
        std::string message;
        std::string function_name;
        std::string file_name;
        int line_number;
        std::chrono::system_clock::time_point timestamp;
        size_t thread_id;
    };

    class PDFUtilsException : public std::exception {
    private:
        ErrorContext context_;
        std::string formatted_message_;
        
    public:
        PDFUtilsException(ErrorCode code, const std::string& message, 
                         const std::string& function, const std::string& file, int line);
        
        const char* what() const noexcept override;
        const ErrorContext& get_context() const noexcept;
        ErrorCode get_error_code() const noexcept;
    };

    // Resource guard implementation for preventing resource exhaustion
    class ResourceGuard {
    public:
        class MemoryGuard {
        private:
            size_t allocated_size_;
            bool released_;
            
        public:
            explicit MemoryGuard(size_t size);
            ~MemoryGuard();
            void release();
        };
        
        class OperationGuard {
        private:
            bool active_;
            
        public:
            OperationGuard();
            ~OperationGuard();
            void release();
        };
        
        static void set_memory_limit(size_t limit_bytes);
        static void set_operation_limit(size_t limit);
        static size_t get_memory_usage();
        static size_t get_active_operations();
        static bool check_memory_available(size_t required);
        static bool check_operation_slot_available();
        
    private:
        static std::atomic<size_t> total_memory_allocated_;
        static std::atomic<size_t> active_operations_;
        static size_t max_memory_limit_;
        static size_t max_concurrent_operations_;
        static std::mutex resource_mutex_;
    };

    // LRU Cache Template Implementation (Critical Fix #1)
    template<typename K, typename V>
    class LRUCache {
    private:
        struct CacheNode {
            K key;
            V value;
            std::shared_ptr<CacheNode> prev;
            std::shared_ptr<CacheNode> next;
            
            CacheNode() = default;
            CacheNode(const K& k, const V& v) : key(k), value(v) {}
        };
        
        size_t capacity_;
        std::unordered_map<K, std::shared_ptr<CacheNode>> cache_map_;
        std::shared_ptr<CacheNode> head_;
        std::shared_ptr<CacheNode> tail_;
        mutable std::mutex cache_mutex_;
        
        void move_to_head(std::shared_ptr<CacheNode> node) {
            remove_node(node);
            add_to_head(node);
        }
        
        void remove_node(std::shared_ptr<CacheNode> node) {
            if (node->prev) {
                node->prev->next = node->next;
            }
            if (node->next) {
                node->next->prev = node->prev;
            }
        }
        
        void add_to_head(std::shared_ptr<CacheNode> node) {
            node->prev = head_;
            node->next = head_->next;
            
            if (head_->next) {
                head_->next->prev = node;
            }
            head_->next = node;
            
            if (tail_->prev == head_) {
                tail_->prev = node;
            }
        }
        
        std::shared_ptr<CacheNode> remove_tail() {
            auto last_node = tail_->prev;
            if (last_node == head_) {
                return nullptr;
            }
            remove_node(last_node);
            return last_node;
        }
        
    public:
        explicit LRUCache(size_t capacity) : capacity_(capacity) {
            head_ = std::make_shared<CacheNode>();
            tail_ = std::make_shared<CacheNode>();
            head_->next = tail_;
            tail_->prev = head_;
        }
        
        bool get(const K& key, V& value) {
            std::lock_guard<std::mutex> lock(cache_mutex_);
            
            auto it = cache_map_.find(key);
            if (it == cache_map_.end()) {
                return false;
            }
            
            auto node = it->second;
            move_to_head(node);
            value = node->value;
            return true;
        }
        
        void put(const K& key, const V& value) {
            std::lock_guard<std::mutex> lock(cache_mutex_);
            
            auto it = cache_map_.find(key);
            if (it != cache_map_.end()) {
                auto node = it->second;
                node->value = value;
                move_to_head(node);
                return;
            }
            
            auto new_node = std::make_shared<CacheNode>(key, value);
            
            if (cache_map_.size() >= capacity_) {
                auto tail_node = remove_tail();
                if (tail_node) {
                    cache_map_.erase(tail_node->key);
                }
            }
            
            cache_map_[key] = new_node;
            add_to_head(new_node);
        }
        
        void clear() {
            std::lock_guard<std::mutex> lock(cache_mutex_);
            cache_map_.clear();
            head_->next = tail_;
            tail_->prev = head_;
        }
        
        size_t size() const {
            std::lock_guard<std::mutex> lock(cache_mutex_);
            return cache_map_.size();
        }
        
        bool empty() const {
            std::lock_guard<std::mutex> lock(cache_mutex_);
            return cache_map_.empty();
        }
    };

    // Random byte generation utility (Critical Fix #4)
    // generate_random_bytes function implemented in global namespace
};

// Global utility functions for missing implementations
std::vector<uint8_t> generate_random_bytes(size_t count);
std::string trim(const std::string& str);
size_t find_matching_delimiter(const std::string& data, size_t start, const std::string& open, const std::string& close);
std::map<std::string, std::string> parse_dictionary_content(const std::string& dict_content);
std::vector<uint8_t> decompress_stream_data(const std::vector<uint8_t>& stream_data, const std::vector<std::string>& filters);
