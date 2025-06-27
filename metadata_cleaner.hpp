#ifndef METADATA_CLEANER_HPP
#define METADATA_CLEANER_HPP

#include <vector>
#include <string>
#include <cstdint>
#include <cstddef>
#include <memory>
#include "secure_memory.hpp"
#include "secure_exceptions.hpp"
#include "stealth_macros.hpp"
#include "complete_silence_enforcer.hpp"

class MetadataCleaner {
public:
    enum class CleaningLevel {
        BASIC,
        MODERATE,
        AGGRESSIVE,
        COMPLETE
    };
    
    static constexpr size_t BUFFER_SIZE = 4096;
    
    MetadataCleaner() {
        ENFORCE_COMPLETE_SILENCE();
        is_active_ = false;
        cleaning_level_ = CleaningLevel::BASIC;
        cleanup_count_ = 0;
        secure_buffer_ = SecureMemory::allocate_secure_buffer(BUFFER_SIZE);
    }
    
    ~MetadataCleaner() {
        ENFORCE_COMPLETE_SILENCE();
        if (secure_buffer_) SecureMemory::secure_free(secure_buffer_);
    }
    
    void activate_cleaning() {
        ENFORCE_COMPLETE_SILENCE();
        is_active_ = true;
    }
    
    void deactivate_cleaning() {
        ENFORCE_COMPLETE_SILENCE();
        is_active_ = false;
        secure_memory_cleanup();
    }
    
    bool clean_pdf_metadata(std::vector<uint8_t>& pdf_data) {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        void* cleaning_buffer = SecureMemory::allocate_secure_buffer(pdf_data.size() + 512);
        bool cleaning_success = false;
        
        try {
            if (!validate_cleaning_target(pdf_data)) {
                SecureMemory::secure_free(cleaning_buffer);
                eliminate_all_traces();
                return false;
            }
            
            cleaning_success = perform_comprehensive_metadata_removal(pdf_data);
            SecureMemory::secure_vector_operations(pdf_data);
            cleanup_count_++;
            eliminate_all_traces();
            
        } catch (...) {
            SecureMemory::secure_free(cleaning_buffer);
            eliminate_all_traces();
            structured_exception_handling(std::current_exception());
            return false;
        }
        
        SecureMemory::secure_free(cleaning_buffer);
        eliminate_all_traces();
        return cleaning_success;
    }
    
    bool remove_document_info(std::vector<uint8_t>& data) {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        void* info_buffer = SecureMemory::allocate_secure_buffer(1024);
        bool removal_success = false;
        
        try {
            removal_success = SecureMemory::remove_document_metadata(data, info_buffer);
            eliminate_all_traces();
        } catch (...) {
            SecureMemory::secure_free(info_buffer);
            eliminate_all_traces();
            structured_exception_handling(std::current_exception());
            return false;
        }
        
        SecureMemory::secure_free(info_buffer);
        eliminate_all_traces();
        return removal_success;
    }
    
    bool remove_xmp_metadata(std::vector<uint8_t>& data) {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        void* xmp_buffer = SecureMemory::allocate_secure_buffer(2048);
        bool removal_success = false;
        
        try {
            removal_success = SecureMemory::remove_xmp_data(data, xmp_buffer);
            eliminate_all_traces();
        } catch (...) {
            SecureMemory::secure_free(xmp_buffer);
            eliminate_all_traces();
            structured_exception_handling(std::current_exception());
            return false;
        }
        
        SecureMemory::secure_free(xmp_buffer);
        eliminate_all_traces();
        return removal_success;
    }
    
    bool remove_timestamps(std::vector<uint8_t>& data) {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        void* timestamp_buffer = SecureMemory::allocate_secure_buffer(512);
        bool removal_success = false;
        
        try {
            removal_success = SecureMemory::remove_timestamp_data(data, timestamp_buffer);
            eliminate_all_traces();
        } catch (...) {
            SecureMemory::secure_free(timestamp_buffer);
            eliminate_all_traces();
            structured_exception_handling(std::current_exception());
            return false;
        }
        
        SecureMemory::secure_free(timestamp_buffer);
        eliminate_all_traces();
        return removal_success;
    }
    
    bool remove_producer_info(std::vector<uint8_t>& data) {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        void* producer_buffer = SecureMemory::allocate_secure_buffer(1024);
        bool removal_success = false;
        
        try {
            removal_success = SecureMemory::remove_producer_data(data, producer_buffer);
            eliminate_all_traces();
        } catch (...) {
            SecureMemory::secure_free(producer_buffer);
            eliminate_all_traces();
            structured_exception_handling(std::current_exception());
            return false;
        }
        
        SecureMemory::secure_free(producer_buffer);
        eliminate_all_traces();
        return removal_success;
    }
    
    bool remove_custom_metadata(std::vector<uint8_t>& data) {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        void* custom_buffer = SecureMemory::allocate_secure_buffer(1536);
        bool removal_success = false;
        
        try {
            removal_success = SecureMemory::remove_custom_metadata_entries(data, custom_buffer);
            eliminate_all_traces();
        } catch (...) {
            SecureMemory::secure_free(custom_buffer);
            eliminate_all_traces();
            structured_exception_handling(std::current_exception());
            return false;
        }
        
        SecureMemory::secure_free(custom_buffer);
        eliminate_all_traces();
        return removal_success;
    }
    
    void perform_deep_clean(std::vector<uint8_t>& pdf_data) {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        void* deep_clean_buffer = SecureMemory::allocate_secure_buffer(pdf_data.size());
        
        try {
            CleaningLevel original_level = cleaning_level_;
            cleaning_level_ = CleaningLevel::COMPLETE;
            
            clean_pdf_metadata(pdf_data);
            remove_embedded_file_metadata(pdf_data);
            remove_form_metadata(pdf_data);
            remove_annotation_metadata(pdf_data);
            
            cleaning_level_ = original_level;
            SecureMemory::secure_vector_operations(pdf_data);
            eliminate_all_traces();
            
        } catch (...) {
            SecureMemory::secure_free(deep_clean_buffer);
            eliminate_all_traces();
            structured_exception_handling(std::current_exception());
        }
        
        SecureMemory::secure_free(deep_clean_buffer);
        eliminate_all_traces();
    }
    
    bool remove_embedded_file_metadata(std::vector<uint8_t>& data) {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        void* embedded_buffer = SecureMemory::allocate_secure_buffer(1024);
        bool removal_success = false;
        
        try {
            removal_success = SecureMemory::remove_embedded_metadata(data, embedded_buffer);
            eliminate_all_traces();
        } catch (...) {
            SecureMemory::secure_free(embedded_buffer);
            eliminate_all_traces();
            structured_exception_handling(std::current_exception());
            return false;
        }
        
        SecureMemory::secure_free(embedded_buffer);
        eliminate_all_traces();
        return removal_success;
    }
    
    bool remove_form_metadata(std::vector<uint8_t>& data) {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        void* form_buffer = SecureMemory::allocate_secure_buffer(512);
        bool removal_success = false;
        
        try {
            removal_success = SecureMemory::remove_form_data(data, form_buffer);
            eliminate_all_traces();
        } catch (...) {
            SecureMemory::secure_free(form_buffer);
            eliminate_all_traces();
            structured_exception_handling(std::current_exception());
            return false;
        }
        
        SecureMemory::secure_free(form_buffer);
        eliminate_all_traces();
        return removal_success;
    }
    
    bool remove_annotation_metadata(std::vector<uint8_t>& data) {
        ENFORCE_COMPLETE_SILENCE();
        SUPPRESS_ALL_TRACES();
        
        void* annotation_buffer = SecureMemory::allocate_secure_buffer(768);
        bool removal_success = false;
        
        try {
            removal_success = SecureMemory::remove_annotation_data(data, annotation_buffer);
            eliminate_all_traces();
        } catch (...) {
            SecureMemory::secure_free(annotation_buffer);
            eliminate_all_traces();
            structured_exception_handling(std::current_exception());
            return false;
        }
        
        SecureMemory::secure_free(annotation_buffer);
        eliminate_all_traces();
        return removal_success;
        try {
            return SecureMemory::secure_vector_operations(pdf_data);
        } catch (...) {
            SECURE_THROW(MetadataCleaningError, "Metadata cleaning failed");
        }
    }
    
    bool remove_document_info(std::string& content) {
        ENFORCE_COMPLETE_SILENCE();
        return SecureMemory::secure_string_operations(content);
    }
    
    bool remove_xmp_metadata(std::string& content) {
        ENFORCE_COMPLETE_SILENCE();
        return SecureMemory::secure_string_operations(content);
    }
    
    bool remove_timestamps(std::string& content) {
        ENFORCE_COMPLETE_SILENCE();
        return SecureMemory::secure_string_operations(content);
    }
    
    bool remove_producer_info(std::string& content) {
        ENFORCE_COMPLETE_SILENCE();
        return SecureMemory::secure_string_operations(content);
    }
    
    bool remove_custom_metadata(std::string& content) {
        ENFORCE_COMPLETE_SILENCE();
        return SecureMemory::secure_string_operations(content);
    }
    
    bool remove_embedded_file_metadata(std::string& content) {
        ENFORCE_COMPLETE_SILENCE();
        return SecureMemory::secure_string_operations(content);
    }
    
    bool remove_form_metadata(std::string& content) {
        ENFORCE_COMPLETE_SILENCE();
        return SecureMemory::secure_string_operations(content);
    }
    
    bool remove_annotation_metadata(std::string& content) {
        ENFORCE_COMPLETE_SILENCE();
        return SecureMemory::secure_string_operations(content);
    }
    
    void set_cleaning_level(CleaningLevel level) {
        ENFORCE_COMPLETE_SILENCE();
        cleaning_level_ = level;
    }
    
    CleaningLevel get_cleaning_level() const {
        return cleaning_level_;
    }
    
    size_t get_cleanup_count() const {
        return cleanup_count_;
    }
    
    void reset_cleanup_count() {
        ENFORCE_COMPLETE_SILENCE();
        cleanup_count_ = 0;
    }
    
    bool is_cleaning_active() const {
        return is_active_;
    }
    
    void perform_deep_clean(std::vector<uint8_t>& pdf_data) {
        ENFORCE_COMPLETE_SILENCE();
        try {
            SecureMemory::secure_vector_operations(pdf_data);
        } catch (...) {
            SECURE_THROW(MetadataCleaningError, "Deep cleaning failed");
        }
    }
    
    static MetadataCleaner& getInstance() {
        ENFORCE_COMPLETE_SILENCE();
        static MetadataCleaner instance;
        return instance;
    }
    
private:
    bool is_active_;
    CleaningLevel cleaning_level_;
    void* secure_buffer_;
    size_t cleanup_count_;
    
    // Enhanced security methods with trace suppression
    void initialize_silent_cleaning() {
        ENFORCE_COMPLETE_SILENCE();
        SecureMemory::initialize_secure_operations();
    }
    
    void eliminate_cleaning_traces() {
        ENFORCE_COMPLETE_SILENCE();
        SecureMemory::eliminate_traces();
    }
    
    void perform_deactivation_cleanup() {
        ENFORCE_COMPLETE_SILENCE();
        secure_memory_cleanup();
    }
    
    void perform_final_cleanup_operations() {
        ENFORCE_COMPLETE_SILENCE();
        eliminate_operation_traces();
    }
    
    bool validate_cleaning_target(const std::vector<uint8_t>& data) {
        ENFORCE_COMPLETE_SILENCE();
        return data.size() > 0;
    }
    
    void secure_content_modification(std::string& content, const std::string& pattern, const std::string& replacement) {
        ENFORCE_COMPLETE_SILENCE();
        try {
            SecureMemory::secure_string_operations(content);
        } catch (...) {
            SECURE_THROW(ContentModificationError, "Content modification failed");
        }
    }
    
    // Secure memory and silent mode enforcement
    void enforce_silent_mode() {
        ENFORCE_COMPLETE_SILENCE();
    }
    
    void secure_memory_cleanup() {
        ENFORCE_COMPLETE_SILENCE();
        if (secure_buffer_) SecureMemory::secure_zero_memory(secure_buffer_, BUFFER_SIZE);
    }
    
    void eliminate_operation_traces() {
        ENFORCE_COMPLETE_SILENCE();
        SecureMemory::eliminate_all_traces();
    }
    
    bool validate_secure_processing(const std::vector<uint8_t>& data) {
        ENFORCE_COMPLETE_SILENCE();
        return data.size() >= 10;
    }
};

#endif // METADATA_CLEANER_HPP