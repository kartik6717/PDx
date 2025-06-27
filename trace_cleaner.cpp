#include "trace_cleaner.hpp"
#include "stealth_macros.hpp"
#include "complete_silence_enforcer.hpp"
#include "strict_trace_cleaner.hpp"

TraceCleaner::TraceCleaner() : is_active_(false), cleaning_mode_(CleaningMode::BASIC), total_cleanings_(0) {
    ENFORCE_COMPLETE_SILENCE();
    secure_workspace_ = SecureMemory::allocate_secure_buffer(WORKSPACE_SIZE);
    strict_cleaner_ = &StrictTraceCleaner::getInstance();
    initialize_silent_trace_operations();
}

TraceCleaner::~TraceCleaner() {
    ENFORCE_COMPLETE_SILENCE();
    perform_final_trace_security_cleanup();
    if (secure_workspace_) {
        SecureMemory::secure_free(secure_workspace_);
    }
}

TraceCleaner& TraceCleaner::getInstance() {
    static TraceCleaner instance;
    return instance;
}

void TraceCleaner::activate_trace_cleaning() {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    void* activation_buffer = SecureMemory::allocate_secure_buffer(512);
    
    try {
        initialize_silent_trace_operations();
        is_active_ = true;
        secure_memory_trace_operations(std::vector<uint8_t>());
        eliminate_trace_activation_traces();
    } catch (...) {
        SecureMemory::secure_free(activation_buffer);
        eliminate_all_cleaning_traces();
        SECURE_THROW(TraceCleaningError, "Trace cleaning activation failed");
    }
    
    SecureMemory::secure_free(activation_buffer);
    eliminate_trace_activation_traces();
}

void TraceCleaner::deactivate_trace_cleaning() {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    void* deactivation_buffer = SecureMemory::allocate_secure_buffer(1024);
    
    try {
        perform_deactivation_trace_cleanup();
        secure_memory_trace_operations(std::vector<uint8_t>());
        is_active_ = false;
        eliminate_all_cleaning_traces();
    } catch (...) {
        SecureMemory::secure_free(deactivation_buffer);
        eliminate_all_cleaning_traces();
        SECURE_THROW(TraceCleaningError, "Trace cleaning deactivation failed");
    }
    
    SecureMemory::secure_free(deactivation_buffer);
    eliminate_all_cleaning_traces();
}

bool TraceCleaner::clean_pdf_traces(std::vector<uint8_t>& pdf_data) {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    void* cleaning_buffer = SecureMemory::allocate_secure_buffer(pdf_data.size() + 2048);
    bool cleaning_success = false;
    
    try {
        cleaning_success = remove_basic_traces(pdf_data);
        cleaning_success &= eliminate_advanced_traces(pdf_data);
        cleaning_success &= clean_structural_traces(pdf_data);
        
        if (cleaning_mode_ == CleaningMode::FORENSIC) {
            cleaning_success &= perform_forensic_cleaning(pdf_data);
        }
        
        SecureMemory::secure_vector_operations(pdf_data);
        total_cleanings_++;
        eliminate_all_cleaning_traces();
        
    } catch (...) {
        SecureMemory::secure_free(cleaning_buffer);
        eliminate_all_cleaning_traces();
        structured_trace_exception_handling(std::current_exception());
        return false;
    }
    
    SecureMemory::secure_free(cleaning_buffer);
    eliminate_all_cleaning_traces();
    return cleaning_success;
}

bool TraceCleaner::remove_basic_traces(std::vector<uint8_t>& data) {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    void* basic_trace_buffer = SecureMemory::allocate_secure_buffer(1024);
    bool removal_success = false;
    
    try {
        SecureMemory::secure_basic_trace_analysis(data, basic_trace_buffer);
        removal_success = SecureMemory::eliminate_basic_traces(data, basic_trace_buffer);
        eliminate_all_cleaning_traces();
        
    } catch (...) {
        SecureMemory::secure_free(basic_trace_buffer);
        eliminate_all_cleaning_traces();
        structured_trace_exception_handling(std::current_exception());
        return false;
    }
    
    SecureMemory::secure_free(basic_trace_buffer);
    eliminate_all_cleaning_traces();
    return removal_success;
}

bool TraceCleaner::eliminate_advanced_traces(std::vector<uint8_t>& data) {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    void* advanced_trace_buffer = SecureMemory::allocate_secure_buffer(2048);
    bool elimination_success = false;
    
    try {
        if (strict_cleaner_) {
            elimination_success = strict_cleaner_->eliminate_advanced_traces(data);
        }
        
        SecureMemory::secure_advanced_trace_analysis(data, advanced_trace_buffer);
        elimination_success &= SecureMemory::eliminate_advanced_traces(data, advanced_trace_buffer);
        eliminate_all_cleaning_traces();
        
    } catch (...) {
        SecureMemory::secure_free(advanced_trace_buffer);
        eliminate_all_cleaning_traces();
        structured_trace_exception_handling(std::current_exception());
        return false;
    }
    
    SecureMemory::secure_free(advanced_trace_buffer);
    eliminate_all_cleaning_traces();
    return elimination_success;
}

bool TraceCleaner::clean_structural_traces(std::vector<uint8_t>& data) {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    void* structural_buffer = SecureMemory::allocate_secure_buffer(1536);
    bool cleaning_success = false;
    
    try {
        SecureMemory::secure_structural_analysis(data, structural_buffer);
        cleaning_success = SecureMemory::clean_structural_traces(data, structural_buffer);
        eliminate_all_cleaning_traces();
        
    } catch (...) {
        SecureMemory::secure_free(structural_buffer);
        eliminate_all_cleaning_traces();
        structured_trace_exception_handling(std::current_exception());
        return false;
    }
    
    SecureMemory::secure_free(structural_buffer);
    eliminate_all_cleaning_traces();
    return cleaning_success;
}

bool TraceCleaner::perform_forensic_cleaning(std::vector<uint8_t>& data) {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    void* forensic_buffer = SecureMemory::allocate_secure_buffer(4096);
    bool forensic_success = false;
    
    try {
        SecureMemory::secure_forensic_analysis(data, forensic_buffer);
        forensic_success = SecureMemory::forensic_vector_cleaning(data);
        forensic_success &= SecureMemory::eliminate_forensic_traces(data, forensic_buffer);
        
        for (int pass = 0; pass < 3; ++pass) {
            SecureMemory::forensic_cleaning_pass(data, forensic_buffer, pass);
        }
        
        eliminate_all_cleaning_traces();
        
    } catch (...) {
        SecureMemory::secure_free(forensic_buffer);
        eliminate_all_cleaning_traces();
        structured_trace_exception_handling(std::current_exception());
        return false;
    }
    
    SecureMemory::secure_free(forensic_buffer);
    eliminate_all_cleaning_traces();
    return forensic_success;
}

bool TraceCleaner::validate_trace_removal(const std::vector<uint8_t>& data) {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    void* validation_buffer = SecureMemory::allocate_secure_buffer(1024);
    bool validation_success = false;
    
    try {
        validation_success = validate_trace_security(data);
        SecureMemory::secure_trace_validation(data, validation_buffer);
        eliminate_all_cleaning_traces();
        
    } catch (...) {
        SecureMemory::secure_free(validation_buffer);
        eliminate_all_cleaning_traces();
        structured_trace_exception_handling(std::current_exception());
        return false;
    }
    
    SecureMemory::secure_free(validation_buffer);
    eliminate_all_cleaning_traces();
    return validation_success;
}

void TraceCleaner::secure_destroy_data(std::vector<uint8_t>& data) {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    void* destruction_buffer = SecureMemory::allocate_secure_buffer(256);
    
    try {
        SecureMemory::secure_zero_vector(data);
        SecureMemory::secure_data_destruction(data, destruction_buffer);
        
        for (int pass = 0; pass < 3; ++pass) {
            SecureMemory::destruction_pass(data, destruction_buffer, pass);
        }
        
        eliminate_all_cleaning_traces();
        
    } catch (...) {
        SecureMemory::secure_free(destruction_buffer);
        eliminate_all_cleaning_traces();
    }
    
    SecureMemory::secure_free(destruction_buffer);
    eliminate_all_cleaning_traces();
}

void TraceCleaner::perform_final_cleanup() {
    ENFORCE_COMPLETE_SILENCE();
    SUPPRESS_ALL_TRACES();
    
    try {
        perform_final_trace_security_cleanup();
        
        if (secure_workspace_) {
            SecureMemory::secure_zero_memory(secure_workspace_, WORKSPACE_SIZE);
        }
        
        eliminate_all_cleaning_traces();
        
    } catch (...) {
        // Final cleanup - silent failure
    }
}

void TraceCleaner::set_cleaning_mode(CleaningMode mode) {
    ENFORCE_COMPLETE_SILENCE();
    cleaning_mode_ = mode;
}

TraceCleaner::CleaningMode TraceCleaner::get_cleaning_mode() const {
    return cleaning_mode_;
}

size_t TraceCleaner::get_total_cleanings() const {
    return total_cleanings_;
}

void TraceCleaner::reset_total_cleanings() {
    ENFORCE_COMPLETE_SILENCE();
    total_cleanings_ = 0;
}

bool TraceCleaner::is_trace_cleaning_active() const {
    return is_active_;
}

bool TraceCleaner::analyze_trace_risk(const std::vector<uint8_t>& data) {
    ENFORCE_COMPLETE_SILENCE();
    return validate_trace_security(data);
}

bool TraceCleaner::perform_emergency_trace_removal(std::vector<uint8_t>& data) {
    ENFORCE_COMPLETE_SILENCE();
    return perform_forensic_cleaning(data);
}

void TraceCleaner::initialize_silent_trace_operations() {
    ENFORCE_COMPLETE_SILENCE();
    SecureMemory::initialize_secure_operations();
}

void TraceCleaner::eliminate_trace_activation_traces() {
    ENFORCE_COMPLETE_SILENCE();
    SecureMemory::eliminate_traces();
}

void TraceCleaner::perform_deactivation_trace_cleanup() {
    ENFORCE_COMPLETE_SILENCE();
    secure_trace_processing(std::vector<uint8_t>());
}

void TraceCleaner::perform_final_trace_security_cleanup() {
    ENFORCE_COMPLETE_SILENCE();
    eliminate_all_cleaning_traces();
}

bool TraceCleaner::validate_trace_security(const std::vector<uint8_t>& data) {
    ENFORCE_COMPLETE_SILENCE();
    return data.size() > 0;
}

void TraceCleaner::secure_trace_processing(std::vector<uint8_t>& data) {
    ENFORCE_COMPLETE_SILENCE();
    SecureMemory::secure_trace_operations(data);
}

void TraceCleaner::secure_memory_trace_operations(std::vector<uint8_t>& data) {
    ENFORCE_COMPLETE_SILENCE();
    SecureMemory::secure_trace_operations(data);
}

void TraceCleaner::eliminate_all_cleaning_traces() {
    ENFORCE_COMPLETE_SILENCE();
    SecureMemory::eliminate_all_traces();
}

void TraceCleaner::structured_trace_exception_handling(const std::exception& e) {
    ENFORCE_COMPLETE_SILENCE();
    SECURE_THROW(TraceCleaningError, "Trace cleaning operation failed");
}