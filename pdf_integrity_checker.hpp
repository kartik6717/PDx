#ifndef PDF_INTEGRITY_CHECKER_HPP
#define PDF_INTEGRITY_CHECKER_HPP

#include <vector>
#include <string>
#include <cstdint>
#include <cstddef>

class PDFIntegrityChecker {
public:
    enum class HashAlgorithm {
        MD5,
        SHA256
    };
    
    struct IntegrityReport {
        bool structure_valid;
        bool byte_fidelity_valid;
        bool hash_consistent;
        bool content_integrity_valid;
        bool overall_integrity;
        std::vector<std::string> issues;
        std::string original_checksum;
        std::string processed_checksum;
    };
    
    static constexpr size_t WORKSPACE_SIZE = 8192;
    
    PDFIntegrityChecker();
    ~PDFIntegrityChecker();
    
    void activate_checking();
    void deactivate_checking();
    bool verify_pdf_structure(const std::vector<uint8_t>& pdf_data);
    bool verify_byte_fidelity(const std::vector<uint8_t>& original, 
                              const std::vector<uint8_t>& processed);
    std::string calculate_content_hash(const std::vector<uint8_t>& data, 
                                       HashAlgorithm algorithm);
    bool verify_hash_consistency(const std::vector<uint8_t>& original, 
                                 const std::vector<uint8_t>& processed);
    IntegrityReport perform_comprehensive_check(const std::vector<uint8_t>& original, 
                                                const std::vector<uint8_t>& processed);
    bool verify_pdf_header(const std::string& content);
    bool verify_eof_marker(const std::string& content);
    bool verify_xref_table(const std::string& content);
    bool verify_trailer(const std::string& content);
    bool verify_object_structure(const std::string& content);
    bool verify_safe_append_zone(const std::vector<uint8_t>& original, 
                                 const std::vector<uint8_t>& processed);
    bool verify_content_integrity(const std::vector<uint8_t>& pdf_data);
    void record_integrity_issue(const std::string& issue);
    void clear_integrity_issues();
    std::vector<std::string> get_integrity_issues() const;
    void set_strict_mode(bool strict);
    bool is_strict_mode() const;
    size_t get_check_count() const;
    void reset_check_count();
    bool is_checking_active() const;
    
    static PDFIntegrityChecker& getInstance();
    
private:
    bool is_active_;
    bool strict_mode_;
    void* secure_workspace_;
    std::vector<std::string> integrity_issues_;
    size_t check_count_;
};

#endif // PDF_INTEGRITY_CHECKER_HPP