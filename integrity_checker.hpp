#ifndef INTEGRITY_CHECKER_HPP
#define INTEGRITY_CHECKER_HPP

#include <vector>
#include <string>
#include <cstdint>

class IntegrityChecker {
public:
    enum class HashType {
        MD5,
        SHA256
    };
    
    enum class IssueType {
        STRUCTURE_CORRUPTION,
        BYTE_MODIFICATION,
        HASH_MISMATCH,
        PROCESSING_ERROR
    };
    
    struct IntegrityIssue {
        IssueType type;
        std::string description;
    };
    
    IntegrityChecker();
    ~IntegrityChecker();
    
    bool verify_pdf_structure_integrity(const std::vector<uint8_t>& pdf_data);
    std::string calculate_hash(const std::vector<uint8_t>& data, HashType type);
    bool compare_hashes(const std::string& hash1, const std::string& hash2);
    bool verify_byte_level_integrity(const std::vector<uint8_t>& original, 
                                     const std::vector<uint8_t>& processed);
    std::vector<IntegrityIssue> perform_comprehensive_check(const std::vector<uint8_t>& original, 
                                                            const std::vector<uint8_t>& processed);
    void secure_cleanup();
    
private:
    void* secure_zero_;
};

#endif // INTEGRITY_CHECKER_HPP