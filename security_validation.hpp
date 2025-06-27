#pragma once

#include "logger.hpp"
#include "error_handler.hpp"
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <memory>
#include <functional>
#include <atomic>
#include <thread>

// Security validation framework for comprehensive security testing
// This framework validates all security features implemented in the PDF scrubber

namespace SecurityValidation {

// Test severity levels
enum class TestSeverity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

// Test categories
enum class TestCategory {
    INPUT_VALIDATION,
    MEMORY_SAFETY,
    BUFFER_OVERFLOW,
    INJECTION_ATTACKS,
    DOS_ATTACKS,
    PRIVILEGE_ESCALATION,
    INFORMATION_DISCLOSURE,
    FORENSIC_EVASION,
    ENCRYPTION_VALIDATION,
    CONFIGURATION_SECURITY,
    SYSTEM_HARDENING,
    COMPLIANCE_VALIDATION
};

// Test result status
enum class TestResult {
    PASS,
    FAIL,
    WARNING,
    SKIP,
    ERROR
};

// Individual security test result
struct SecurityTestResult {
    std::string test_id;
    std::string test_name;
    std::string description;
    TestCategory category;
    TestSeverity severity;
    TestResult result;
    std::string details;
    std::string remediation;
    std::chrono::milliseconds execution_time;
    std::map<std::string, std::string> metadata;
    std::vector<std::string> evidence;
    std::chrono::system_clock::time_point timestamp;
};

// Security test suite results
struct SecurityTestSuite {
    std::string suite_name;
    std::string version;
    std::vector<SecurityTestResult> test_results;
    size_t total_tests;
    size_t passed_tests;
    size_t failed_tests;
    size_t warning_tests;
    size_t skipped_tests;
    std::chrono::milliseconds total_execution_time;
    std::chrono::system_clock::time_point execution_timestamp;
};

// Penetration testing attack vectors
enum class AttackVector {
    MALFORMED_PDF,
    OVERSIZED_INPUT,
    RECURSIVE_BOMBS,
    MEMORY_EXHAUSTION,
    INFINITE_LOOPS,
    BUFFER_OVERFLOW,
    FORMAT_STRING,
    INTEGER_OVERFLOW,
    NULL_POINTER,
    USE_AFTER_FREE,
    DOUBLE_FREE,
    HEAP_CORRUPTION,
    STACK_SMASHING,
    ROP_GADGETS,
    JAVASCRIPT_INJECTION,
    METADATA_INJECTION,
    COMPRESSION_BOMBS,
    NESTED_ARCHIVES,
    SYMBOLIC_LINKS,
    RACE_CONDITIONS
};

// Security vulnerability assessment
struct VulnerabilityAssessment {
    std::string vulnerability_id;
    std::string title;
    std::string description;
    TestSeverity severity;
    std::vector<std::string> affected_components;
    std::vector<std::string> attack_vectors;
    std::string proof_of_concept;
    std::string impact_assessment;
    std::string remediation_steps;
    bool exploitable;
    double cvss_score;
    std::string cvss_vector;
};

// Forensic tool validation
enum class ForensicTool {
    EXIFTOOL,
    PEEPDF,
    PDF_PARSER,
    PDFID,
    PDFTK,
    QPDF,
    ORIGAMI,
    PEFRAME,
    YARA,
    BINWALK,
    STRINGS,
    HEXDUMP,
    VOLATILITY,
    AUTOPSY,
    SLEUTHKIT
};

struct ForensicTestResult {
    ForensicTool tool;
    std::string tool_version;
    std::string test_file;
    bool detection_bypassed;
    std::string tool_output;
    std::string analysis_notes;
    std::vector<std::string> artifacts_found;
    bool successful_evasion;
};

// Compliance framework testing
enum class ComplianceFramework {
    GDPR,
    HIPAA,
    SOX,
    PCI_DSS,
    ISO27001,
    NIST_CYBERSECURITY,
    COMMON_CRITERIA,
    FIPS_140_2,
    CC_EAL4
};

struct ComplianceTestResult {
    ComplianceFramework framework;
    std::string requirement_id;
    std::string requirement_description;
    TestResult compliance_status;
    std::string evidence;
    std::string gaps_identified;
    std::string remediation_required;
};

// Base security test interface
class SecurityTest {
public:
    virtual ~SecurityTest() = default;
    
    virtual std::string get_test_id() const = 0;
    virtual std::string get_test_name() const = 0;
    virtual std::string get_description() const = 0;
    virtual TestCategory get_category() const = 0;
    virtual TestSeverity get_severity() const = 0;
    
    virtual SecurityTestResult execute() = 0;
    virtual bool setup() { return true; }
    virtual void cleanup() {}
    
protected:
    SecurityTestResult create_result(TestResult result, const std::string& details = "",
                                   const std::string& remediation = "");
    void add_evidence(SecurityTestResult& result, const std::string& evidence);
    void set_metadata(SecurityTestResult& result, const std::string& key, const std::string& value);
};

// Penetration testing engine
class PenetrationTestEngine {
public:
    PenetrationTestEngine();
    ~PenetrationTestEngine();
    
    // Attack vector testing
    SecurityTestSuite run_attack_vector_tests();
    SecurityTestResult test_malformed_pdf_handling();
    SecurityTestResult test_memory_exhaustion_attacks();
    SecurityTestResult test_buffer_overflow_attacks();
    SecurityTestResult test_compression_bomb_attacks();
    SecurityTestResult test_recursive_bomb_attacks();
    SecurityTestResult test_integer_overflow_attacks();
    SecurityTestResult test_format_string_attacks();
    SecurityTestResult test_injection_attacks();
    SecurityTestResult test_race_condition_attacks();
    SecurityTestResult test_privilege_escalation();
    
    // Fuzzing tests
    SecurityTestSuite run_fuzzing_tests(size_t iterations = 10000);
    SecurityTestResult fuzz_pdf_parser(const std::vector<uint8_t>& seed_data);
    SecurityTestResult fuzz_configuration_parser(const std::string& config_data);
    SecurityTestResult fuzz_command_line_interface(const std::vector<std::string>& args);
    
    // Load testing
    SecurityTestSuite run_load_tests();
    SecurityTestResult test_concurrent_processing();
    SecurityTestResult test_resource_exhaustion();
    SecurityTestResult test_denial_of_service();
    
    // Generate attack payloads
    std::vector<uint8_t> generate_malformed_pdf();
    std::vector<uint8_t> generate_compression_bomb();
    std::vector<uint8_t> generate_recursive_pdf();
    std::vector<uint8_t> generate_oversized_pdf();
    std::string generate_format_string_payload();
    std::string generate_injection_payload();

private:
    void initialize_attack_vectors();
    void setup_test_environment();
    void cleanup_test_environment();
    
    std::map<AttackVector, std::function<SecurityTestResult()>> attack_tests_;
    std::string test_directory_;
    std::atomic<bool> stop_testing_;
};

// Forensic validation engine
class ForensicValidationEngine {
public:
    ForensicValidationEngine();
    ~ForensicValidationEngine();
    
    // Tool-specific validation
    std::vector<ForensicTestResult> validate_against_all_tools();
    ForensicTestResult validate_against_exiftool(const std::string& test_file);
    ForensicTestResult validate_against_peepdf(const std::string& test_file);
    ForensicTestResult validate_against_pdfid(const std::string& test_file);
    ForensicTestResult validate_against_yara(const std::string& test_file);
    ForensicTestResult validate_against_binwalk(const std::string& test_file);
    
    // Evasion effectiveness testing
    SecurityTestSuite test_metadata_scrubbing_effectiveness();
    SecurityTestSuite test_entropy_shaping_effectiveness();
    SecurityTestSuite test_anti_forensic_effectiveness();
    SecurityTestSuite test_fingerprint_removal_effectiveness();
    
    // Generate test files for validation
    void generate_test_pdfs_with_artifacts();
    void create_pdf_with_metadata();
    void create_pdf_with_javascript();
    void create_pdf_with_embedded_files();
    void create_pdf_with_forms();
    void create_pdf_with_signatures();
    
private:
    bool is_tool_available(ForensicTool tool);
    std::string get_tool_command(ForensicTool tool);
    std::string get_tool_version(ForensicTool tool);
    std::string execute_tool(ForensicTool tool, const std::string& file_path);
    void analyze_tool_output(const std::string& output, ForensicTestResult& result);
    
    std::map<ForensicTool, std::string> tool_paths_;
    std::string test_files_directory_;
};

// Compliance validation engine
class ComplianceValidationEngine {
public:
    ComplianceValidationEngine();
    ~ComplianceValidationEngine();
    
    // Framework-specific validation
    std::vector<ComplianceTestResult> validate_gdpr_compliance();
    std::vector<ComplianceTestResult> validate_hipaa_compliance();
    std::vector<ComplianceTestResult> validate_sox_compliance();
    std::vector<ComplianceTestResult> validate_pci_dss_compliance();
    std::vector<ComplianceTestResult> validate_iso27001_compliance();
    std::vector<ComplianceTestResult> validate_nist_compliance();
    std::vector<ComplianceTestResult> validate_common_criteria();
    std::vector<ComplianceTestResult> validate_fips_140_2();
    
    // Cross-framework validation
    SecurityTestSuite run_all_compliance_tests();
    
    // Audit report generation
    std::string generate_compliance_report(const std::vector<ComplianceTestResult>& results);
    std::string generate_gap_analysis(const std::vector<ComplianceTestResult>& results);
    std::string generate_remediation_plan(const std::vector<ComplianceTestResult>& results);

private:
    ComplianceTestResult test_data_protection_requirements();
    ComplianceTestResult test_access_control_requirements();
    ComplianceTestResult test_audit_logging_requirements();
    ComplianceTestResult test_encryption_requirements();
    ComplianceTestResult test_incident_response_requirements();
    ComplianceTestResult test_vulnerability_management();
    ComplianceTestResult test_secure_configuration();
    
    std::map<ComplianceFramework, std::vector<std::string>> framework_requirements_;
};

// Main security validation coordinator
class SecurityValidationCoordinator {
public:
    static SecurityValidationCoordinator& getInstance();
    
    // Run comprehensive security validation
    SecurityTestSuite run_full_security_validation();
    SecurityTestSuite run_penetration_tests();
    SecurityTestSuite run_forensic_validation();
    SecurityTestSuite run_compliance_validation();
    
    // Real-world attack scenario testing
    SecurityTestSuite run_attack_scenarios();
    SecurityTestResult simulate_targeted_attack();
    SecurityTestResult simulate_insider_threat();
    SecurityTestResult simulate_supply_chain_attack();
    SecurityTestResult simulate_advanced_persistent_threat();
    
    // Vulnerability assessment
    std::vector<VulnerabilityAssessment> conduct_vulnerability_assessment();
    VulnerabilityAssessment assess_input_validation_vulnerabilities();
    VulnerabilityAssessment assess_memory_safety_vulnerabilities();
    VulnerabilityAssessment assess_cryptographic_vulnerabilities();
    VulnerabilityAssessment assess_configuration_vulnerabilities();
    
    // Security metrics and scoring
    double calculate_security_score(const SecurityTestSuite& results);
    std::string generate_security_scorecard(const SecurityTestSuite& results);
    std::string generate_risk_assessment(const std::vector<VulnerabilityAssessment>& vulnerabilities);
    
    // Reporting
    std::string generate_comprehensive_security_report();
    std::string generate_executive_summary();
    std::string generate_technical_findings();
    std::string generate_remediation_roadmap();
    
    // Configuration
    void set_test_configuration(const std::map<std::string, std::string>& config);
    void enable_verbose_logging(bool enable);
    void set_output_directory(const std::string& directory);

private:
    SecurityValidationCoordinator();
    ~SecurityValidationCoordinator();
    
    // Disable copy/move
    SecurityValidationCoordinator(const SecurityValidationCoordinator&) = delete;
    SecurityValidationCoordinator& operator=(const SecurityValidationCoordinator&) = delete;
    
    void initialize_validation_environment();
    void setup_test_data();
    void cleanup_test_environment();
    
    std::unique_ptr<PenetrationTestEngine> penetration_engine_;
    std::unique_ptr<ForensicValidationEngine> forensic_engine_;
    std::unique_ptr<ComplianceValidationEngine> compliance_engine_;
    
    std::string output_directory_;
    bool verbose_logging_;
    std::map<std::string, std::string> test_configuration_;
    
    mutable std::mutex validation_mutex_;
};

// Security test registry for custom tests
class SecurityTestRegistry {
public:
    static SecurityTestRegistry& getInstance();
    
    void register_test(std::unique_ptr<SecurityTest> test);
    void register_test_suite(const std::string& suite_name, std::vector<std::unique_ptr<SecurityTest>> tests);
    
    SecurityTestSuite run_registered_tests(const std::string& suite_name = "");
    std::vector<std::string> get_available_test_suites();
    
private:
    std::map<std::string, std::vector<std::unique_ptr<SecurityTest>>> test_suites_;
    mutable std::mutex registry_mutex_;
};

// Utility functions
std::string to_string(TestSeverity severity);
std::string to_string(TestCategory category);
std::string to_string(TestResult result);
std::string to_string(AttackVector vector);
std::string to_string(ForensicTool tool);
std::string to_string(ComplianceFramework framework);

double calculate_cvss_score(const std::string& cvss_vector);
std::string severity_to_color(TestSeverity severity);
std::string generate_test_report_html(const SecurityTestSuite& results);
std::string generate_test_report_json(const SecurityTestSuite& results);
std::string generate_test_report_xml(const SecurityTestSuite& results);

// Macros for test implementation
#define SECURITY_TEST_CLASS(TestName, Category, Severity) \
    class TestName : public SecurityTest { \
    public: \
        std::string get_test_id() const override { return #TestName; } \
        std::string get_test_name() const override { return #TestName; } \
        TestCategory get_category() const override { return Category; } \
        TestSeverity get_severity() const override { return Severity; } \
        SecurityTestResult execute() override; \
        std::string get_description() const override; \
    }

#define IMPLEMENT_SECURITY_TEST(TestName) \
    SecurityTestResult TestName::execute()

#define IMPLEMENT_TEST_DESCRIPTION(TestName, Description) \
    std::string TestName::get_description() const { return Description; }

#define ASSERT_SECURITY(condition, message) \
    if (!(condition)) { \
        return create_result(TestResult::FAIL, message, "Fix the security vulnerability"); \
    }

#define ASSERT_SECURITY_WARNING(condition, message) \
    if (!(condition)) { \
        return create_result(TestResult::WARNING, message, "Consider addressing this security concern"); \
    }

} // namespace SecurityValidation
