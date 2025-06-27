cmake_minimum_required(VERSION 3.16)
project(PDFScrubber 
    VERSION 1.0.0
    DESCRIPTION "Advanced PDF Scrubbing and Forensic Analysis Tool"
    LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set build type default
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler-specific options
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# Platform-specific settings
if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
endif()

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

# Find OpenSSL
find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND)
    message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
else()
    message(FATAL_ERROR "OpenSSL not found")
endif()

# Find zlib (optional for better compatibility)
find_package(ZLIB QUIET)
if(ZLIB_FOUND)
    message(STATUS "ZLIB found: ${ZLIB_VERSION_STRING}")
    set(ZLIB_LIBRARIES ${ZLIB_LIBRARIES})
else()
    message(STATUS "ZLIB not found - using system libraries")
    set(ZLIB_LIBRARIES "z")
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${ZLIB_INCLUDE_DIRS})

# Security compiler flags
set(SECURITY_FLAGS "")
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(SECURITY_FLAGS 
        "-fstack-protector-strong"
        "-D_FORTIFY_SOURCE=2"
        "-fPIE"
        "-Wl,-z,relro"
        "-Wl,-z,now"
        "-Wformat"
        "-Wformat-security"
        "-Werror=format-security"
        "-fno-delete-null-pointer-checks"
        "-fwrapv"
    )
endif()

# Add security flags to compilation
add_compile_options(${SECURITY_FLAGS})

# Define source files for each module
set(UTILS_SOURCES
    utils.cpp
    utils.hpp
)

# Add silent operation source files
set(SILENT_OPERATION_SOURCES
    silent_operation_manager.cpp
    silent_error_handler.cpp
    silent_status_tracker.cpp
    stream_suppression.cpp
    library_silence_config.cpp
)

set(PDF_PARSER_SOURCES
    pdf_parser.cpp
    pdf_parser.hpp
)

set(ENTROPY_SHAPER_SOURCES
    entropy_shaper.cpp
    entropy_shaper.hpp
)

set(SCRUBBER_SOURCES
    scrubber.cpp
    scrubber.hpp
)

set(ENCRYPTOR_SOURCES
    encryptor.cpp
    encryptor.hpp
)

set(FORENSIC_VALIDATOR_SOURCES
    forensic_validator.cpp
    forensic_validator.hpp
)

set(CONFIG_MANAGER_SOURCES
    config_manager.cpp
    config_manager.hpp
    config_integration.hpp
)

set(CACHE_MANAGER_SOURCES
    cache_manager.cpp
    cache_manager.hpp
)

set(CLONER_SOURCES
    cloner.cpp
    cloner.hpp
)

set(ANTI_FINGERPRINT_SOURCES
    anti_fingerprint_engine.cpp
    anti_fingerprint_engine.hpp
)

# SECURITY FIX: Add new security modules
set(SECURE_MEMORY_SOURCES
    secure_memory.cpp
    secure_memory.hpp
)

set(SECURE_EXCEPTIONS_SOURCES
    secure_exceptions.cpp
    secure_exceptions.hpp
)

set(MISSING_METHOD_IMPLEMENTATIONS_SOURCES
    missing_method_implementations.cpp
)

set(FINAL_SECURITY_IMPLEMENTATIONS_SOURCES
    final_security_implementations.hpp
)

# Create static libraries for each module
add_library(SilentOperation STATIC ${SILENT_OPERATION_SOURCES})
target_link_libraries(SilentOperation Threads::Threads)

add_library(PDFUtils STATIC ${UTILS_SOURCES})
target_link_libraries(PDFUtils ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARIES})

add_library(PDFParser STATIC ${PDF_PARSER_SOURCES})
target_link_libraries(PDFParser PDFUtils ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARIES} Threads::Threads)

add_library(EntropyShaper STATIC ${ENTROPY_SHAPER_SOURCES})
target_link_libraries(EntropyShaper PDFUtils Threads::Threads)

add_library(PDFScrubberLib STATIC ${SCRUBBER_SOURCES})
target_link_libraries(PDFScrubberLib PDFUtils PDFParser EntropyShaper)

add_library(Encryptor STATIC ${ENCRYPTOR_SOURCES})
target_link_libraries(Encryptor PDFUtils ${OPENSSL_LIBRARIES})

add_library(ForensicValidator STATIC ${FORENSIC_VALIDATOR_SOURCES})
target_link_libraries(ForensicValidator PDFUtils PDFParser)

add_library(ConfigManager STATIC ${CONFIG_MANAGER_SOURCES})
target_link_libraries(ConfigManager PDFUtils ${OPENSSL_LIBRARIES})

# Add nlohmann_json for JSON configuration support
find_package(nlohmann_json QUIET)
if(nlohmann_json_FOUND)
    target_link_libraries(ConfigManager nlohmann_json::nlohmann_json)
else()
    # Fallback: add nlohmann json as header-only
    target_include_directories(ConfigManager PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third_party)
endif()

add_library(CacheManager STATIC ${CACHE_MANAGER_SOURCES})
target_link_libraries(CacheManager PDFUtils ${OPENSSL_LIBRARIES})

add_library(Cloner STATIC ${CLONER_SOURCES})
target_link_libraries(Cloner PDFUtils PDFParser EntropyShaper)

add_library(AntiFingerprintEngine STATIC ${ANTI_FINGERPRINT_SOURCES})
target_link_libraries(AntiFingerprintEngine PDFUtils ${OPENSSL_LIBRARIES})

# SECURITY FIX: Add security libraries
add_library(SecureMemory STATIC ${SECURE_MEMORY_SOURCES})
target_link_libraries(SecureMemory Threads::Threads)

add_library(SecureExceptions STATIC ${SECURE_EXCEPTIONS_SOURCES})
target_link_libraries(SecureExceptions SecureMemory)

add_library(MissingMethodImplementations STATIC ${MISSING_METHOD_IMPLEMENTATIONS_SOURCES})
target_link_libraries(MissingMethodImplementations SecureMemory SecureExceptions)

# Define all security component sources first
set(STEALTH_SCRUBBER_SOURCES
    stealth_scrubber.cpp
    stealth_scrubber.hpp
)

set(MEMORY_GUARD_SOURCES
    memory_guard.cpp
    memory_guard.hpp
)

set(MEMORY_SANITIZER_SOURCES
    memory_sanitizer.cpp
    memory_sanitizer.hpp
)

set(METADATA_CLEANER_SOURCES
    metadata_cleaner.cpp
    metadata_cleaner.hpp
)

set(PDF_INTEGRITY_CHECKER_SOURCES
    pdf_integrity_checker.cpp
    pdf_integrity_checker.hpp
)

set(SECURITY_VALIDATION_SOURCES
    security_validation.cpp
    security_validation.hpp
)

set(STRICT_TRACE_CLEANER_SOURCES
    strict_trace_cleaner.cpp
    strict_trace_cleaner.hpp
)

set(TRACE_CLEANER_SOURCES
    trace_cleaner.cpp
    trace_cleaner.hpp
)

set(LIGHTWEIGHT_MEMORY_SCRUBBER_SOURCES
    lightweight_memory_scrubber.cpp
    lightweight_memory_scrubber.hpp
)

set(MONITORING_WEB_SERVER_SOURCES
    monitoring_web_server.cpp
    monitoring_web_server.hpp
)

set(FORMAT_MIGRATION_MANAGER_SOURCES
    format_migration_manager.cpp
    format_migration_manager.hpp
)

set(FORMAT_VALIDATION_ENGINE_SOURCES
    format_validation_engine.cpp
    format_validation_engine.hpp
)

set(INTEGRITY_CHECKER_SOURCES
    integrity_checker.cpp
    integrity_checker.hpp
)

# Header-only security enforcement components
set(SILENCE_ENFORCER_HEADERS
    complete_output_suppressor.hpp
    complete_silence_enforcer.hpp
    global_silence_enforcer.hpp
    lightweight_trace_suppressor.hpp
    silent_operation_manager.hpp
    pdf_version_converter.hpp
)

set(TRACE_CLEANER_SOURCES
    trace_cleaner.cpp
    trace_cleaner.hpp
)

set(STRICT_TRACE_CLEANER_SOURCES
    strict_trace_cleaner.cpp
    strict_trace_cleaner.hpp
)

set(METADATA_CLEANER_SOURCES
    metadata_cleaner.cpp
    metadata_cleaner.hpp
)

set(MEMORY_GUARD_SOURCES
    memory_guard.cpp
    memory_guard.hpp
)

set(MEMORY_SANITIZER_SOURCES
    memory_sanitizer.cpp
    memory_sanitizer.hpp
)

set(LIGHTWEIGHT_MEMORY_SCRUBBER_SOURCES
    lightweight_memory_scrubber.cpp
    lightweight_memory_scrubber.hpp
)

set(PDF_INTEGRITY_CHECKER_SOURCES
    pdf_integrity_checker.cpp
    pdf_integrity_checker.hpp
)

set(INTEGRITY_CHECKER_SOURCES
    integrity_checker.cpp
    integrity_checker.hpp
)

set(SECURITY_VALIDATION_SOURCES
    security_validation.cpp
    security_validation.hpp
)

# Additional security libraries already defined above

# Define source files for new components
set(THREAT_INTELLIGENCE_SOURCES
    threat_intelligence_engine.cpp
    threat_intelligence_engine.hpp
)

set(BINARY_SIGNATURE_CAMOUFLAGE_SOURCES
    binary_signature_camouflage.cpp
    binary_signature_camouflage.hpp
)

set(FORENSIC_EVASION_SOURCES
    comprehensive_forensic_evasion.cpp
    comprehensive_forensic_evasion.hpp
)

set(PRODUCTION_API_SOURCES
    production_api_layer.cpp
    production_api_layer.hpp
)

set(SOURCE_FORMAT_PRESERVATION_SOURCES
    source_format_preservation.cpp
    source_format_preservation.hpp
)

set(ZERO_TRACE_PROCESSOR_SOURCES
    zero_trace_processor.cpp
    zero_trace_processor.hpp
)

# MISSING LIBRARY SOURCES - Integration Fix
set(ML_EVASION_ENGINE_SOURCES
    ml_evasion_engine.cpp
    ml_evasion_engine.hpp
)

set(DOCUMENT_LIFECYCLE_SIMULATOR_SOURCES
    document_lifecycle_simulator.cpp
    document_lifecycle_simulator.hpp
)

set(PROFESSIONAL_METADATA_ENGINE_SOURCES
    professional_metadata_engine.cpp
    professional_metadata_engine.hpp
)

set(STATISTICAL_PATTERN_MASKER_SOURCES
    statistical_pattern_masker.cpp
    statistical_pattern_masker.hpp
)

set(ADVANCED_PATTERN_RECOGNIZER_SOURCES
    advanced_pattern_recognizer.cpp
    advanced_pattern_recognizer.hpp
)

set(PDF_VERSION_CONVERTER_SOURCES
    pdf_version_converter.cpp
    pdf_version_converter.hpp
)

set(FORMAT_MIGRATION_MANAGER_SOURCES
    format_migration_manager.cpp
    format_migration_manager.hpp
)

set(ENTROPY_ANALYSIS_SOURCES
    entropy_analysis.cpp
    entropy_analysis.hpp
)

set(PERFORMANCE_OPTIMIZER_SOURCES
    performance_optimizer.cpp
    performance_optimizer.hpp
)

set(TEMPORAL_CONSISTENCY_MANAGER_SOURCES
    temporal_consistency_manager.cpp
    temporal_consistency_manager.hpp
)

set(FORMAT_VALIDATION_ENGINE_SOURCES
    format_validation_engine.cpp
    format_validation_engine.hpp
)

set(PDF_BYTE_FIDELITY_PROCESSOR_SOURCES
    pdf_byte_fidelity_processor.cpp
    pdf_byte_fidelity_processor.hpp
)

# Add new static libraries
add_library(ThreatIntelligence STATIC ${THREAT_INTELLIGENCE_SOURCES})
target_link_libraries(ThreatIntelligence PDFUtils Threads::Threads)

add_library(ForensicEvasion STATIC ${FORENSIC_EVASION_SOURCES})
target_link_libraries(ForensicEvasion PDFUtils Threads::Threads)

add_library(ProductionAPI STATIC ${PRODUCTION_API_SOURCES})
target_link_libraries(ProductionAPI PDFUtils Threads::Threads)

add_library(SourceFormatPreservation STATIC ${SOURCE_FORMAT_PRESERVATION_SOURCES})
target_link_libraries(SourceFormatPreservation PDFUtils)

add_library(ZeroTraceProcessor STATIC ${ZERO_TRACE_PROCESSOR_SOURCES})
target_link_libraries(ZeroTraceProcessor PDFUtils)

# MISSING LIBRARY DEFINITIONS - Integration Fix
add_library(EntropyAnalysis STATIC ${ENTROPY_ANALYSIS_SOURCES})
target_link_libraries(EntropyAnalysis PDFUtils)

add_library(MLEvasionEngine STATIC ${ML_EVASION_ENGINE_SOURCES})
target_link_libraries(MLEvasionEngine EntropyAnalysis ForensicValidator PDFUtils)

add_library(DocumentLifecycleSimulator STATIC ${DOCUMENT_LIFECYCLE_SIMULATOR_SOURCES})
target_link_libraries(DocumentLifecycleSimulator ProfessionalMetadataEngine PDFUtils)

add_library(ProfessionalMetadataEngine STATIC ${PROFESSIONAL_METADATA_ENGINE_SOURCES})
target_link_libraries(ProfessionalMetadataEngine AntiFingerprintEngine PDFUtils)

add_library(StatisticalPatternMasker STATIC ${STATISTICAL_PATTERN_MASKER_SOURCES})
target_link_libraries(StatisticalPatternMasker EntropyShaper PDFUtils)

add_library(AdvancedPatternRecognizer STATIC ${ADVANCED_PATTERN_RECOGNIZER_SOURCES})
target_link_libraries(AdvancedPatternRecognizer ForensicValidator PDFUtils)

add_library(PDFVersionConverter STATIC ${PDF_VERSION_CONVERTER_SOURCES})
target_link_libraries(PDFVersionConverter PDFParser PDFUtils)

# FormatMigrationManager already defined above

add_library(PerformanceOptimizer STATIC ${PERFORMANCE_OPTIMIZER_SOURCES})
target_link_libraries(PerformanceOptimizer PDFUtils Threads::Threads)

add_library(TemporalConsistencyManager STATIC ${TEMPORAL_CONSISTENCY_MANAGER_SOURCES})
target_link_libraries(TemporalConsistencyManager PDFUtils)

# FormatValidationEngine already defined above

add_library(PDFByteFidelityProcessor STATIC ${PDF_BYTE_FIDELITY_PROCESSOR_SOURCES})
target_link_libraries(PDFByteFidelityProcessor 
    SourceFormatPreservation 
    FormatValidationEngine 
    DocumentLifecycleSimulator 
    ProfessionalMetadataEngine 
    StatisticalPatternMasker 
    MLEvasionEngine 
    ZeroTraceProcessor 
    TemporalConsistencyManager 
    PerformanceOptimizer 
    AdvancedPatternRecognizer 
    FormatMigrationManager 
    PDFUtils)

# Add silent operation source files
set(SILENT_OPERATION_SOURCES
    silent_operation_manager.cpp
    silent_error_handler.cpp
    silent_status_tracker.cpp
    stream_suppression.cpp
    library_silence_config.cpp
)

# Create all security component libraries
add_library(StealthScrubber STATIC ${STEALTH_SCRUBBER_SOURCES})
target_link_libraries(StealthScrubber SecureMemory SecureExceptions ${OPENSSL_LIBRARIES})

add_library(MemoryGuard STATIC ${MEMORY_GUARD_SOURCES})
target_link_libraries(MemoryGuard SecureMemory SecureExceptions)

add_library(MemorySanitizer STATIC ${MEMORY_SANITIZER_SOURCES})
target_link_libraries(MemorySanitizer SecureMemory SecureExceptions)

add_library(MetadataCleaner STATIC ${METADATA_CLEANER_SOURCES})
target_link_libraries(MetadataCleaner SecureMemory SecureExceptions)

add_library(PDFIntegrityChecker STATIC ${PDF_INTEGRITY_CHECKER_SOURCES})
target_link_libraries(PDFIntegrityChecker SecureMemory SecureExceptions ${OPENSSL_LIBRARIES})

add_library(SecurityValidation STATIC ${SECURITY_VALIDATION_SOURCES})
target_link_libraries(SecurityValidation SecureMemory SecureExceptions PDFParser)

add_library(StrictTraceCleaner STATIC ${STRICT_TRACE_CLEANER_SOURCES})
target_link_libraries(StrictTraceCleaner SecureMemory SecureExceptions)

add_library(TraceCleaner STATIC ${TRACE_CLEANER_SOURCES})
target_link_libraries(TraceCleaner SecureMemory SecureExceptions StrictTraceCleaner)

add_library(LightweightMemoryScrubber STATIC ${LIGHTWEIGHT_MEMORY_SCRUBBER_SOURCES})
target_link_libraries(LightweightMemoryScrubber SecureMemory SecureExceptions)

add_library(MonitoringWebServer STATIC ${MONITORING_WEB_SERVER_SOURCES})
target_link_libraries(MonitoringWebServer SecureMemory SecureExceptions)

add_library(FormatMigrationManager STATIC ${FORMAT_MIGRATION_MANAGER_SOURCES})
target_link_libraries(FormatMigrationManager SecureMemory SecureExceptions PDFParser)

add_library(FormatValidationEngine STATIC ${FORMAT_VALIDATION_ENGINE_SOURCES})
target_link_libraries(FormatValidationEngine SecureMemory SecureExceptions PDFParser)

add_library(IntegrityChecker STATIC ${INTEGRITY_CHECKER_SOURCES})
target_link_libraries(IntegrityChecker SecureMemory SecureExceptions ${OPENSSL_LIBRARIES})

# Create silent operation library
add_library(silent_operation STATIC ${SILENT_OPERATION_SOURCES})

# Main executable
add_executable(pdfscrubber main.cpp)
target_link_libraries(pdfscrubber 
    SilentOperation
    PDFScrubberLib
    PDFParser
    EntropyShaper
    SecureMemory
    SecureExceptions
    Encryptor
    ForensicValidator
    ConfigManager
    CacheManager
    Cloner
    AntiFingerprintEngine
    ThreatIntelligence
    ForensicEvasion
    ProductionAPI
    SourceFormatPreservation
    ZeroTraceProcessor
    # Advanced Processing Engines - Integration Complete
    EntropyAnalysis
    MLEvasionEngine
    DocumentLifecycleSimulator
    ProfessionalMetadataEngine
    StatisticalPatternMasker
    AdvancedPatternRecognizer
    PDFVersionConverter
    FormatMigrationManager
    PerformanceOptimizer
    TemporalConsistencyManager
    FormatValidationEngine
    PDFByteFidelityProcessor
    # Security and Stealth Components - Integration Complete
    StealthScrubber
    TraceCleaner
    StrictTraceCleaner
    MetadataCleaner
    MemoryGuard
    MemorySanitizer
    LightweightMemoryScrubber
    PDFIntegrityChecker
    IntegrityChecker
    SecurityValidation
    PDFUtils
    ${OPENSSL_LIBRARIES}
    ${ZLIB_LIBRARIES}
    Threads::Threads
)

# Forensic analysis executable
add_executable(pdfforensic main_forensic.cpp)
target_link_libraries(pdfforensic
    ForensicValidator
    PDFParser
    PDFUtils
    ${OPENSSL_LIBRARIES}
    ${ZLIB_LIBRARIES}
    Threads::Threads
)

# Set output directories
set_target_properties(pdfscrubber PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

set_target_properties(pdfforensic PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Compiler warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(pdfscrubber PRIVATE 
        -Wall -Wextra -Wpedantic -Werror
        -Wno-unused-parameter -Wno-unused-variable
    )
    target_compile_options(pdfforensic PRIVATE 
        -Wall -Wextra -Wpedantic -Werror
        -Wno-unused-parameter -Wno-unused-variable
    )
endif()

# Enable testing
enable_testing()

# Basic test validation
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/test_forensic_validator.cpp)
    add_executable(test_forensic_validator test_forensic_validator.cpp)
    target_link_libraries(test_forensic_validator
        ForensicValidator
        PDFUtils
        ${OPENSSL_LIBRARIES}
        ${ZLIB_LIBRARIES}
        Threads::Threads
    )
endif()

# Monitoring system executable
add_executable(monitoring_server 
    monitoring_web_server.cpp
    monitoring_system.cpp
    monitoring_system.hpp
)
target_link_libraries(monitoring_server
    ConfigManager
    PDFUtils
    ${OPENSSL_LIBRARIES}
    Threads::Threads
)

# Find libmicrohttpd for web server
find_package(PkgConfig REQUIRED)
pkg_check_modules(MICROHTTPD REQUIRED libmicrohttpd)
if(MICROHTTPD_FOUND)
    target_link_libraries(monitoring_server ${MICROHTTPD_LIBRARIES})
    target_include_directories(monitoring_server PRIVATE ${MICROHTTPD_INCLUDE_DIRS})
    target_compile_options(monitoring_server PRIVATE ${MICROHTTPD_CFLAGS_OTHER})
endif()

# Find cURL for webhook notifications
find_package(CURL REQUIRED)
if(CURL_FOUND)
    target_link_libraries(monitoring_server ${CURL_LIBRARIES})
    target_include_directories(monitoring_server PRIVATE ${CURL_INCLUDE_DIRS})
endif()

# Add tests
add_test(NAME BuildTest COMMAND build_test)
add_test(NAME ComprehensiveTests COMMAND test_suite)

# Installation configuration
install(TARGETS pdfscrubber pdfforensic
    RUNTIME DESTINATION bin
    COMPONENT applications
)

install(FILES 
    ${CMAKE_CURRENT_SOURCE_DIR}/USAGE_GUIDELINES.md
    ${CMAKE_CURRENT_SOURCE_DIR}/SECURITY_CONSIDERATIONS.md
    ${CMAKE_CURRENT_SOURCE_DIR}/PERFORMANCE_GUIDE.md
    DESTINATION share/doc/pdfscrubber
    COMPONENT documentation
)

# CPack configuration
set(CPACK_PACKAGE_NAME "PDFScrubber")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_PACKAGE_VENDOR "PDF Security Tools")
set(CPACK_PACKAGE_CONTACT "security@pdfscrubber.com")

# Platform-specific packaging
if(WIN32)
    set(CPACK_GENERATOR "ZIP;NSIS")
    set(CPACK_NSIS_DISPLAY_NAME "PDF Scrubber")
    set(CPACK_NSIS_PACKAGE_NAME "PDFScrubber")
elseif(APPLE)
    set(CPACK_GENERATOR "ZIP;DragNDrop")
else()
    set(CPACK_GENERATOR "TGZ;DEB;RPM")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl3, zlib1g")
    set(CPACK_RPM_PACKAGE_REQUIRES "openssl, zlib")
endif()

include(CPack)

# Custom targets
add_custom_target(format
    COMMAND find ${CMAKE_SOURCE_DIR} -name "*.cpp" -o -name "*.hpp" | xargs clang-format -i
    COMMENT "Formatting source code"
)

add_custom_target(docs
    COMMAND doxygen ${CMAKE_SOURCE_DIR}/Doxyfile
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Generating documentation"
)

# Print configuration summary
message(STATUS "")
message(STATUS "Configuration Summary:")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  OpenSSL Version: ${OPENSSL_VERSION}")
message(STATUS "  ZLIB Version: ${ZLIB_VERSION_STRING}")
message(STATUS "  Install Prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")