#ifndef SILENT_EXECUTION_WRAPPERS_HPP
#define SILENT_EXECUTION_WRAPPERS_HPP
#include "stealth_macros.hpp"

#include "silent_error_handler.hpp"

#define SILENT_EXECUTE(operation) \
    try { \
        operation; \
    } catch (const std::exception& e) { \
        SilentErrorHandler::log_internal_error("OPERATION_FAILED", e.what(), \
                                             SilentErrorHandler::ErrorSeverity::WARNING); \
    } catch (...) { \
        SilentErrorHandler::log_internal_error("UNKNOWN_ERROR", "Unknown exception occurred", \
                                             SilentErrorHandler::ErrorSeverity::CRITICAL); \
    }

#define SILENT_EXECUTE_WITH_RESULT(operation, default_result) \
    [&]() { \
        try { \
            return operation; \
        } catch (const std::exception& e) { \
            SilentErrorHandler::log_internal_error("OPERATION_FAILED", e.what(), \
                                                 SilentErrorHandler::ErrorSeverity::WARNING); \
            return default_result; \
        } catch (...) { \
            SilentErrorHandler::log_internal_error("UNKNOWN_ERROR", "Unknown exception occurred", \
                                                 SilentErrorHandler::ErrorSeverity::CRITICAL); \
            return default_result; \
        } \
    }()

#endif // SILENT_EXECUTION_WRAPPERS_HPP
