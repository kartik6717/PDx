#ifndef SILENCE_ENFORCEMENT_CONFIG_HPP
#define SILENCE_ENFORCEMENT_CONFIG_HPP

// Global configuration for enforcing complete silence across the entire application
// This header ensures all output suppression mechanisms are activated before main()

#include "global_silence_enforcer.hpp"
#include "complete_output_suppressor.hpp"
#include "production_mode_checker.hpp"
#include "silent_operation_manager.hpp"
#include "stream_suppression.hpp"
#include "library_silence_config.hpp"

// Force production mode by default
#ifndef DEBUG_MODE
    #define PRODUCTION_MODE 1
#endif

// Automatic silence enforcement on program startup
namespace {
    struct SilenceEnforcementInitializer {
        SilenceEnforcementInitializer() {
            // Set production environment
            setenv("APP_MODE", "production", 1);
            setenv("NODE_ENV", "production", 1);
            setenv("DEBUG_MODE", "0", 1);
            
            // Activate all silence mechanisms
            CompleteOutputSuppressor::suppress_all_output();
            GlobalSilenceEnforcer::activate_complete_silence();
            SilentOperationManager::enable_stealth_mode();
            StreamSuppression::suppress_all_streams();
            LibrarySilenceConfig::configure_all_libraries_silent();
        }
    } silence_enforcement_initializer;
}

#endif // SILENCE_ENFORCEMENT_CONFIG_HPP