#ifndef PRODUCTION_SILENCE_WRAPPER_HPP
#define PRODUCTION_SILENCE_WRAPPER_HPP

#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <fstream>

// This wrapper ensures complete silence in production before any other code runs
class ProductionSilenceWrapper {
private:
    static bool initialized_;
    
    static void enforce_complete_silence() {
        // Redirect all file descriptors to null
        #ifdef _WIN32
            freopen("NUL", "w", stdout);
            freopen("NUL", "w", stderr);
            freopen("NUL", "r", stdin);
        #else
            freopen("/dev/null", "w", stdout);
            freopen("/dev/null", "w", stderr);
            freopen("/dev/null", "r", stdin);
        #endif
        
        // Create null stream and redirect all C++ streams
        static std::ofstream null_stream;
        #ifdef _WIN32
            null_stream.open("NUL");
        #else
            null_stream.open("/dev/null");
        #endif
        
        std::cout.rdbuf(null_stream.rdbuf());
        std::cerr.rdbuf(null_stream.rdbuf());
        std::clog.rdbuf(null_stream.rdbuf());
        
        // Disable stream syncing for performance
        std::ios_base::sync_with_stdio(false);
        
        // Set environment to production
        setenv("APP_MODE", "production", 1);
        setenv("NODE_ENV", "production", 1);
        setenv("DEBUG_MODE", "0", 1);
        setenv("SILENT_MODE", "1", 1);
    }
    
public:
    ProductionSilenceWrapper() {
        if (!initialized_) {
            enforce_complete_silence();
            initialized_ = true;
        }
    }
};

// Static initialization
bool ProductionSilenceWrapper::initialized_ = false;

// Create global instance to run before main
namespace {
    ProductionSilenceWrapper production_silence_wrapper_instance;
}

#endif // PRODUCTION_SILENCE_WRAPPER_HPP