#include <iostream>
#include <fstream>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>

// Global constructor to enforce silence before main()
class NullOutputEnforcer {
public:
    NullOutputEnforcer() {
        // Redirect all streams to null before any code runs
        #ifdef _WIN32
            freopen("NUL", "w", stdout);
            freopen("NUL", "w", stderr);
            static std::ofstream null_stream("NUL");
        #else
            freopen("/dev/null", "w", stdout);
            freopen("/dev/null", "w", stderr);
            static std::ofstream null_stream("/dev/null");
        #endif
        
        std::cout.rdbuf(null_stream.rdbuf());
        std::cerr.rdbuf(null_stream.rdbuf());
        std::clog.rdbuf(null_stream.rdbuf());
        
        // Disable C stdio buffering
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stderr, NULL, _IONBF, 0);
        
        // Set environment variables for production
        setenv("APP_MODE", "production", 1);
        setenv("NODE_ENV", "production", 1);
        setenv("DEBUG_MODE", "0", 1);
    }
};

// Create global instance to run constructor before main
static NullOutputEnforcer null_output_enforcer;