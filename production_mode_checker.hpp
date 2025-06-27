#ifndef PRODUCTION_MODE_CHECKER_HPP
#define PRODUCTION_MODE_CHECKER_HPP

#include <cstdlib>
#include <string>

class ProductionModeChecker {
public:
    static bool is_production_mode() {
        // Check multiple environment variables for production mode
        const char* env_mode = std::getenv("APP_MODE");
        if (env_mode && std::string(env_mode) == "production") {
            return true;
        }
        
        const char* node_env = std::getenv("NODE_ENV");
        if (node_env && std::string(node_env) == "production") {
            return true;
        }
        
        const char* debug_mode = std::getenv("DEBUG_MODE");
        if (debug_mode && std::string(debug_mode) == "0") {
            return true;
        }
        
        // Default to production mode for safety
        return true;
    }
    
    static bool is_debug_mode() {
        return !is_production_mode();
    }
};

#endif // PRODUCTION_MODE_CHECKER_HPP