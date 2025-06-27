#ifndef SILENT_STATUS_TRACKER_HPP
#define SILENT_STATUS_TRACKER_HPP

#include <string>
#include <vector>
#include <memory>

class SilentStatusTracker {
public:
    struct Status {
        std::string operation;
        bool success;
        std::string details;
        long long timestamp;
    };

    static void track_operation(const std::string& operation, bool success, const std::string& details = "");
    static std::vector<Status> get_status_history();
    static void clear_history();
    static bool is_tracking_enabled();
    static void enable_tracking(bool enable);

private:
    static std::vector<Status> status_history_;
    static bool tracking_enabled_;
};

#endif // SILENT_STATUS_TRACKER_HPP