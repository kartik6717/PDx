
#include "silent_status_tracker.hpp"
#include <chrono>

std::vector<SilentStatusTracker::Status> SilentStatusTracker::status_history_;
bool SilentStatusTracker::tracking_enabled_ = false;

void SilentStatusTracker::track_operation(const std::string& operation, bool success, const std::string& details) {
    if (!tracking_enabled_) return;
    
    Status status;
    status.operation = operation;
    status.success = success;
    status.details = details;
    status.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    status_history_.push_back(status);
    
    // Keep only last 100 entries to prevent memory bloat
    if (status_history_.size() > 100) {
        status_history_.erase(status_history_.begin());
    }
}

std::vector<SilentStatusTracker::Status> SilentStatusTracker::get_status_history() {
    return status_history_;
}

void SilentStatusTracker::clear_history() {
    status_history_.clear();
}

bool SilentStatusTracker::is_tracking_enabled() {
    return tracking_enabled_;
}

void SilentStatusTracker::enable_tracking(bool enable) {
    tracking_enabled_ = enable;
}
