
#include "stream_suppression.hpp"

std::streambuf* StreamSuppression::original_cout_ = nullptr;
std::streambuf* StreamSuppression::original_cerr_ = nullptr;
std::streambuf* StreamSuppression::original_clog_ = nullptr;
std::ostringstream StreamSuppression::memory_stream_;
bool StreamSuppression::streams_suppressed_ = false;

void StreamSuppression::suppress_all_streams() {
    if (!streams_suppressed_) {
        original_cout_ = std::cout.rdbuf();
        original_cerr_ = std::cerr.rdbuf();
        original_clog_ = std::clog.rdbuf();
        
        static std::ofstream null_stream;
        
        #ifdef _WIN32
            null_stream.open("NUL");
        #else
            null_stream.open("/dev/null");
        #endif
        
        std::cout.rdbuf(null_stream.rdbuf());
        std::cerr.rdbuf(null_stream.rdbuf());
        std::clog.rdbuf(null_stream.rdbuf());
        
        streams_suppressed_ = true;
    }
}

void StreamSuppression::restore_streams() {
    if (streams_suppressed_) {
        std::cout.rdbuf(original_cout_);
        std::cerr.rdbuf(original_cerr_);
        std::clog.rdbuf(original_clog_);
        streams_suppressed_ = false;
    }
}

void StreamSuppression::redirect_to_memory() {
    if (!streams_suppressed_) {
        original_cout_ = std::cout.rdbuf();
        original_cerr_ = std::cerr.rdbuf();
        original_clog_ = std::clog.rdbuf();
        
        std::cout.rdbuf(memory_stream_.rdbuf());
        std::cerr.rdbuf(memory_stream_.rdbuf());
        std::clog.rdbuf(memory_stream_.rdbuf());
        
        streams_suppressed_ = true;
    }
}
