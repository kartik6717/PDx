
#pragma once
#include <iostream>
#include <fstream>
#include <sstream>
#include <streambuf>

class StreamSuppression {
public:
    static void suppress_all_streams();
    static void restore_streams();
    static void redirect_to_memory();
    
private:
    static std::streambuf* original_cout_;
    static std::streambuf* original_cerr_;
    static std::streambuf* original_clog_;
    static std::ostringstream memory_stream_;
    static bool streams_suppressed_;
};
