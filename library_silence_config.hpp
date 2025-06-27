
#pragma once

class LibrarySilenceConfig {
public:
    static void configure_openssl_silent_mode();
    static void configure_all_libraries_silent();
    
private:
    static void disable_openssl_errors();
    static void suppress_zlib_warnings();
    static void silence_curl_output();
};
