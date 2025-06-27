
#include "library_silence_config.hpp"
#include <openssl/err.h>
#include <openssl/bio.h>

void LibrarySilenceConfig::configure_openssl_silent_mode() {
    // Disable OpenSSL error output
    ERR_set_error_data(NULL, 0);
    
    // Redirect OpenSSL error output to null
    BIO* null_bio = BIO_new(BIO_s_null());
    ERR_print_errors(null_bio);
    BIO_free(null_bio);
}

void LibrarySilenceConfig::configure_all_libraries_silent() {
    configure_openssl_silent_mode();
    // Add other library configurations as needed
}
