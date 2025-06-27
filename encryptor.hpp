#pragma once
#include <vector>
#include <string>
#include <map>
#include <cstdint>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Forward declarations
struct CryptFilter;
struct PDFObject;

struct EncryptionParams {
    std::string user_password;
    std::string owner_password;
    int key_length;
    int revision;
    int permissions;
    std::string algorithm;
    std::vector<uint8_t> encryption_key;
    std::vector<uint8_t> owner_key;
    std::vector<uint8_t> user_key;
    std::vector<uint8_t> file_id;
    bool use_aes;
    bool encrypt_metadata;
};

struct CryptFilter {
    std::string name;
    std::string method;
    int key_length;
    std::map<std::string, std::string> params;
};

class PDFEncryptor {
public:
    PDFEncryptor();
    ~PDFEncryptor();
    
    // Main encryption functions
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& pdf_data, 
                                const std::string& user_password, 
                                const std::string& owner_password);
    
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& encrypted_pdf_data,
                                const std::string& password);
    
    // Configuration
    void set_encryption_algorithm(const std::string& algorithm);
    void set_key_length(int bits);
    void set_permissions(int permissions);
    void set_revision(int revision);
    void set_encrypt_metadata(bool encrypt);
    
private:
    // Encryption setup and key derivation
    EncryptionParams setup_encryption(const std::string& user_password,
                                     const std::string& owner_password,
                                     const std::vector<uint8_t>& file_id);
    
    std::vector<uint8_t> derive_encryption_key(const EncryptionParams& params,
                                              const std::vector<uint8_t>& file_id);
    
    std::vector<uint8_t> compute_owner_key(const std::string& owner_password,
                                          const std::string& user_password,
                                          int key_length, int revision);
    
    std::vector<uint8_t> compute_user_key(const std::string& user_password,
                                         const std::vector<uint8_t>& owner_key,
                                         int permissions, int key_length,
                                         int revision, const std::vector<uint8_t>& file_id);
    
    std::vector<uint8_t> authenticate_user_password(const std::string& password,
                                                   const std::vector<uint8_t>& user_key,
                                                   const EncryptionParams& params);
    
    std::vector<uint8_t> authenticate_owner_password(const std::string& password,
                                                    const std::vector<uint8_t>& owner_key,
                                                    const EncryptionParams& params);
    
    // PDF structure encryption
    std::vector<uint8_t> encrypt_pdf_structure(const std::vector<uint8_t>& pdf_data,
                                              const EncryptionParams& params);
    
    void encrypt_pdf_objects(std::vector<uint8_t>& pdf_data,
                            const EncryptionParams& params);
    
    void encrypt_pdf_strings(std::vector<uint8_t>& pdf_data,
                            const EncryptionParams& params);
    
    void encrypt_pdf_streams(std::vector<uint8_t>& pdf_data,
                            const EncryptionParams& params);
    
    // Object-level encryption
    std::vector<uint8_t> encrypt_object(const std::vector<uint8_t>& object_data,
                                       int obj_num, int gen_num,
                                       const EncryptionParams& params);
    
    std::vector<uint8_t> decrypt_object(const std::vector<uint8_t>& encrypted_data,
                                       int obj_num, int gen_num,
                                       const EncryptionParams& params);
    
    std::vector<uint8_t> encrypt_string(const std::vector<uint8_t>& string_data,
                                       int obj_num, int gen_num,
                                       const EncryptionParams& params);
    
    std::vector<uint8_t> decrypt_string(const std::vector<uint8_t>& encrypted_string,
                                       int obj_num, int gen_num,
                                       const EncryptionParams& params);
    
    std::vector<uint8_t> encrypt_stream(const std::vector<uint8_t>& stream_data,
                                       int obj_num, int gen_num,
                                       const EncryptionParams& params);
    
    std::vector<uint8_t> decrypt_stream(const std::vector<uint8_t>& encrypted_stream,
                                       int obj_num, int gen_num,
                                       const EncryptionParams& params);
    
    // Cryptographic primitives
    std::vector<uint8_t> rc4_encrypt(const std::vector<uint8_t>& data,
                                    const std::vector<uint8_t>& key);
    
    std::vector<uint8_t> rc4_decrypt(const std::vector<uint8_t>& encrypted_data,
                                    const std::vector<uint8_t>& key);
    
    std::vector<uint8_t> aes_encrypt(const std::vector<uint8_t>& data,
                                    const std::vector<uint8_t>& key,
                                    const std::vector<uint8_t>& iv);
    
    std::vector<uint8_t> aes_decrypt(const std::vector<uint8_t>& encrypted_data,
                                    const std::vector<uint8_t>& key,
                                    const std::vector<uint8_t>& iv);
    
    std::vector<uint8_t> aes_cbc_encrypt(const std::vector<uint8_t>& plaintext,
                                        const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& iv);
    
    std::vector<uint8_t> aes_cbc_decrypt(const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& iv);
    
public:
    // Hash functions for testing
    std::vector<uint8_t> md5_hash(const std::vector<uint8_t>& data);
    std::vector<uint8_t> sha256_hash(const std::vector<uint8_t>& data);
    std::vector<uint8_t> sha1_hash(const std::vector<uint8_t>& data);
    std::vector<uint8_t> hmac_sha1(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data);
    std::vector<uint8_t> generate_random_bytes(int length);

    // Anti-fingerprinting methods
    std::vector<uint8_t> remove_openssl_traces(const std::vector<uint8_t>& data);
    std::vector<uint8_t> remove_encryption_watermarks(const std::vector<uint8_t>& data);
    std::vector<uint8_t> clone_original_metadata_to_encrypted(const std::vector<uint8_t>& encrypted_data, 
                                                              const std::vector<uint8_t>& original_data);

private:
    
    // Key derivation functions
    std::vector<uint8_t> pbkdf2(const std::vector<uint8_t>& password,
                               const std::vector<uint8_t>& salt,
                               int iterations, int key_length);
    
    std::vector<uint8_t> derive_object_key(const std::vector<uint8_t>& base_key,
                                          int obj_num, int gen_num);
    
    // Padding and formatting
    std::vector<uint8_t> apply_pkcs7_padding(const std::vector<uint8_t>& data,
                                            int block_size);
    
    std::vector<uint8_t> remove_pkcs7_padding(const std::vector<uint8_t>& padded_data);
    
    // Encryption dictionary management
    std::string create_encryption_dictionary(const EncryptionParams& params);
    void insert_encryption_dictionary(std::vector<uint8_t>& pdf_data,
                                     const std::string& encrypt_dict);
    
    EncryptionParams parse_encryption_dictionary(const std::string& encrypt_dict,
                                                const std::vector<uint8_t>& file_id);
    EncryptionParams parse_encryption_dictionary(const std::string& pdf_data);
    std::vector<uint8_t> derive_object_key(const std::vector<uint8_t>& file_key, int obj_num, int gen_num, const EncryptionParams& params);
    
    // Missing functions referenced in encryptor.cpp
    EncryptionParams extract_encryption_params(const std::vector<uint8_t>& encrypted_pdf_data);
    std::vector<uint8_t> decrypt_with_rc4(const std::vector<uint8_t>& encrypted_data, 
                                         const std::string& password, 
                                         const EncryptionParams& params);
    std::vector<uint8_t> decrypt_with_aes(const std::vector<uint8_t>& encrypted_data, 
                                         const std::string& password, 
                                         const EncryptionParams& params);
    std::vector<uint8_t> decrypt_aes_stream(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);
    std::vector<uint8_t> decrypt_rc4_stream(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);
    std::string decrypt_string_literals(const std::string& content, const std::vector<uint8_t>& key, const EncryptionParams& params);
    std::vector<uint8_t> compute_user_password_key(const EncryptionParams& params);
    std::string derive_user_from_owner_password(const EncryptionParams& params);
    std::map<std::string, std::string> parse_dictionary_entries(const std::string& dict_content);
    bool contains_encrypted_strings(const std::string& content);
    
    // Permission handling
    int calculate_permissions_value(bool print, bool modify, bool copy,
                                   bool add_notes, bool fill_forms,
                                   bool extract_text, bool assemble,
                                   bool print_high_res);
    
    void validate_permissions(int permissions);
    
    // Standard security handler
    std::vector<uint8_t> standard_security_handler_r2(const std::string& password,
                                                     const std::vector<uint8_t>& owner_key,
                                                     int permissions,
                                                     const std::vector<uint8_t>& file_id);
    
    std::vector<uint8_t> standard_security_handler_r3(const std::string& password,
                                                     const std::vector<uint8_t>& owner_key,
                                                     int permissions,
                                                     const std::vector<uint8_t>& file_id);
    
    std::vector<uint8_t> standard_security_handler_r4(const std::string& password,
                                                     const std::vector<uint8_t>& owner_key,
                                                     int permissions,
                                                     const std::vector<uint8_t>& file_id);
    
    // PDF parsing helpers for encryption
    std::vector<size_t> find_pdf_objects(const std::vector<uint8_t>& pdf_data);
    std::vector<size_t> find_pdf_strings(const std::vector<uint8_t>& pdf_data);
    std::vector<size_t> find_pdf_streams(const std::vector<uint8_t>& pdf_data);
    
    std::pair<int, int> extract_object_numbers(const std::vector<uint8_t>& pdf_data,
                                              size_t object_start);
    
    bool is_encrypted_object(const std::vector<uint8_t>& pdf_data,
                            size_t object_start);
    
    // Validation and integrity
    bool validate_encryption_parameters(const EncryptionParams& params);
    bool verify_password(const std::string& password, const EncryptionParams& params);
    bool check_encryption_integrity(const std::vector<uint8_t>& encrypted_data);
    
    // Error handling
    void handle_encryption_error(const std::string& error_message);
    void handle_decryption_error(const std::string& error_message);
    
    // PDF decryption implementation
    std::vector<uint8_t> apply_pdf_decryption(const std::vector<uint8_t>& encrypted_pdf_data,
                                             const EncryptionParams& params);
    
    // Utility functions
    std::vector<uint8_t> string_to_bytes(const std::string& str);
    std::string bytes_to_string(const std::vector<uint8_t>& bytes);
    std::string bytes_to_hex(const std::vector<uint8_t>& bytes);
    std::vector<uint8_t> hex_to_bytes(const std::string& hex);
    
    void secure_zero_memory(std::vector<uint8_t>& data);
    void secure_zero_memory(std::string& str);
    
    // Advanced PDF features
    bool handle_compressed_object_streams(std::vector<uint8_t>& pdf_data, const EncryptionParams& params);
    bool handle_cross_reference_streams(std::vector<uint8_t>& pdf_data, const EncryptionParams& params);
    std::vector<uint8_t> decrypt_compressed_object_stream(const std::vector<uint8_t>& stream_data, const EncryptionParams& params);
    std::vector<uint8_t> decrypt_xref_stream(const std::vector<uint8_t>& stream_data, const EncryptionParams& params);
    
    // PDF 2.0 encryption support
    bool setup_pdf2_encryption(EncryptionParams& params, const std::string& user_password, const std::string& owner_password);
    std::vector<uint8_t> aes_256_gcm_encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);
    std::vector<uint8_t> aes_256_gcm_decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);
    
    // Certificate-based encryption
    bool setup_certificate_encryption(EncryptionParams& params, const std::string& cert_path);
    std::vector<uint8_t> encrypt_with_certificate(const std::vector<uint8_t>& data, const std::string& cert_path);
    std::vector<uint8_t> decrypt_with_certificate(const std::vector<uint8_t>& encrypted_data, const std::string& key_path);
    
    // Performance optimizations
    class StreamingEncryptor {
    public:
        StreamingEncryptor(const EncryptionParams& params, size_t buffer_size = 1024 * 1024);
        ~StreamingEncryptor();
        bool process_chunk(const std::vector<uint8_t>& input_chunk, std::vector<uint8_t>& output_chunk);
        std::vector<uint8_t> finalize();
    private:
        EncryptionParams params_;
        size_t buffer_size_;
        EVP_CIPHER_CTX* ctx_;
        std::vector<uint8_t> buffer_;
    };
    
    class MemoryPool {
    public:
        MemoryPool(size_t block_size = 4096, size_t max_blocks = 1000);
        ~MemoryPool();
        void* allocate(size_t size);
        void deallocate(void* ptr);
        void clear();
    private:
        size_t block_size_;
        size_t max_blocks_;
        std::vector<void*> free_blocks_;
        std::vector<void*> allocated_blocks_;
        // SECURITY FIX: Track allocation sizes for secure cleanup
        std::map<void*, size_t> block_size_map_;
    };
    
    // Streaming support for large files
    bool encrypt_file_streaming(const std::string& input_file, const std::string& output_file, const EncryptionParams& params);
    bool decrypt_file_streaming(const std::string& input_file, const std::string& output_file, const EncryptionParams& params);
    
    // Hardware acceleration
    bool enable_hardware_acceleration();
    bool is_aes_ni_available();
    std::vector<uint8_t> aes_encrypt_hardware_accelerated(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);

    // Configuration
    std::string default_algorithm_;
    int default_key_length_;
    int default_permissions_;
    int default_revision_;
    bool default_encrypt_metadata_;
    
    // Security
    bool secure_random_initialized_;
    std::vector<uint8_t> entropy_pool_;
    
    // Performance optimizations
    static MemoryPool* memory_pool_;
    bool hardware_acceleration_enabled_;
    size_t streaming_buffer_size_;
    
    // Statistics
    struct EncryptionStats {
        size_t objects_encrypted;
        size_t strings_encrypted;
        size_t streams_encrypted;
        size_t bytes_encrypted;
        double encryption_time;
    } stats_;
};
