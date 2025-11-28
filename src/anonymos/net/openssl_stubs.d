module anonymos.net.openssl_stubs;

import anonymos.console : printLine;

extern(C) @nogc nothrow {
    void SSL_library_init() { printLine("[openssl-stub] SSL_library_init (stub)"); }
    void SSL_load_error_strings() {}
    void OpenSSL_add_all_algorithms() {}
    
    void* TLS_client_method() { return null; }
    void* TLS_server_method() { return null; }
    void* SSL_CTX_new(void* method) { return null; }
    void SSL_CTX_free(void* ctx) {}
    int SSL_CTX_use_certificate_file(void* ctx, const(char)* file, int type) { return 0; }
    int SSL_CTX_use_PrivateKey_file(void* ctx, const(char)* file, int type) { return 0; }
    int SSL_CTX_load_verify_locations(void* ctx, const(char)* caFile, const(char)* caPath) { return 0; }
    void SSL_CTX_set_verify(void* ctx, int mode, void* callback) {}
    
    void* SSL_new(void* ctx) { return null; }
    void SSL_free(void* ssl) {}
    int SSL_set_fd(void* ssl, int fd) { return 0; }
    int SSL_connect(void* ssl) { return 0; }
    int SSL_accept(void* ssl) { return 0; }
    int SSL_read(void* ssl, void* buf, int num) { return -1; }
    int SSL_write(void* ssl, const(void)* buf, int num) { return -1; }
    int SSL_shutdown(void* ssl) { return 0; }
    int SSL_get_error(void* ssl, int ret) { return 1; } // SSL_ERROR_SSL
    
    void* BIO_new(void* type) { return null; }
    void* BIO_s_mem() { return null; }
    int BIO_read(void* bio, void* data, int len) { return -1; }
    int BIO_write(void* bio, const(void)* data, int len) { return -1; }
    void BIO_free(void* bio) {}
}
