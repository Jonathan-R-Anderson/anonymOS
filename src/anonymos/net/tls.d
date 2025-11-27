module anonymos.net.tls;

import anonymos.net.types;
import anonymos.net.tcp;

/// TLS version
enum TLSVersion {
    TLS_1_2,
    TLS_1_3,
}

/// TLS context
struct TLSContext {
    void* sslCtx;       // OpenSSL SSL_CTX*
    void* ssl;          // OpenSSL SSL*
    int tcpSocket;      // Underlying TCP socket
    bool connected;
    bool handshakeComplete;
}

/// TLS configuration
struct TLSConfig {
    TLSVersion version_;
    bool verifyPeer;
    const(char)* caFile;
    const(char)* certFile;
    const(char)* keyFile;
}

// OpenSSL function declarations (will be linked from libssl.a)
extern(C) @nogc nothrow {
    // SSL library initialization
    void SSL_library_init();
    void SSL_load_error_strings();
    void OpenSSL_add_all_algorithms();
    
    // SSL_CTX functions
    void* TLS_client_method();
    void* TLS_server_method();
    void* SSL_CTX_new(void* method);
    void SSL_CTX_free(void* ctx);
    int SSL_CTX_use_certificate_file(void* ctx, const(char)* file, int type);
    int SSL_CTX_use_PrivateKey_file(void* ctx, const(char)* file, int type);
    int SSL_CTX_load_verify_locations(void* ctx, const(char)* caFile, const(char)* caPath);
    void SSL_CTX_set_verify(void* ctx, int mode, void* callback);
    
    // SSL functions
    void* SSL_new(void* ctx);
    void SSL_free(void* ssl);
    int SSL_set_fd(void* ssl, int fd);
    int SSL_connect(void* ssl);
    int SSL_accept(void* ssl);
    int SSL_read(void* ssl, void* buf, int num);
    int SSL_write(void* ssl, const(void)* buf, int num);
    int SSL_shutdown(void* ssl);
    int SSL_get_error(void* ssl, int ret);
    
    // BIO functions (for custom I/O)
    void* BIO_new(void* type);
    void* BIO_s_mem();
    int BIO_read(void* bio, void* data, int len);
    int BIO_write(void* bio, const(void)* data, int len);
    void BIO_free(void* bio);
}

// OpenSSL constants
enum {
    SSL_FILETYPE_PEM = 1,
    SSL_VERIFY_NONE = 0,
    SSL_VERIFY_PEER = 1,
    SSL_ERROR_NONE = 0,
    SSL_ERROR_WANT_READ = 2,
    SSL_ERROR_WANT_WRITE = 3,
    SSL_ERROR_SYSCALL = 5,
    SSL_ERROR_SSL = 1,
}

private __gshared bool g_tlsInitialized = false;
private __gshared void* g_defaultClientCtx = null;
private __gshared TLSContext[64] g_tlsContexts;
private __gshared size_t g_tlsContextCount = 0;

/// Initialize TLS library
export extern(C) bool initTLS() @nogc nothrow {
    if (g_tlsInitialized) return true;
    
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // Create default client context
    void* method = TLS_client_method();
    if (method is null) return false;
    
    g_defaultClientCtx = SSL_CTX_new(method);
    if (g_defaultClientCtx is null) return false;
    
    // Set default verification mode (verify peer)
    SSL_CTX_set_verify(g_defaultClientCtx, SSL_VERIFY_PEER, null);
    
    g_tlsInitialized = true;
    return true;
}

/// Create TLS context
export extern(C) int tlsCreateContext(const ref TLSConfig config) @nogc nothrow {
    if (!g_tlsInitialized) {
        if (!initTLS()) return -1;
    }
    
    if (g_tlsContextCount >= g_tlsContexts.length) {
        return -1;
    }
    
    int ctxId = cast(int)g_tlsContextCount;
    TLSContext* ctx = &g_tlsContexts[ctxId];
    
    // Create SSL context
    void* method = TLS_client_method();
    ctx.sslCtx = SSL_CTX_new(method);
    if (ctx.sslCtx is null) return -1;
    
    // Configure verification
    if (config.verifyPeer) {
        SSL_CTX_set_verify(ctx.sslCtx, SSL_VERIFY_PEER, null);
        
        if (config.caFile !is null) {
            if (SSL_CTX_load_verify_locations(ctx.sslCtx, config.caFile, null) != 1) {
                SSL_CTX_free(ctx.sslCtx);
                return -1;
            }
        }
    } else {
        SSL_CTX_set_verify(ctx.sslCtx, SSL_VERIFY_NONE, null);
    }
    
    // Load certificate and key if provided
    if (config.certFile !is null) {
        if (SSL_CTX_use_certificate_file(ctx.sslCtx, config.certFile, SSL_FILETYPE_PEM) != 1) {
            SSL_CTX_free(ctx.sslCtx);
            return -1;
        }
    }
    
    if (config.keyFile !is null) {
        if (SSL_CTX_use_PrivateKey_file(ctx.sslCtx, config.keyFile, SSL_FILETYPE_PEM) != 1) {
            SSL_CTX_free(ctx.sslCtx);
            return -1;
        }
    }
    
    ctx.ssl = null;
    ctx.tcpSocket = -1;
    ctx.connected = false;
    ctx.handshakeComplete = false;
    
    g_tlsContextCount++;
    return ctxId;
}

/// Connect TLS over existing TCP socket
export extern(C) bool tlsConnect(int ctxId, int tcpSocket) @nogc nothrow {
    if (ctxId < 0 || ctxId >= g_tlsContextCount) return false;
    
    TLSContext* ctx = &g_tlsContexts[ctxId];
    
    // Create SSL object
    ctx.ssl = SSL_new(ctx.sslCtx);
    if (ctx.ssl is null) return false;
    
    // Set file descriptor
    if (SSL_set_fd(ctx.ssl, tcpSocket) != 1) {
        SSL_free(ctx.ssl);
        ctx.ssl = null;
        return false;
    }
    
    ctx.tcpSocket = tcpSocket;
    
    // Perform TLS handshake
    int ret = SSL_connect(ctx.ssl);
    if (ret != 1) {
        int error = SSL_get_error(ctx.ssl, ret);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
            SSL_free(ctx.ssl);
            ctx.ssl = null;
            return false;
        }
        // Would block - handshake in progress
        ctx.connected = true;
        ctx.handshakeComplete = false;
        return true;
    }
    
    ctx.connected = true;
    ctx.handshakeComplete = true;
    return true;
}

/// Check if TLS handshake is complete
export extern(C) bool tlsHandshakeComplete(int ctxId) @nogc nothrow {
    if (ctxId < 0 || ctxId >= g_tlsContextCount) return false;
    
    TLSContext* ctx = &g_tlsContexts[ctxId];
    
    if (ctx.handshakeComplete) return true;
    if (!ctx.connected || ctx.ssl is null) return false;
    
    // Try to complete handshake
    int ret = SSL_connect(ctx.ssl);
    if (ret == 1) {
        ctx.handshakeComplete = true;
        return true;
    }
    
    int error = SSL_get_error(ctx.ssl, ret);
    if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
        return false;  // Still in progress
    }
    
    // Error occurred
    ctx.connected = false;
    return false;
}

/// Read data from TLS connection
export extern(C) int tlsRead(int ctxId, ubyte* buffer, size_t len) @nogc nothrow {
    if (ctxId < 0 || ctxId >= g_tlsContextCount) return -1;
    if (buffer is null || len == 0) return -1;
    
    TLSContext* ctx = &g_tlsContexts[ctxId];
    
    if (!ctx.connected || !ctx.handshakeComplete || ctx.ssl is null) {
        return -1;
    }
    
    int ret = SSL_read(ctx.ssl, buffer, cast(int)len);
    if (ret <= 0) {
        int error = SSL_get_error(ctx.ssl, ret);
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
            return 0;  // Would block
        }
        return -1;  // Error
    }
    
    return ret;
}

/// Write data to TLS connection
export extern(C) int tlsWrite(int ctxId, const(ubyte)* data, size_t len) @nogc nothrow {
    if (ctxId < 0 || ctxId >= g_tlsContextCount) return -1;
    if (data is null || len == 0) return 0;
    
    TLSContext* ctx = &g_tlsContexts[ctxId];
    
    if (!ctx.connected || !ctx.handshakeComplete || ctx.ssl is null) {
        return -1;
    }
    
    int ret = SSL_write(ctx.ssl, data, cast(int)len);
    if (ret <= 0) {
        int error = SSL_get_error(ctx.ssl, ret);
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
            return 0;  // Would block
        }
        return -1;  // Error
    }
    
    return ret;
}

/// Close TLS connection
export extern(C) void tlsClose(int ctxId) @nogc nothrow {
    if (ctxId < 0 || ctxId >= g_tlsContextCount) return;
    
    TLSContext* ctx = &g_tlsContexts[ctxId];
    
    if (ctx.ssl !is null) {
        SSL_shutdown(ctx.ssl);
        SSL_free(ctx.ssl);
        ctx.ssl = null;
    }
    
    if (ctx.tcpSocket >= 0) {
        tcpClose(ctx.tcpSocket);
        ctx.tcpSocket = -1;
    }
    
    ctx.connected = false;
    ctx.handshakeComplete = false;
}

/// Free TLS context
export extern(C) void tlsFreeContext(int ctxId) @nogc nothrow {
    if (ctxId < 0 || ctxId >= g_tlsContextCount) return;
    
    TLSContext* ctx = &g_tlsContexts[ctxId];
    
    tlsClose(ctxId);
    
    if (ctx.sslCtx !is null) {
        SSL_CTX_free(ctx.sslCtx);
        ctx.sslCtx = null;
    }
}

/// Simple TLS connect (creates context, connects, and returns context ID)
export extern(C) int tlsSimpleConnect(const ref IPv4Address ip, ushort port, bool verifyPeer) @nogc nothrow {
    // Create TCP connection first
    int tcpSock = tcpConnectTo(ip.bytes[0], ip.bytes[1], ip.bytes[2], ip.bytes[3], port);
    if (tcpSock < 0) return -1;
    
    // Wait for TCP connection
    for (int i = 0; i < 100; i++) {
        networkStackPoll();
        for (int j = 0; j < 100000; j++) {
            asm { nop; }
        }
    }
    
    // Create TLS context
    TLSConfig config;
    config.version_ = TLSVersion.TLS_1_3;
    config.verifyPeer = verifyPeer;
    config.caFile = null;
    config.certFile = null;
    config.keyFile = null;
    
    int ctxId = tlsCreateContext(config);
    if (ctxId < 0) {
        tcpClose(tcpSock);
        return -1;
    }
    
    // Connect TLS
    if (!tlsConnect(ctxId, tcpSock)) {
        tlsFreeContext(ctxId);
        return -1;
    }
    
    // Wait for handshake
    for (int i = 0; i < 100; i++) {
        networkStackPoll();
        if (tlsHandshakeComplete(ctxId)) {
            return ctxId;
        }
        for (int j = 0; j < 100000; j++) {
            asm { nop; }
        }
    }
    
    // Handshake timeout
    tlsFreeContext(ctxId);
    return -1;
}
