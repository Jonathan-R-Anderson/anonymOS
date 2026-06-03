extern(C) {
    // LZMA stubs for libunwind
    int lzma_stream_footer_decode(void* ptr, void* ptr2) { return 1; }
    int lzma_index_buffer_decode(void* p1, void* p2, void* p3, ulong l) { return 1; }
    ulong lzma_index_size(void* p) { return 0; }
    void lzma_index_end(void* p, void* p2) {}
    ulong lzma_index_uncompressed_size(void* p) { return 0; }
    int lzma_stream_buffer_decode(void* p1, void* p2, void* p3, void* p4, ulong l1, void* p5, void* p6, ulong l2) { return 1; }

    // ZLIB stubs
    int deflateEnd(void* strm) { return 0; }
    int deflate(void* strm, int flush) { return 0; }
    int deflateInit2_(void* strm, int level, int method, int windowBits, int memLevel, int strategy, const char* version_, int stream_size) { return 0; }
    
    int inflateEnd(void* strm) { return 0; }
    int inflate(void* strm, int flush) { return 0; }
    int inflateInit2_(void* strm, int windowBits, const char* version_, int stream_size) { return 0; }
    
    uint crc32(uint crc, const(ubyte)* buf, uint len) { return 0; }

    // Glibc / Phobos stubs to prevent crash/warnings
    void _dl_tunable_set_hwcaps() {} // Prevent GP Fault
    
    void* dlopen(const char* filename, int flag) { return null; }
    char* dlerror() { return cast(char*)"dlopen disabled"; }
    void* dlsym(void* handle, const char* symbol) { return null; }
    int dlclose(void* handle) { return 0; }

    int getaddrinfo(const char* node, const char* service, const void* hints, void** res) { return -1; }
    void freeaddrinfo(void* res) {}
    void* gethostbyname(const char* name) { return null; }
    void* gethostbyaddr(const void* addr, uint len, int type) { return null; }
    void* getprotobyname(const char* name) { return null; }
    void* getprotobynumber(int proto) { return null; }
    void* getservbyname(const char* name, const char* proto) { return null; }
    void* getservbyport(int port, const char* proto) { return null; }
}
