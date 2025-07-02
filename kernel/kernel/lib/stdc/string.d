module kernel.lib.stdc.string;

// Minimal implementations for BetterC compatibility
extern(C) size_t strlen(const char* s) {
    size_t len = 0;
    while (s[len]) ++len;
    return len;
}

extern(C) int memcmp(const void* a, const void* b, size_t n) {
    const ubyte* ap = cast(const ubyte*)a;
    const ubyte* bp = cast(const ubyte*)b;
    for (size_t i = 0; i < n; ++i) {
        if (ap[i] != bp[i])
            return ap[i] - bp[i];
    }
    return 0;
}

extern(C) void* memcpy(void* dst, const void* src, size_t n) {
    ubyte* dp = cast(ubyte*)dst;
    const ubyte* sp = cast(const ubyte*)src;
    for (size_t i = 0; i < n; ++i)
        dp[i] = sp[i];
    return dst;
}

extern(C) int strcmp(const char* a, const char* b) {
    size_t i = 0;
    while (a[i] && b[i]) {
        if (a[i] != b[i])
            break;
        ++i;
    }
    return cast(int)a[i] - cast(int)b[i];
}

extern(C) int strcasecmp(const char* a, const char* b) {
    size_t i = 0;
    while (a[i] && b[i]) {
        char ca = cast(char)a[i];
        char cb = cast(char)b[i];
        // simple ASCII lowercase conversion
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb)
            break;
        ++i;
    }
    return cast(int)a[i] - cast(int)b[i];
}
