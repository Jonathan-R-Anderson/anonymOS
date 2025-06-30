module core.stdc.string;

extern(C):
int strcasecmp(const char*, const char*);
int strncasecmp(const char*, const char*, ulong n);

// Remove the previous prototypes – we provide full definitions below that
// are usable at compile-time.  The compiler will infer the extern(C)
// linkage from the attribute.

pure nothrow @nogc @trusted pragma(inline, true)
extern(C) size_t strlen(const char* s)
{
    size_t i = 0;
    if(s is null) return 0;
    while(s[i]) ++i;
    return i;
}

pure nothrow @nogc @trusted pragma(inline, true)
extern(C) void* memcpy(void* dst, const void* src, size_t n)
{
    auto d = cast(ubyte*)dst;
    auto s = cast(const(ubyte)*)src;
    foreach(i; 0 .. n) d[i] = s[i];
    return dst;
}

pure nothrow @nogc @trusted pragma(inline, true)
extern(C) int memcmp(const void* a, const void* b, size_t n)
{
    auto pa = cast(const(ubyte)*)a;
    auto pb = cast(const(ubyte)*)b;
    foreach(i; 0 .. n)
    {
        int diff = pa[i] - pb[i];
        if(diff) return diff;
    }
    return 0;
}

pure nothrow @nogc @trusted pragma(inline, true)
extern(C) int strcmp(const char* a, const char* b)
{
    size_t i = 0;
    while(a[i] && b[i])
    {
        int diff = a[i] - b[i];
        if(diff) return diff;
        ++i;
    }
    return a[i] - b[i];
}

// Implementation of memset – required by druntime
pure nothrow @nogc @trusted pragma(inline, true)
extern(C) void* memset(void* dst, int c, size_t n)
{
    auto d = cast(ubyte*)dst;
    auto val = cast(ubyte)c;
    foreach(i; 0 .. n)
        d[i] = val;
    return dst;
} 