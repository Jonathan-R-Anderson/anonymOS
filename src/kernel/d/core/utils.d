module core.utils;

extern (C):

@nogc nothrow:

void* memset(void* dest, int val, size_t count) {
    ubyte* ptr = cast(ubyte*)dest;
    while(count--) *ptr++ = cast(ubyte)val;
    return dest;
}

void* memcpy(void* dest, const(void)* src, size_t count) {
    ubyte* d = cast(ubyte*)dest;
    const(ubyte)* s = cast(const(ubyte)*)src;
    while(count--) *d++ = *s++;
    return dest;
}

int memcmp(const(void)* s1, const(void)* s2, size_t n) {
    const(ubyte)* p1 = cast(const(ubyte)*)s1;
    const(ubyte)* p2 = cast(const(ubyte)*)s2;
    foreach (i; 0 .. n) {
        if (p1[i] < p2[i]) return -1;
        if (p1[i] > p2[i]) return 1;
    }
    return 0;
}

void* memmove(void* dest, const(void)* src, size_t n) {
    ubyte* d = cast(ubyte*)dest;
    const(ubyte)* s = cast(const(ubyte)*)src;
    if (d < s) {
        foreach (i; 0 .. n) d[i] = s[i];
    } else {
        foreach_reverse (i; 0 .. n) d[i] = s[i];
    }
    return dest;
}

size_t strlen(const(char)* s) {
    size_t n = 0;
    while (s[n] != 0) {
        n++;
    }
    return n;
}

int strcmp(const(char)* s1, const(char)* s2) {
    size_t i = 0;
    while (true) {
        const ubyte a = cast(ubyte)s1[i];
        const ubyte b = cast(ubyte)s2[i];
        if (a != b) {
            return (a < b) ? -1 : 1;
        }
        if (a == 0) {
            return 0;
        }
        i++;
    }
}
