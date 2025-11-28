module anonymos.kernel.libc_stubs;

import anonymos.kernel.heap : kmalloc, kfree;
import anonymos.kernel.memory : memcpy, memset;
import anonymos.console : print, printLine;

extern(C):

// Memory management with size tracking
struct AllocHeader
{
    size_t size;
    size_t magic;
}

enum MAGIC = 0xDEADBEEF;

void* malloc(size_t size)
{
    size_t total = size + AllocHeader.sizeof;
    void* ptr = kmalloc(total);
    if (!ptr) return null;
    
    AllocHeader* header = cast(AllocHeader*)ptr;
    header.size = size;
    header.magic = MAGIC;
    
    return ptr + AllocHeader.sizeof;
}

void free(void* ptr)
{
    if (!ptr) return;
    
    void* realPtr = ptr - AllocHeader.sizeof;
    AllocHeader* header = cast(AllocHeader*)realPtr;
    
    if (header.magic != MAGIC)
    {
        // Not allocated by us or corrupted, or allocated by raw kmalloc
        // Just pass to kfree (which is no-op anyway)
        kfree(ptr); 
        return;
    }
    
    // Invalidate magic to detect double free
    header.magic = 0;
    kfree(realPtr);
}

void* realloc(void* ptr, size_t size)
{
    if (!ptr) return malloc(size);
    if (size == 0) { free(ptr); return null; }
    
    void* realPtr = ptr - AllocHeader.sizeof;
    AllocHeader* header = cast(AllocHeader*)realPtr;
    
    // Check if it's our allocation
    if (header.magic != MAGIC)
    {
        // Can't realloc unknown pointer
        return null;
    }
    
    if (header.size >= size)
    {
        // Shrinking or same size: reuse
        // Update size? No, keep capacity.
        return ptr;
    }
    
    // Allocate new
    void* newPtr = malloc(size);
    if (!newPtr) return null;
    
    // Copy old data
    memcpy(newPtr, ptr, header.size);
    
    // Free old
    free(ptr);
    
    return newPtr;
}

void* calloc(size_t nmemb, size_t size)
{
    size_t total = nmemb * size;
    void* ptr = malloc(total);
    if (ptr)
    {
        memset(ptr, 0, total);
    }
    return ptr;
}

// String/Memory manipulation
// Note: D runtime usually provides memcpy/memset, but we might need to expose them for C libs
// if they are not picked up from builtins.
// For now, let's assume builtins handle standard mem* functions.
// But we need strtol.

long strtol(const(char)* nptr, char** endptr, int base)
{
    // Minimal implementation
    return 0;
}

// Wrapper for newer glibc versions
long __isoc23_strtol(const(char)* nptr, char** endptr, int base)
{
    return strtol(nptr, endptr, base);
}

// String/Memory utils
int bcmp(const void* s1, const void* s2, size_t n)
{
    import anonymos.kernel.memory : memcmp;
    return memcmp(s1, s2, n);
}

char* strrchr(const(char)* s, int c)
{
    char* last = null;
    while (*s)
    {
        if (*s == c) last = cast(char*)s;
        s++;
    }
    if (c == 0) return cast(char*)s;
    return last;
}

char* strchr(const(char)* s, int c)
{
    while (*s != cast(char)c)
    {
        if (*s == 0) return null;
        s++;
    }
    return cast(char*)s;
}

// errno
__gshared int g_errno;
int* __errno_location()
{
    return &g_errno;
}

// strtoul
ulong strtoul(const(char)* nptr, char** endptr, int base)
{
    return 0; // minimal
}

ulong __isoc23_strtoul(const(char)* nptr, char** endptr, int base)
{
    return strtoul(nptr, endptr, base);
}

// sysconf
long sysconf(int name)
{
    return -1;
}

// File I/O stubs
struct FILE;
__gshared FILE* stderr = null;

int fputc(int c, FILE* stream)
{
    // Ignore
    return c;
}

FILE* fopen(const(char)* filename, const(char)* mode)
{
    print("[libc] fopen called (unsupported): ");
    // print(filename); // filename is C string, print expects D string or needs conversion
    printLine("");
    return null;
}

size_t fwrite(const(void)* ptr, size_t size, size_t nmemb, FILE* stream)
{
    return size * nmemb;
}

int vfprintf(FILE* stream, const(char)* format, void* ap)
{
    return 0;
}

// Math stubs
float hypotf(float x, float y)
{
    return 0; // TODO: Implement sqrt
}

void sincosf(float x, float* s, float* c)
{
    *s = 0;
    *c = 1;
}

float ceilf(float x)
{
    long i = cast(long)x;
    if (x > i) return i + 1;
    return i;
}

float floorf(float x)
{
    long i = cast(long)x;
    if (x < i) return i - 1;
    return i;
}

float tanf(float x)
{
    return 0;
}

// close
int close(int fd)
{
    return -1;
}

// Locale stubs
struct __locale_struct;
alias locale_t = __locale_struct*;

locale_t newlocale(int category_mask, const(char)* locale, locale_t base)
{
    return null;
}

locale_t uselocale(locale_t newloc)
{
    return null;
}

void freelocale(locale_t loc)
{
}

// mprotect
int mprotect(void* addr, size_t len, int prot)
{
    return -1;
}

// strerror
char* strerror(int errnum)
{
    return cast(char*)"unknown error";
}

// open64
int open64(const(char)* pathname, int flags, ...)
{
    return -1;
}

// setlocale
char* setlocale(int category, const(char)* locale)
{
    return null;
}

// snprintf/vsnprintf
int snprintf(char* str, size_t size, const(char)* format, ...)
{
    return 0;
}

int vsnprintf(char* str, size_t size, const(char)* format, void* ap)
{
    return 0;
}

// fstat64
struct stat64;
int fstat64(int fd, stat64* buf)
{
    return -1;
}

// mmap64
void* mmap64(void* addr, size_t len, int prot, int flags, int fd, long offset)
{
    return cast(void*)-1;
}

// munmap
int munmap(void* addr, size_t length)
{
    return -1;
}

// stdio
int feof(FILE* stream)
{
    return 1;
}

int ferror(FILE* stream)
{
    return 1;
}

// Math
double floor(double x)
{
    long i = cast(long)x;
    if (x < i) return i - 1;
    return i;
}

// abort
void abort()
{
    printLine("ABORT!");
    while(true) {}
}

// Pthreads
int pthread_mutex_lock(void* mutex) { return 0; }
int pthread_mutex_unlock(void* mutex) { return 0; }
int pthread_mutex_init(void* mutex, const(void)* attr) { return 0; }
int pthread_mutex_destroy(void* mutex) { return 0; }

// atexit
int atexit(void function() func)
{
    return 0;
}

// fopen64
FILE* fopen64(const(char)* filename, const(char)* mode) { return null; }

// memchr
void* memchr(const(void)* s, int c, size_t n)
{
    const(ubyte)* p = cast(const(ubyte)*)s;
    foreach(i; 0..n)
    {
        if (p[i] == cast(ubyte)c) return cast(void*)(p + i);
    }
    return null;
}

// strcpy
char* strcpy(char* dest, const(char)* src)
{
    char* d = dest;
    while (*src) *d++ = *src++;
    *d = 0;
    return dest;
}

// strlen
size_t strlen(const(char)* s)
{
    size_t len = 0;
    while (*s++) len++;
    return len;
}

// strncmp
int strncmp(const(char)* s1, const(char)* s2, size_t n)
{
    while (n > 0)
    {
        if (*s1 != *s2) return (*s1 < *s2) ? -1 : 1;
        if (*s1 == 0) return 0;
        s1++; s2++; n--;
    }
    return 0;
}

// strncpy
char* strncpy(char* dest, const(char)* src, size_t n)
{
    size_t i;
    for (i = 0; i < n && src[i] != 0; i++)
        dest[i] = src[i];
    for ( ; i < n; i++)
        dest[i] = 0;
    return dest;
}

// strcat
char* strcat(char* dest, const(char)* src)
{
    char* d = dest;
    while (*d) d++;
    while (*src) *d++ = *src++;
    *d = 0;
    return dest;
}

// getenv
char* getenv(const(char)* name)
{
    return null;
}

// strcmp
int strcmp(const(char)* s1, const(char)* s2)
{
    while (*s1 && (*s1 == *s2))
    {
        s1++;
        s2++;
    }
    return *cast(const(ubyte)*)s1 - *cast(const(ubyte)*)s2;
}

// strstr
char* strstr(const(char)* haystack, const(char)* needle)
{
    if (!*needle) return cast(char*)haystack;
    for ( ; *haystack; haystack++)
    {
        if (*haystack != *needle) continue;
        const(char)* h = haystack;
        const(char)* n = needle;
        while (*n && *h == *n)
        {
            h++; n++;
        }
        if (!*n) return cast(char*)haystack;
    }
    return null;
}

// setjmp
// FreeType uses _setjmp. We map it to our kernel setjmp.
import anonymos.kernel.posixutils.context : setjmp, jmp_buf;

int _setjmp(void* env)
{
    return setjmp(*cast(jmp_buf*)env);
}

size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream)
{
    return 0;
}

int fclose(FILE* stream)
{
    return -1;
}

int fseek(FILE* stream, long offset, int whence)
{
    return -1;
}

long ftell(FILE* stream)
{
    return -1;
}

// Assert
void __assert_fail(const(char)* assertion, const(char)* file, uint line, const(char)* functionName)
{
    printLine("ASSERTION FAILED!");
    // TODO: Print details
    while(true) {}
}

// QSort (used by HarfBuzz)
void qsort(void* base, size_t nmemb, size_t size, int function(const(void)*, const(void)*) compar)
{
    // Minimal bubble sort for now (slow but simple)
    if (nmemb < 2 || size == 0) return;
    
    ubyte* p = cast(ubyte*)base;
    ubyte* tmp = cast(ubyte*)kmalloc(size);
    
    for (size_t i = 0; i < nmemb - 1; i++)
    {
        for (size_t j = 0; j < nmemb - i - 1; j++)
        {
            void* a = p + j * size;
            void* b = p + (j + 1) * size;
            
            if (compar(a, b) > 0)
            {
                // Swap
                // memcpy tmp, a, size
                for(size_t k=0; k<size; k++) tmp[k] = (cast(ubyte*)a)[k];
                // memcpy a, b, size
                for(size_t k=0; k<size; k++) (cast(ubyte*)a)[k] = (cast(ubyte*)b)[k];
                // memcpy b, tmp, size
                for(size_t k=0; k<size; k++) (cast(ubyte*)b)[k] = tmp[k];
            }
        }
    }
    
    kfree(tmp);
}
