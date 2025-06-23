module kernel.lib.stdc.stdio;

// Minimal declarations for FILE operations.
// These allow compiling code that references basic C stdio
// when targeting a freestanding kernel with -betterC.

import kernel.lib.stdc.stdint; // for size_t alias via c_ulong etc if needed

extern(C):

/// Represents a dummy FILE handle. The structure layout is irrelevant as
/// the kernel does not provide real stdio capabilities yet.
struct FILE { int _dummy; }

// -------------------------------------------------------------------------
// Minimal stub implementations
// -------------------------------------------------------------------------
// The original code referenced C stdio functions.  When building the kernel
// in freestanding mode with `-betterC` there is no libc available which
// results in unresolved symbols at link time.  To allow the kernel to build we
// provide very small stub versions here.  They do nothing and simply satisfy
// the linker.

FILE* fopen(const(char)* path, const(char)* mode)
{
    return null;
}

int fclose(FILE* f)
{
    return 0;
}

char* fgets(char* s, int size, FILE* stream)
{
    return null;
}

size_t fwrite(const(void)* ptr, size_t size, size_t nmemb, FILE* stream)
{
    return 0;
}

size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream)
{
    return 0;
}
