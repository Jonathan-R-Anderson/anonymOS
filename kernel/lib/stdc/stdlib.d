module kernel.lib.stdc.stdlib;

// Minimal C standard library function declarations for -betterC builds.
// These are provided by the kernel's memory management subsystem.
extern(C) void* malloc(size_t size);
extern(C) void* realloc(void* ptr, size_t size);
extern(C) void free(void* ptr);
