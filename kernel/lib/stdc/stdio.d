module kernel.lib.stdc.stdio;

// Minimal declarations for FILE operations.
// These allow compiling code that references basic C stdio
// when targeting a freestanding kernel with -betterC.

import kernel.lib.stdc.stdint; // for size_t alias via c_ulong etc if needed

extern(C):
struct FILE { int _dummy; }

FILE* fopen(const(char)* path, const(char)* mode);
int fclose(FILE* f);
char* fgets(char* s, int size, FILE* stream);
size_t fwrite(const(void)* ptr, size_t size, size_t nmemb, FILE* stream);
size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream);
