module core.stdc.stdlib;

alias size_t = ulong;

extern(C):
void* malloc(size_t n){ return null; }
void free(void* p){}
void* calloc(size_t n, size_t s){ return null; }
void* realloc(void* p, size_t n){ return null; }
int atoi(const char* s){ return 0; }
void exit(int status) { while(true){} } 