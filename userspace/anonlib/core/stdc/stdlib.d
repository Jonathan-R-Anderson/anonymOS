module core.stdc.stdlib;

alias size_t = ulong;

extern(C):
void* malloc(size_t n){ return null; }
void free(void* p){}
void* calloc(size_t n, size_t s){ return null; }
void* realloc(void* p, size_t n){ return null; }
int atoi(const char* s){ return 0; }
void exit(int status) { while(true){} }
long strtol(const char* nptr, char** end, int base){ return 0; }
long strtoll(const char* nptr, char** end, int base){ return 0; }
double strtod(const char* nptr, char** end){ return 0.0; }
int c_system(const char* cmd){ return 0; }

// Provide alias so existing C code can still link if it expects `system` symbol.
alias system = c_system;

// Convenience D overload accepting a D string.
int system(string cmd)
{
    import mstd.string : toStringz;
    return c_system(cmd.toStringz());
}

int abort(){ while(true){} return 0; } 