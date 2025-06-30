module core.stdc.stdio;

public import core.stdc.config : FILE, fpos_t, wchar_t;

extern(C):

__gshared FILE* stdin;
__gshared FILE* stdout;
__gshared FILE* stderr;

int fputc(int, FILE*);
int fputs(const char*, FILE*);
int putchar(int);
int puts(const char*);

int printf(const char*, ...);
int fprintf(FILE*, const char*, ...);
int sprintf(char*, const char*, ...);
int snprintf(char*, size_t, const char*, ...);

size_t fread(void*, size_t, size_t, FILE*);
size_t fwrite(const void*, size_t, size_t, FILE*);

int fflush(FILE*);
int fopen(const char*, const char*);
int fclose(FILE*); 