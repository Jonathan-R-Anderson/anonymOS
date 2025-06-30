module core.stdc.wchar_;

public import core.stdc.config : wchar_t, FILE;

extern(C):
// Provide only the few prototypes that –sh may reference.  They are
// declared but left unimplemented – linking resolves them to the stubs in
// kernel.lib.posix_stubs or they remain unused.

int fputws(const(wchar_t)*, FILE*);
int fwide(FILE*, int); 