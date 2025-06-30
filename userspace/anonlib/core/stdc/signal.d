module core.stdc.signal;

alias sigfn_t = void function(int);
extern(C) sigfn_t signal(int, sigfn_t){ return null; } 