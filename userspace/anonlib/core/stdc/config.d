module core.stdc.config;

// Minimal freestanding replacements for the basic C types that D programs
// expect when compiling with druntime.  We only define the identifiers that
// the –sh interpreter (and its dependencies) actually reference.
// Nothing here provides real ABI-level compatibility – the goal is only to
// satisfy the compiler during a freestanding cross-compile.

alias time_t   = long;    // seconds since Unix epoch
alias wchar_t  = ushort;  // 16-bit wide char – matches Windows & LLVM default
alias FILE     = void*;   // opaque FILE* handle, never dereferenced

// These appear in a handful of the core.stdc.* wrappers, keep them simple.
alias c_long        = long;
alias c_ulong       = ulong;
alias c_long_double = real;

// Fixed-width integer aliases expected by core.stdc.stdint
alias  int8_t  =  byte;
alias uint8_t  = ubyte;
alias  int16_t =  short;
alias uint16_t = ushort;
alias  int32_t =  int;
alias uint32_t = uint;
alias  int64_t =  long;
alias uint64_t = ulong;

alias intptr_t  = long;
alias uintptr_t = ulong;

alias intmax_t  = long;
alias uintmax_t = ulong;

// least-/fast-width aliases required by core.stdc.stdint
alias  int_least8_t   =  int8_t;
alias uint_least8_t   = uint8_t;
alias  int_least16_t  =  int16_t;
alias uint_least16_t  = uint16_t;
alias  int_least32_t  =  int32_t;
alias uint_least32_t  = uint32_t;
alias  int_least64_t  =  int64_t;
alias uint_least64_t  = uint64_t;

alias  int_fast8_t    =  int8_t;
alias uint_fast8_t    = uint8_t;
// C typically promotes 16-bit fast types to at least 32 bits
alias  int_fast16_t   =  int32_t;
alias uint_fast16_t   = uint32_t;
alias  int_fast32_t   =  int32_t;
alias uint_fast32_t   = uint32_t;
alias  int_fast64_t   =  int64_t;
alias uint_fast64_t   = uint64_t; 