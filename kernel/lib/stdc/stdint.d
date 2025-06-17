module kernel.lib.stdc.stdint;

// This is a stub module for -betterC compilation.
// It provides essential fixed-width integer type definitions.

public import kernel.lib.stdc.config; // For c_long, c_ulong

// Exact-width integer types
alias int8_t   = byte;
alias int16_t  = short;
alias int32_t  = int;
alias int64_t  = long;

alias uint8_t  = ubyte;
alias uint16_t = ushort;
alias uint32_t = uint;
alias uint64_t = ulong;

// Minimum-width integer types
alias int_least8_t   = byte;
alias int_least16_t  = short;
alias int_least32_t  = int;
alias int_least64_t  = long;

alias uint_least8_t  = ubyte;
alias uint_least16_t = ushort;
alias uint_least32_t = uint;
alias uint_least64_t = ulong;

// Fastest minimum-width integer types
alias int_fast8_t   = byte;
alias int_fast16_t  = int; // Often int is faster than short on 32-bit
alias int_fast32_t  = int;
alias int_fast64_t  = long;

alias uint_fast8_t  = ubyte;
alias uint_fast16_t = uint; // Often uint is faster than ushort on 32-bit
alias uint_fast32_t = uint;
alias uint_fast64_t = ulong;

// Integer types capable of holding object pointers
alias intptr_t  = c_long;  // For i386, pointers are 32-bit
alias uintptr_t = c_ulong; // For i386, pointers are 32-bit

// Greatest-width integer types
alias intmax_t  = long;
alias uintmax_t = ulong;