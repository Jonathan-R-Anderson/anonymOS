module kernel.lib.stdc.config;

// Stub for core.stdc.config
// Provide C-compatible type aliases for the target.
// For x86_64-unknown-elf:
alias c_char = char;
alias c_schar = byte;
alias c_uchar = ubyte;
alias c_short = short;
alias c_ushort = ushort;
alias c_int = int;
alias c_uint = uint;
alias c_long = long;     // On x86-64, long is typically 64-bit
alias c_ulong = ulong;   // On x86-64, unsigned long is typically 64-bit
alias c_longlong = long; // D's long is 64-bit
alias c_ulonglong = ulong; // D's ulong is 64-bit