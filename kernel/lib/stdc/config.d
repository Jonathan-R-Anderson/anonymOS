module core.stdc.config;

// Stub for core.stdc.config
// Provide C-compatible type aliases for the target.
// For i386-unknown-elf:
alias c_char = char;
alias c_schar = byte;
alias c_uchar = ubyte;
alias c_short = short;
alias c_ushort = ushort;
alias c_int = int;
alias c_uint = uint;
alias c_long = int;      // On i386, long is typically 32-bit
alias c_ulong = uint;    // On i386, unsigned long is typically 32-bit
alias c_longlong = long; // D's long is 64-bit
alias c_ulonglong = ulong; // D's ulong is 64-bit