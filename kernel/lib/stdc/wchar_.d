module kernel.lib.stdc.wchar_;

// This is a stub module for -betterC compilation.
// It prevents the full core.stdc.wchar_ from being pulled in.

import kernel.lib.stdc.stdio; // The stubbed stdio

// Provide a minimal definition for wchar_t.
// The compiler error suggested `dchar`, which is a UTF-32 char in D.
alias wchar_t = dchar;
