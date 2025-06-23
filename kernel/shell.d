module kernel.shell;

import kernel.terminal : terminal_writestring, terminal_writestring_color;

/// Stub implementation for the Haskell ttyShelly shell entry point.
/// The real implementation is expected to come from the userland
/// Haskell code, but that is currently not linked in the kernel build.
extern(C) void ttyShellyMain()
{
    terminal_writestring("Welcome to ttyShelly stub shell.\n");
    while(true) {
        terminal_writestring("ttyShelly> ");
        asm { "hlt"; }
    }
}

extern(C) void ttyShelly_shell()
{
    // Invoke the stub or real Haskell shell if linked.
    ttyShellyMain();
}
