module kernel.shell;

extern(C) void ttyShellyMain(); // From Haskell code

extern (C) void ttyShelly_shell() {
    // Initialize and invoke the Haskell ttyShelly shell.
    ttyShellyMain();
}
