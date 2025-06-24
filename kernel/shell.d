module kernel.shell;

import kernel.terminal : terminal_writestring, terminal_writestring_color, terminal_putchar;
import kernel.keyboard : keyboard_getchar;

private bool similar(const(char)[] a, const(char)[] b)
{
    size_t la = a.length;
    size_t lb = b.length;
    size_t minLen = (la < lb) ? la : lb;
    size_t diff = (la > lb) ? la - lb : lb - la;
    for(size_t i = 0; i < minLen; ++i) {
        if (a[i] != b[i]) diff++;
    }
    return diff <= 1;
}

/// Stub implementation for the Haskell ttyShelly shell entry point.
/// The real implementation is expected to come from the userland
/// Haskell code, but that is currently not linked in the kernel build.
extern(C) void ttyShellyMain()
{
    terminal_writestring("Welcome to ttyShelly stub shell.\n");
    char[256] line;
    while (true) {
        size_t idx = 0;
        terminal_writestring("wcuser@default:/# ");
        while (true) {
            char c = keyboard_getchar();
            if (c == '\n') {
                terminal_putchar('\n');
                line[idx] = '\0';
                break;
            } else if (c == '\b') {
                if (idx > 0) {
                    idx--;
                    terminal_writestring("\b \b");
                }
            } else {
                line[idx++] = c;
                // Character was already echoed by the keyboard interrupt
                // handler. The shell only needs to store it.
            }
        }

        if (idx == 0) continue;

        if (line[0..idx] == "help") {
            terminal_writestring("Available commands:\n");
            terminal_writestring("  help - show this message\n");
            terminal_writestring("  exit - halt the system\n");
        } else if (line[0..idx] == "exit") {
            terminal_writestring("Bye!\n");
            asm { "hlt"; }
        } else {
            bool suggested = false;
            if (similar(line[0..idx], "help")) {
                terminal_writestring("Unknown command. Did you mean 'help'?\n");
                suggested = true;
            } else if (similar(line[0..idx], "exit")) {
                terminal_writestring("Unknown command. Did you mean 'exit'?\n");
                suggested = true;
            }
            if (!suggested) {
                terminal_writestring("Unknown command. This is not a system call.\n");
            }
        }
    }
}

extern(C) void ttyShelly_shell()
{
    // Invoke the stub or real Haskell shell if linked.
    ttyShellyMain();
}
