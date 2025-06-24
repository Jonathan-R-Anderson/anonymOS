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
    terminal_writestring("Welcome to ttyShelly stub shell.\r\n");

    char[256] line;

    while (true) {
        // Display shell prompt
        terminal_writestring("wcuser@default:/# ");

        size_t idx = 0;
        // Clear buffer to avoid old data
        for (size_t i = 0; i < line.length; ++i)
            line[i] = 0;

        while (true) {
            char c = keyboard_getchar();

            if (c == '\n') {
                terminal_writestring("\r\n");
                line[idx] = '\0';
                break;
            } else if (c == '\b') {
                if (idx > 0) {
                    idx--;
                    terminal_writestring("\b \b"); // erase character visually
                }
            } else if (idx < line.length - 1) {
                line[idx++] = c;
                terminal_putchar(c); // echo character here instead of IRQ
            }
        }

        if (idx == 0) {
            continue; // Empty input, skip
        }

        // Convert the null-terminated buffer to a slice without using
        // the GC-enabled std.string.fromStringz helper which is
        // incompatible with -betterC.
        auto cmd = line[0 .. idx];

        // Removed debug output

        // Command matching
        if (cmd == "help") {
            terminal_writestring("Available commands:\r\n");
            terminal_writestring("  help - show this message\r\n");
            terminal_writestring("  exit - halt the system\r\n");
        } else if (cmd == "exit") {
            terminal_writestring("Bye!\r\n");
            asm { "hlt"; }
        } else {
            bool suggested = false;
            if (similar(cmd, "help")) {
                terminal_writestring("Unknown command. Did you mean 'help'?\r\n");
                suggested = true;
            } else if (similar(cmd, "exit")) {
                terminal_writestring("Unknown command. Did you mean 'exit'?\r\n");
                suggested = true;
            }

            if (!suggested) {
                terminal_writestring("Unknown command. This is not a system call.\r\n");
            }
        }

        // Prompt will redraw at top of loop
    }
}




extern(C) void ttyShelly_shell()
{
    // Invoke the stub or real Haskell shell if linked.
    ttyShellyMain();
}
