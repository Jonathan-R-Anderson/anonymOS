module kernel.shell;

import kernel.terminal : terminal_writestring, terminal_putchar;
import kernel.keyboard : scancode_to_char;
import kernel.io : inb;

enum KBD_STATUS_PORT = 0x64;
enum KBD_DATA_PORT = 0x60;

private ubyte read_scancode() {
    while ((inb(KBD_STATUS_PORT) & 1) == 0) {
        // busy wait for key
    }
    return inb(KBD_DATA_PORT);
}

private char read_char() {
    while (true) {
        ubyte sc = read_scancode();
        if (sc & 0x80) continue; // ignore releases
        char c = scancode_to_char(sc);
        if (c != 0) return c;
    }
}

private bool equals(in char[] buf, size_t len, const(char)* str) {
    size_t i;
    for (i = 0; i < len; i++) {
        if (str[i] == '\0' || buf[i] != str[i])
            return false;
    }
    return str[i] == '\0';
}

extern (C) void basic_tty_shell() {
    terminal_writestring("Basic TTY Shell. Type 'help' or 'exit'.\n");
    char[128] buffer;
    size_t len;
    while (true) {
        terminal_writestring("> ");
        len = 0;
        while (true) {
            char ch = read_char();
            if (ch == '\n') {
                terminal_putchar('\n');
                buffer[len] = '\0';
                break;
            } else if (ch == '\b') {
                if (len > 0) {
                    len--;
                    terminal_writestring("\b \b");
                }
            } else {
                if (len < buffer.length - 1) {
                    buffer[len++] = ch;
                    terminal_putchar(ch);
                }
            }
        }
        if (len == 0) continue;
        if (equals(buffer[], len, "help")) {
            terminal_writestring("Commands: help, exit\n");
        } else if (equals(buffer[], len, "exit")) {
            terminal_writestring("Exiting shell.\n");
            return;
        } else {
            terminal_writestring("You typed: ");
            terminal_writestring(buffer.ptr);
            terminal_putchar('\n');
        }
    }
}