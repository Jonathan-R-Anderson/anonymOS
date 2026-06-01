module core.console;

import core.io : kchar;
import arch.x86_64.bootstrap : fb_putchar;

@nogc nothrow:

void console_putchar(char c) {
    kchar(c);
    fb_putchar(c);
}

void console_write(const(char)* s, size_t n) {
    if (s is null || n == 0) return;
    foreach (i; 0 .. n) {
        console_putchar(s[i]);
    }
}

void console_backspace() {
    console_putchar('\b');
    console_putchar(' ');
    console_putchar('\b');
}
