module core.console;

import core.io : kchar;
import arch.x86_64.bootstrap : fb_putchar;

@nogc nothrow:

// When userspace takes over the framebuffer (Hyprland's CREATE_DUMB returns the
// real g_fb pages), the kernel must stop drawing its debug/text console onto the
// framebuffer or it scribbles over the compositor's output.  Serial (kchar) stays
// on so the log is unaffected.  Cleared by the DRM dumb-buffer path in posix.d.
__gshared bool g_fbConsoleEnabled = true;

void console_putchar(char c) {
    kchar(c);
    if (g_fbConsoleEnabled)
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
