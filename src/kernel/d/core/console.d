module core.console;

import core.io : kchar;
import arch.x86_64.bootstrap : fb_putchar;

@nogc nothrow:

// When userspace takes over the framebuffer (Hyprland's CREATE_DUMB returns the
// real g_fb pages), the kernel must stop drawing its debug/text console onto the
// framebuffer or it scribbles over the compositor's output.  Serial (kchar) stays
// on so the log is unaffected.  Cleared by the DRM dumb-buffer path in posix.d.
__gshared bool g_fbConsoleEnabled = true;

// Set true once the compositor owns the framebuffer (its first full-screen dumb
// buffer / present).  After that the kernel must NEVER draw to the framebuffer —
// not the debug console, not a re-enabled fault log, not the direct-fb diagnostics
// — or the text scribbles over the live desktop.  Serial (kchar) is unaffected.
__gshared bool g_desktopClaimedFb = false;

void console_set_framebuffer_enabled(bool enabled) {
    g_fbConsoleEnabled = enabled;
}

void console_force_framebuffer_log() {
    // Once the desktop owns the screen, a recoverable userspace fault (SIGSEGV) must
    // not re-enable the on-screen log — that scribbles the crash + every later klog
    // over the compositor's output.  The fault still goes to serial.
    if (g_desktopClaimedFb) return;
    g_fbConsoleEnabled = true;
}

void console_putchar(char c) {
    kchar(c);
    if (g_fbConsoleEnabled && !g_desktopClaimedFb)
        fb_putchar(c);
}

void console_serial_putchar(char c) {
    kchar(c);
}

void console_framebuffer_putchar(char c) {
    if (g_desktopClaimedFb) return;   // desktop owns the screen — don't scribble over it
    fb_putchar(c);
}

void console_framebuffer_write(const(char)* s) {
    if (s is null) return;
    while (*s) {
        console_framebuffer_putchar(*s++);
    }
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
