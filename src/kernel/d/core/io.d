module core.io;

extern (C):

@nogc nothrow:

void outb(ushort port, ubyte value) {
    import ldc.llvmasm;
    __asm("outb $1, $0", "{dx},{al}", port, value);
}

ubyte inb(ushort port) {
    import ldc.llvmasm;
    return __asm!ubyte("inb $1, $0", "={al},{dx}", port);
}

// Serial output self-disables once the UART proves unreadable.  On the real FW13 there is no serial
// reader; if its 16550 THR-empty bit ever stops setting, the spin below caps EVERY char, and because
// kchar inherits the caller's IF (it does NOT cli/sti), a flood of chars in an IF=0 syscall context
// (e.g. usb-storage's device-list fprintf dump) pins the CPU with interrupts masked → the 4 kHz timer
// stops → PS/2 mouse dies → HARD FREEZE (black screen, dead cursor).  Diagnosed by a 3-agent workflow
// as the concrete IF=0 stall mechanism.  Fix: cap the spin TIGHT, and after a streak of caps latch the
// port dead so no char ever spins again.  QEMU's UART drains instantly (bit always set) so it never
// caps, never latches — serial.log keeps working for testing.  The byte is always in the klog ring
// above (→ /run/klog → the Logs app + the USB stick), so a dropped serial copy loses nothing.
__gshared bool g_serialDead      = false;
__gshared uint g_serialCapStreak = 0;
void kchar(char c) {
    klogRingPut(c);
    if (g_serialDead) return;                        // UART proven stuck/unread → never spin here again
    uint spin = 0;
    while ((inb(0x3F8 + 5) & 0x20) == 0) {
        if (++spin > 4096) {                         // THR never emptied → this char is lost to serial
            if (++g_serialCapStreak >= 8) g_serialDead = true;   // 8 caps in a row → stop using serial
            return;
        }
    }
    g_serialCapStreak = 0;                           // a real send → UART is alive; reset the streak
    outb(0x3F8, c);
}

// ── Kernel log RAM ring ───────────────────────────────────────────────────────
// EVERY byte that reaches the serial port passes through kchar(): kernel klog()
// (via console_putchar), userspace stdout/stderr on FD_CONSOLE (lkl-boot/iwlwifi,
// dbus-daemon, NetworkManager, wpa_supplicant, the boot-doctor), and the *.log
// rtfile serial mirror.  Tee that single choke-point into a 4 MiB drop-oldest ring
// so the on-desktop "Logs" viewer can read the FULL boot + driver log through the
// synthetic file /run/klog — real hardware has NO serial capture, and photographing
// scrolling boot text is impossible.  g_klogHead is a MONOTONIC byte counter (2^64
// range — never wraps in practice); the ring index is head & (SIZE-1).  No
// allocation, no framebuffer access, no cli/sti: safe in syscall/exception context.
enum ulong KLOG_RING_SIZE = 4UL << 20;   // 4 MiB, power of two → mask instead of modulo
__gshared ubyte[KLOG_RING_SIZE] g_klogRing;
__gshared ulong g_klogHead = 0;
void klogRingPut(char c) {
    g_klogRing[cast(size_t)(g_klogHead & (KLOG_RING_SIZE - 1))] = cast(ubyte)c;
    ++g_klogHead;
}

// Boot/install diagnostics: mirror klog to the framebuffer too, not just serial.
// console_putchar writes the char to serial (kchar) AND, while g_fbConsoleEnabled
// is set, to the framebuffer text console.  g_fbConsoleEnabled starts true and is
// cleared the moment userspace (the compositor) takes over the framebuffer, so this
// makes the ENTIRE boot sequence visible on screen — including the d_kernel_main
// early setup that previously logged to serial only — then goes silent once the
// desktop/installer GUI comes up.  Safe before the framebuffer exists: fb_putchar
// (reached via console_putchar) early-returns when g_fb is null.
void klog(const(char)* msg) {
    import core.console : console_putchar;
    while (*msg) {
        console_putchar(*msg++);
    }
}

void klog_hex(ulong val) {
    char[17] buf;
    char[16] hex = "0123456789abcdef";
    for (int i = 15; i >= 0; i--) {
        buf[i] = hex[val & 0xF];
        val >>= 4;
    }
    buf[16] = 0;
    klog(buf.ptr);
}

// Decimal printer for human-readable stats (frame rates, milliseconds, etc.).
void klog_dec(ulong val) {
    char[21] buf;
    int i = 20;
    buf[i--] = 0;
    if (val == 0) { buf[i--] = '0'; }
    else while (val > 0 && i >= 0) { buf[i--] = cast(char)('0' + (val % 10)); val /= 10; }
    klog(buf.ptr + i + 1);
}

// VGA text mode
__gshared ushort* vga_buffer;
__gshared uint vga_row = 0;
__gshared uint vga_col = 0;
__gshared ubyte vga_color = 0x07; // Light gray on black

void vga_set_mode_3() {
    // Try to set VGA mode 3 (80x25 text mode) via VGA registers
    // This is a simplified attempt - full VGA mode setting requires more

    // Disable interrupts during VGA programming
    asm @nogc nothrow { cli; }

    // Set misc output register (port 0x3C2) for color text mode
    outb(0x3C2, 0x67);

    // Re-enable screen (sequencer register)
    outb(0x3C4, 0x00);  // Sequencer address register
    outb(0x3C5, 0x03);  // Sequencer data - async reset

    outb(0x3C4, 0x01);  // Clocking mode register
    outb(0x3C5, 0x00);  // 8 dots per char

    outb(0x3C4, 0x02);  // Map mask
    outb(0x3C5, 0x03);  // Enable planes 0-1

    outb(0x3C4, 0x03);  // Character map select
    outb(0x3C5, 0x00);  // Default font

    outb(0x3C4, 0x04);  // Memory mode
    outb(0x3C5, 0x02);  // Extended memory

    // Restore async reset
    outb(0x3C4, 0x00);
    outb(0x3C5, 0x03);

    asm @nogc nothrow { sti; }
}

void vga_init(ulong hhdm_offset) {
    klog("Preparing VGA text buffer while retaining framebuffer graphics...\n");

    vga_buffer = cast(ushort*)(0xB8000 + hhdm_offset);
    klog("VGA buffer address: ");
    klog_hex(cast(ulong)vga_buffer);
    klog("\n");

    // Keep the firmware framebuffer mode active so the native desktop compositor
    // remains visible, but initialize VGA text memory for any legacy writers.
    for (uint i = 0; i < 80 * 25; i++) {
        vga_buffer[i] = 0x0720;
    }
    vga_row = 0;
    vga_col = 0;
}

void vga_scroll() {
    // Move all lines up
    for (uint i = 0; i < 24 * 80; i++) {
        vga_buffer[i] = vga_buffer[i + 80];
    }
    // Clear last line
    for (uint i = 24 * 80; i < 25 * 80; i++) {
        vga_buffer[i] = 0x0720;
    }
    vga_row = 24;
    vga_col = 0;
}

void vga_putchar(char c) {
    if (c == '\n') {
        vga_col = 0;
        vga_row++;
        if (vga_row >= 25) {
            vga_scroll();
        }
        return;
    }
    if (c == '\r') {
        vga_col = 0;
        return;
    }
    if (c == '\b') {
        if (vga_col > 0) {
            vga_col--;
            vga_buffer[vga_row * 80 + vga_col] = (vga_color << 8) | ' ';
        }
        return;
    }

    vga_buffer[vga_row * 80 + vga_col] = (vga_color << 8) | c;
    vga_col++;
    if (vga_col >= 80) {
        vga_col = 0;
        vga_row++;
        if (vga_row >= 25) {
            vga_scroll();
        }
    }
}

void vga_puts(const(char)* str) {
    while (*str) {
        vga_putchar(*str++);
    }
}
