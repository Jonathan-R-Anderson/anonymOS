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

void kchar(char c) {
    // Serial port 0x3F8
    // Wait for transmit empty
    while ((inb(0x3F8 + 5) & 0x20) == 0) {}
    outb(0x3F8, c);
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
