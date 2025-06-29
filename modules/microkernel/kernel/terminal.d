// kernel/terminal.d

module kernel.terminal;

import core.volatile; // for volatile semantics on VGA memory

import kernel.types : VGAColor;

public: // Export these functions and constants

// VGA Constants
enum VGA_ADDRESS = 0xB8000;
enum VGA_WIDTH = 80;
enum VGA_HEIGHT = 25;

// Use volatile for memory-mapped I/O to prevent unwanted compiler optimizations.
// FIXME: Previous toolchains reported `volatile(T)` as undefined with -betterC,
// which meant memory-mapped I/O was not guaranteed safe from optimizations.
// The compiler issue appears resolved, so we declare `g_pVGAMemory` using
// `shared(volatile(ushort))*` for correct semantics.
// Older toolchains used here do not support a pointer typed as
// `shared(volatile(T))`.  Use a plain volatile pointer in
// `__gshared` storage to keep the semantics while avoiding parse
// errors when compiling with -betterC.
__gshared volatile(ushort)* g_pVGAMemory =
    cast(volatile(ushort)*) VGA_ADDRESS;
__gshared size_t g_TerminalRow;
__gshared size_t g_TerminalColumn;
__gshared ubyte g_TerminalColor;

// VGA color byte: foreground on background
ubyte vga_entry_color(VGAColor fg, VGAColor bg) {
    return cast(ubyte)(cast(ubyte)fg | (cast(ubyte)bg << 4));
}
// Overload for raw ubyte colors if needed
ubyte vga_entry_color(ubyte fg, ubyte bg) {
    return cast(ubyte)(fg | (bg << 4));
}

// VGA character entry: character and color attribute
ushort vga_entry(char uc, ubyte color) {
    return (cast(ushort) uc) | (cast(ushort) color << 8);
}

void terminal_initialize() {
    g_TerminalRow = 0;
    g_TerminalColumn = 0;
    g_TerminalColor = vga_entry_color(VGAColor.LIGHT_GREY, VGAColor.BLACK);

    for (size_t y = 0; y < VGA_HEIGHT; y++) {
        for (size_t x = 0; x < VGA_WIDTH; x++) {
            const size_t index = y * VGA_WIDTH + x;
            g_pVGAMemory[index] = vga_entry(' ', g_TerminalColor);
        }
    }
    g_TerminalRow = 0;
    g_TerminalColumn = 0;
}

void terminal_scroll() {
    for (size_t y = 0; y < VGA_HEIGHT - 1; y++) {
        for (size_t x = 0; x < VGA_WIDTH; x++) {
            g_pVGAMemory[y * VGA_WIDTH + x] = g_pVGAMemory[(y + 1) * VGA_WIDTH + x];
        }
    }
    for (size_t x = 0; x < VGA_WIDTH; x++) {
        g_pVGAMemory[(VGA_HEIGHT - 1) * VGA_WIDTH + x] = vga_entry(' ', g_TerminalColor);
    }
    g_TerminalRow = VGA_HEIGHT - 1;
}

void terminal_putchar(char c) {
    if (c == '\n') {
        g_TerminalColumn = 0;
        g_TerminalRow++;
    } else {
        const size_t index = g_TerminalRow * VGA_WIDTH + g_TerminalColumn;
        g_pVGAMemory[index] = vga_entry(c, g_TerminalColor);
        g_TerminalColumn++;
    }

    if (g_TerminalColumn >= VGA_WIDTH) {
        g_TerminalColumn = 0;
        g_TerminalRow++;
    }

    if (g_TerminalRow >= VGA_HEIGHT) {
        terminal_scroll();
    }
}

void terminal_write_hex(ulong n) { // Changed parameter from uint to ulong
    const(char)* hex_chars = "0123456789ABCDEF";
    terminal_putchar('0');
    terminal_putchar('x');
    bool leading_zeros = true;
    // For ulong (64-bit), we have 16 hex digits.
    // Loop from the most significant nibble (bits 60-63) down to 0-3.
    // (16 digits - 1) * 4 = 15 * 4 = 60.
    for (int i = 60; i >= 0; i -= 4) {
        ubyte digit = (n >> i) & 0xF;
        if (digit != 0 || !leading_zeros || i == 0) {
            terminal_putchar(hex_chars[digit]);
            leading_zeros = false;
        }
    }
}

void terminal_writestring(const(char)* str) {
    for (size_t i = 0; str[i] != '\0'; i++) {
        terminal_putchar(str[i]);
    }
}

void terminal_writestring_color(const(char)* str, VGAColor fg, VGAColor bg) {
    ubyte original = g_TerminalColor;
    g_TerminalColor = vga_entry_color(fg, bg);
    terminal_writestring(str);
    g_TerminalColor = original;
}
