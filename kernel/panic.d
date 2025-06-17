// kernel/panic.d

module kernel.panic;

import kernel.types : ErrorCode, VGAColor;
import kernel.terminal; // For terminal functions and VGA constants/types

public: // Export kernel_panic

// Helper function to get the length of a C-style null-terminated string
private size_t strlen_c(const(char)* str) {
    size_t len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}

// Helper for kernel_panic to write directly to VGA, bypassing terminal functions initially
private void panic_vga_writestring(const char* s, size_t r, size_t c, ubyte color) {
    ushort* vga = cast(ushort*)VGA_ADDRESS; // VGA_ADDRESS from kernel.terminal
    size_t i = 0;
    while (s[i] != '\0' && (r * VGA_WIDTH + c + i) < (VGA_WIDTH * VGA_HEIGHT)) {
        vga[r * VGA_WIDTH + c + i] = vga_entry(s[i], color); // vga_entry from kernel.terminal
        i++;
    }
}

extern (C) @noreturn void kernel_panic(const char* message, ErrorCode code) {
    asm { "cli"; }

    ubyte panic_color = vga_entry_color(VGAColor.WHITE, VGAColor.RED);

    for (size_t y_idx = 0; y_idx < 5; ++y_idx) {
        for (size_t x_idx = 0; x_idx < VGA_WIDTH; ++x_idx) {
            (cast(ushort*)VGA_ADDRESS)[y_idx * VGA_WIDTH + x_idx] = vga_entry(' ', panic_color);
        }
    }
    panic_vga_writestring("!!! KERNEL PANIC !!!", 0, (VGA_WIDTH - "!!! KERNEL PANIC !!!".length) / 2, panic_color);
    size_t message_len = strlen_c(message);
    panic_vga_writestring(message, 1, (VGA_WIDTH - message_len) / 2, panic_color);

    g_TerminalColor = panic_color;
    terminal_initialize();
    g_TerminalRow = VGA_HEIGHT / 2 - 3;
    g_TerminalColumn = (VGA_WIDTH - "KERNEL PANIC!".length) / 2;
    terminal_writestring("KERNEL PANIC!");
    g_TerminalRow++; g_TerminalColumn = (VGA_WIDTH - message_len) / 2;
    terminal_writestring(message);
    g_TerminalRow++; g_TerminalColumn = (VGA_WIDTH - "Error Code: 0xXX".length) / 2;
    terminal_writestring("Error Code: ");
    terminal_write_hex(cast(uint)code);
    g_TerminalRow+=2; g_TerminalColumn = (VGA_WIDTH - "System Halted.".length) / 2;
    terminal_writestring("System Halted.");

    while (true) {
        asm { "cli"; "hlt"; }
    }
}