module kernel.keyboard;

// Use kernel.terminal for output
import kernel.terminal : terminal_writestring, terminal_putchar;
import kernel.lib.stdc.stdint; // Use local stdint stub

// If needed for more direct keyboard controller interaction:
// extern (C) {
//     ubyte inb(ushort port);
//     void outb(ushort port, ubyte data);
// }

public:

enum INPUT_BUF_SIZE = 128;
__gshared char[INPUT_BUF_SIZE] input_buffer;
__gshared size_t input_head = 0;
__gshared size_t input_tail = 0;

char keyboard_getchar()
{
    while (input_head == input_tail) {
        asm { "hlt"; }
    }
    char c = input_buffer[input_tail];
    input_tail = (input_tail + 1) % INPUT_BUF_SIZE;

    // Debug: show retrieved character to verify ring buffer activity
    terminal_writestring("[GET]");
    terminal_putchar(c);
    terminal_writestring("\n");

    return c;
}

// Converts a scancode (Scan Code Set 1, make code) to its corresponding ASCII character.
// Returns 0 (null char) if the scancode is not printable or not mapped.
char scancode_to_char(ubyte scancode) {
    // Does not handle shift, ctrl, alt, or key releases yet.
    // Only handles key presses (scancode bit 7 is 0).
    // The check for key release (scancode & 0x80) is done by the caller in interrupts.d

    switch (scancode) {
        // Row 1 (Numbers and symbols)
        case 0x02: return '1'; case 0x03: return '2'; case 0x04: return '3';
        case 0x05: return '4'; case 0x06: return '5'; case 0x07: return '6';
        case 0x08: return '7'; case 0x09: return '8'; case 0x0A: return '9';
        case 0x0B: return '0'; case 0x0C: return '-'; case 0x0D: return '=';
        // Row 2 (QWERTY)
        case 0x10: return 'q'; case 0x11: return 'w'; case 0x12: return 'e';
        case 0x13: return 'r'; case 0x14: return 't'; case 0x15: return 'y';
        case 0x16: return 'u'; case 0x17: return 'i'; case 0x18: return 'o';
        case 0x19: return 'p'; case 0x1A: return '['; case 0x1B: return ']';
        // Row 3 (ASDFGH)
        case 0x1E: return 'a'; case 0x1F: return 's'; case 0x20: return 'd';
        case 0x21: return 'f'; case 0x22: return 'g'; case 0x23: return 'h';
        case 0x24: return 'j'; case 0x25: return 'k'; case 0x26: return 'l';
        case 0x27: return ';'; case 0x28: return '\''; case 0x29: return '`';
        // Row 4 (ZXCVBN)
        case 0x2B: return '\\'; // Note: Original US layout might have this next to Enter or LShift
        case 0x2C: return 'z'; case 0x2D: return 'x'; case 0x2E: return 'c';
        case 0x2F: return 'v'; case 0x30: return 'b'; case 0x31: return 'n';
        case 0x32: return 'm'; case 0x33: return ','; case 0x34: return '.';
        case 0x35: return '/';
        // Special characters
        case 0x0E: return '\b'; // Backspace
        case 0x0F: return '\t'; // Tab
        case 0x1C: return '\n'; // Enter
        case 0x39: return ' ';  // Space

        default:   return 0;  // Null char for unmapped/non-printable scancodes
    }
}

void initialize_keyboard() {
    // For this basic setup, we primarily rely on the BIOS having initialized
    // the keyboard controller. We just need to ensure our IRQ handler is ready
    // and the IRQ is unmasked in the PIC.
    // More advanced setup might involve sending commands (e.g., 0xF4 to enable scanning)
    // to port 0x60 after checking status on port 0x64.
    terminal_writestring("Keyboard driver initialized (ISR set, IRQ1 ready to be unmasked).\n");
}

// This is called by the assembly IRQ1 handler (keyboard_handler_asm.s)
extern (C) void keyboard_interrupt_handler(ubyte scancode) {
    // Log to confirm IRQ1 firing
    terminal_writestring("[IRQ1]\n");

    if (!(scancode & 0x80)) {
        char c = scancode_to_char(scancode);
        if (c != 0) {
            input_buffer[input_head] = c;
            input_head = (input_head + 1) % INPUT_BUF_SIZE;

            // Disable echo here to avoid double characters
            // terminal_putchar(c); ← comment this out
        }
    }
}

