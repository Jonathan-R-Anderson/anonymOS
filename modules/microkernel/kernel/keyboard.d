module kernel.keyboard;

// Use kernel.terminal for output
import kernel.terminal : terminal_writestring, terminal_putchar;
import kernel.lib.stdc.stdint; // Use local stdint stub
import kernel.arch_interface.ports : inb, outb; // Direct port access
import kernel.logger : log_message; // For debug logging

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
__gshared bool shift_state = false; // track whether shift is pressed

char keyboard_getchar()
{
    while (input_head == input_tail) {
        // Poll status port to see if data is available
        ubyte status = inb(0x64);
        if (status & 1) { // Output buffer full
            ubyte sc = inb(0x60);
            // Update shift state
            if (sc == 0x2A || sc == 0x36) {
                shift_state = true; // LSHIFT or RSHIFT press
            } else if (sc == 0xAA || sc == 0xB6) {
                shift_state = false; // release
            } else if ((sc & 0x80) == 0) { // Key press
                char ch = scancode_to_char(sc, shift_state);
                if (ch != 0) {
                    input_buffer[input_head] = ch;
                    input_head = (input_head + 1) % INPUT_BUF_SIZE;
                }
            }
        }
        asm { "hlt"; }
    }
    char c = input_buffer[input_tail];
    input_tail = (input_tail + 1) % INPUT_BUF_SIZE;

    return c;
}

// Converts a scancode (Scan Code Set 1, make code) to its corresponding ASCII character.
// Returns 0 (null char) if the scancode is not printable or not mapped.
char scancode_to_char(ubyte scancode, bool shift) {
    // Handles a limited US keyboard layout with optional shift state.

    switch (scancode) {
        // Row 1 (Numbers and symbols)
        case 0x02: return shift ? '!' : '1';
        case 0x03: return shift ? '@' : '2';
        case 0x04: return shift ? '#' : '3';
        case 0x05: return shift ? '$' : '4';
        case 0x06: return shift ? '%' : '5';
        case 0x07: return shift ? '^' : '6';
        case 0x08: return shift ? '&' : '7';
        case 0x09: return shift ? '*' : '8';
        case 0x0A: return shift ? '(' : '9';
        case 0x0B: return shift ? ')' : '0';
        case 0x0C: return shift ? '_' : '-';
        case 0x0D: return shift ? '+' : '=';
        // Row 2 (QWERTY)
        case 0x10: return shift ? 'Q' : 'q';
        case 0x11: return shift ? 'W' : 'w';
        case 0x12: return shift ? 'E' : 'e';
        case 0x13: return shift ? 'R' : 'r';
        case 0x14: return shift ? 'T' : 't';
        case 0x15: return shift ? 'Y' : 'y';
        case 0x16: return shift ? 'U' : 'u';
        case 0x17: return shift ? 'I' : 'i';
        case 0x18: return shift ? 'O' : 'o';
        case 0x19: return shift ? 'P' : 'p';
        case 0x1A: return shift ? '{' : '[';
        case 0x1B: return shift ? '}' : ']';
        // Row 3 (ASDFGH)
        case 0x1E: return shift ? 'A' : 'a';
        case 0x1F: return shift ? 'S' : 's';
        case 0x20: return shift ? 'D' : 'd';
        case 0x21: return shift ? 'F' : 'f';
        case 0x22: return shift ? 'G' : 'g';
        case 0x23: return shift ? 'H' : 'h';
        case 0x24: return shift ? 'J' : 'j';
        case 0x25: return shift ? 'K' : 'k';
        case 0x26: return shift ? 'L' : 'l';
        case 0x27: return shift ? ':' : ';';
        case 0x28: return shift ? '"' : '\'';
        case 0x29: return shift ? '~' : '`';
        // Row 4 (ZXCVBN)
        case 0x2B: return shift ? '|' : '\\';
        case 0x2C: return shift ? 'Z' : 'z';
        case 0x2D: return shift ? 'X' : 'x';
        case 0x2E: return shift ? 'C' : 'c';
        case 0x2F: return shift ? 'V' : 'v';
        case 0x30: return shift ? 'B' : 'b';
        case 0x31: return shift ? 'N' : 'n';
        case 0x32: return shift ? 'M' : 'm';
        case 0x33: return shift ? '<' : ',';
        case 0x34: return shift ? '>' : '.';
        case 0x35: return shift ? '?' : '/';
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
    // the keyboard controller.  However some BIOSes leave keyboard scanning
    // disabled which means no IRQ1 events are generated.  To be safe we
    // explicitly enable the controller interface and keyboard scanning.  Some
    // emulators and BIOSes require sending the "Enable Keyboard Interface"
    // command (0xAE) to the control port (0x64) before the device will honour
    // the "Enable Scanning" command (0xF4) on the data port (0x60). We keep the
    // logic simple and do not poll the status port as this driver runs very
    // early during boot and the controller is assumed to be ready.

    import kernel.arch_interface.ports : outb;
    outb(0x64, 0xAE); // Activate keyboard interface
    outb(0x60, 0xF4); // Enable keyboard scanning so IRQ1 will fire

    // All further setup (installing IRQ handler, unmasking in the PIC) is done
    // elsewhere during system initialization.
}

// This is called by the assembly IRQ1 handler (keyboard_handler_asm.s)
extern (C) void keyboard_interrupt_handler(ubyte scancode) {
    // Log to confirm IRQ1 firing
    // Removed debug interrupt notification

    if (scancode == 0x2A || scancode == 0x36) {
        shift_state = true;
    } else if (scancode == 0xAA || scancode == 0xB6) {
        shift_state = false;
    } else if (!(scancode & 0x80)) {
        char c = scancode_to_char(scancode, shift_state);
        if (c != 0) {
            input_buffer[input_head] = c;
            input_head = (input_head + 1) % INPUT_BUF_SIZE;

            // Disable echo here to avoid double characters
            // terminal_putchar(c);
        }
    }

}

