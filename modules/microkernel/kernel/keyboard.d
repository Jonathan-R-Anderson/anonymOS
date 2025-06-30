module kernel.keyboard;

// Use kernel.terminal for output
import kernel.terminal : terminal_writestring, terminal_putchar, terminal_writestring_color;
import kernel.lib.stdc.stdint; // Use local stdint stub
import kernel.arch_interface.ports : inb, outb; // Direct port access
import kernel.logger : log_message; // For debug logging
import kernel.types : VGAColor;

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

// Debug counter for keyboard interrupts
__gshared uint keyboard_interrupt_count = 0;

char keyboard_getchar()
{
    import kernel.arch_interface.ports : inb, outb;
    uint timeout_counter = 0;
    const uint MAX_TIMEOUT = 100000; // Reduced timeout for faster debugging
    
    // First, let's test if the keyboard controller is even responding
    log_message("DEBUG: Testing keyboard controller directly...\n");
    
    // Check keyboard controller status
    ubyte status = inb(0x64);
    log_message("DEBUG: Keyboard controller status: ");
    
    // Simple output - show raw value as single characters
    if (status == 0) {
        terminal_writestring_color("0", VGAColor.CYAN, VGAColor.BLACK);
    } else {
        // Show some bits of status for debugging
        terminal_writestring_color("NON_ZERO(", VGAColor.CYAN, VGAColor.BLACK);
        if (status & 0x01) terminal_writestring_color("DATA_READY,", VGAColor.GREEN, VGAColor.BLACK);
        if (status & 0x02) terminal_writestring_color("INPUT_FULL,", VGAColor.RED, VGAColor.BLACK);
        if (status & 0x04) terminal_writestring_color("SYS_FLAG,", VGAColor.YELLOW, VGAColor.BLACK);
        if (status & 0x08) terminal_writestring_color("CMD_DATA,", VGAColor.MAGENTA, VGAColor.BLACK);
        terminal_writestring_color(")", VGAColor.CYAN, VGAColor.BLACK);
    }
    terminal_writestring("\n");
    
    // Try to enable keyboard scanning explicitly
    log_message("DEBUG: Sending enable commands to keyboard controller...\n");
    outb(0x64, 0xAE); // Enable keyboard interface
    outb(0x60, 0xF4); // Enable keyboard scanning
    
    // Check status again
    status = inb(0x64);
    log_message("DEBUG: Keyboard controller status after enable: ");
    if (status == 0) {
        terminal_writestring_color("0", VGAColor.CYAN, VGAColor.BLACK);
    } else {
        terminal_writestring_color("NON_ZERO(", VGAColor.CYAN, VGAColor.BLACK);
        if (status & 0x01) terminal_writestring_color("DATA_READY,", VGAColor.GREEN, VGAColor.BLACK);
        if (status & 0x02) terminal_writestring_color("INPUT_FULL,", VGAColor.RED, VGAColor.BLACK);
        if (status & 0x04) terminal_writestring_color("SYS_FLAG,", VGAColor.YELLOW, VGAColor.BLACK);
        if (status & 0x08) terminal_writestring_color("CMD_DATA,", VGAColor.MAGENTA, VGAColor.BLACK);
        terminal_writestring_color(")", VGAColor.CYAN, VGAColor.BLACK);
    }
    terminal_writestring("\n");
    
    // Check if there's any data available (bit 0 set)
    if (status & 0x01) {
        ubyte scancode = inb(0x60);
        log_message("DEBUG: Found pending scancode!\n");
        char c = scancode_to_char(scancode, shift_state);
        if (c != 0) {
            terminal_writestring_color("DEBUG: Converted to character, returning it\n", VGAColor.GREEN, VGAColor.BLACK);
            return c;
        }
    } else {
        log_message("DEBUG: No data available in keyboard buffer\n");
    }
    
    // Test interrupt count
    log_message("DEBUG: Keyboard interrupt count so far: ");
    if (keyboard_interrupt_count == 0) {
        terminal_writestring_color("ZERO", VGAColor.YELLOW, VGAColor.BLACK);
    } else {
        terminal_writestring_color("NON_ZERO", VGAColor.GREEN, VGAColor.BLACK);
    }
    terminal_writestring("\n");
    
    log_message("DEBUG: Waiting for keyboard input...\n");
    
    while (input_head == input_tail) {
        timeout_counter++;
        if (timeout_counter >= MAX_TIMEOUT) {
            // Debug: Print interrupt count and timeout
            terminal_writestring_color("TIMEOUT: No keyboard input received after 100k iterations\n", VGAColor.RED, VGAColor.BLACK);
            terminal_writestring_color("Keyboard interrupt count: ", VGAColor.RED, VGAColor.BLACK);
            if (keyboard_interrupt_count == 0) {
                terminal_writestring_color("ZERO\n", VGAColor.YELLOW, VGAColor.BLACK);
            } else {
                terminal_writestring_color("NON_ZERO\n", VGAColor.GREEN, VGAColor.BLACK);
            }
            terminal_writestring_color("Trying polling mode as fallback...\n", VGAColor.RED, VGAColor.BLACK);
            
            // Try polling mode as fallback
            uint poll_count = 0;
            while (poll_count < 10000) {
                status = inb(0x64);
                if (status & 0x01) {
                    ubyte scancode = inb(0x60);
                    terminal_writestring_color("Got scancode via polling: ", VGAColor.GREEN, VGAColor.BLACK);
                    // Show scancode as individual bits for debugging
                    for (int i = 7; i >= 0; i--) {
                        if (scancode & (1 << i)) {
                            terminal_writestring_color("1", VGAColor.GREEN, VGAColor.BLACK);
                        } else {
                            terminal_writestring_color("0", VGAColor.CYAN, VGAColor.BLACK);
                        }
                    }
                    terminal_writestring("\n");
                    
                    char c = scancode_to_char(scancode, shift_state);
                    if (c != 0) {
                        terminal_writestring_color("Converted to: ", VGAColor.GREEN, VGAColor.BLACK);
                        terminal_putchar(c);
                        terminal_writestring("\n");
                        return c;
                    }
                }
                poll_count++;
                // Short delay
                for (int i = 0; i < 100; i++) {
                    asm { "pause"; }
                }
            }
            
            terminal_writestring_color("Polling also failed - no keyboard response detected\n", VGAColor.RED, VGAColor.BLACK);
            return ' '; // Return space as fallback to prevent infinite hang
        }
        
        // Simply wait for an interrupt to fill the buffer
        // The keyboard interrupt handler will populate input_buffer
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
    keyboard_interrupt_count++; // Debug: track interrupt count
    
    if (scancode == 0x2A || scancode == 0x36) {
        shift_state = true;
    } else if (scancode == 0xAA || scancode == 0xB6) {
        shift_state = false;
    } else if (!(scancode & 0x80)) {
        char c = scancode_to_char(scancode, shift_state);
        if (c != 0) {
            input_buffer[input_head] = c;
            input_head = (input_head + 1) % INPUT_BUF_SIZE;
            // Do not echo here - let the shell handle echoing
        }
    }
}

