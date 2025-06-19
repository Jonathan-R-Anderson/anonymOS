module kernel.device.vga;

// If hardware cursor control is desired, inb/outb would be needed.
// extern (C) {
//     ubyte inb(ushort port);
//     void outb(ushort port, ubyte data);
// }

enum VGA_WIDTH = 80;
enum VGA_HEIGHT = 25;
enum VGA_MEMORY_ADDRESS = 0xB8000;

__gshared ushort* vga_buffer = cast(ushort*) VGA_MEMORY_ADDRESS;
__gshared ubyte terminal_row;
__gshared ubyte terminal_column;
__gshared ubyte terminal_color;
__gshared Color current_fg;
__gshared Color current_bg;
__gshared Color default_fg_color_val;
__gshared Color default_bg_color_val;
__gshared bool sgr_bold_active;

enum Color : ubyte {
    BLACK = 0, BLUE = 1, GREEN = 2, CYAN = 3, RED = 4, MAGENTA = 5, BROWN = 6, LIGHT_GREY = 7,
    DARK_GREY = 8, LIGHT_BLUE = 9, LIGHT_GREEN = 10, LIGHT_CYAN = 11, LIGHT_RED = 12,
    LIGHT_MAGENTA = 13, YELLOW = 14, WHITE = 15, // VGA YELLOW is bright, BROWN is dark yellow
}

enum AnsiParseState {
    NORMAL,
    EXPECT_BRACKET,  // Seen ESC
    EXPECT_PARAMS,   // Seen ESC [
}
__gshared AnsiParseState ansi_state = AnsiParseState.NORMAL;
enum MAX_ANSI_PARAMS = 5;
__gshared ubyte[MAX_ANSI_PARAMS] ansi_params;
__gshared ubyte ansi_param_idx;
__gshared ushort current_param_value; // Accumulator for current multi-digit param
// Stray brace removed from the end of the previous line

// Precomputed mapping from xterm 256 color index to our 16-color VGA Color enum index
__gshared immutable ubyte[256] xterm_to_vga_palette_indices = [
    0x00, 0x04, 0x02, 0x06, 0x01, 0x05, 0x03, 0x07, 0x08, 0x0C, 0x0A, 0x0E, 0x09, 0x0D, 0x0B, 0x0F, // 0-15
    0x00, 0x01, 0x01, 0x01, 0x09, 0x09, 0x00, 0x01, 0x01, 0x01, 0x09, 0x09, 0x00, 0x03, 0x03, 0x01, // 16-31
    0x0B, 0x09, 0x00, 0x03, 0x03, 0x03, 0x0B, 0x0B, 0x00, 0x02, 0x02, 0x03, 0x0A, 0x0B, 0x00, 0x02, // 32-47
    0x02, 0x02, 0x0A, 0x0A, 0x00, 0x02, 0x02, 0x02, 0x0A, 0x0A, 0x04, 0x05, 0x01, 0x01, 0x0D, 0x09, // 48-63
    0x04, 0x05, 0x05, 0x01, 0x0D, 0x0D, 0x04, 0x06, 0x03, 0x03, 0x0E, 0x0B, 0x04, 0x06, 0x06, 0x03, // 64-79
    0x0E, 0x0E, 0x04, 0x02, 0x02, 0x02, 0x0C, 0x0A, 0x04, 0x02, 0x02, 0x02, 0x0C, 0x0C, 0x08, 0x09, // 80-95
    0x09, 0x09, 0x09, 0x09, 0x08, 0x09, 0x09, 0x09, 0x09, 0x09, 0x08, 0x0B, 0x0B, 0x09, 0x0B, 0x09, // 96-111
    0x08, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x08, 0x0A, 0x0A, 0x0B, 0x0A, 0x0B, 0x08, 0x0A, 0x0A, 0x0A, // 112-127
    0x0A, 0x0A, 0x08, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0C, 0x0D, 0x0D, 0x09, 0x0D, 0x0D, 0x0C, 0x0D, // 128-143
    0x0D, 0x0D, 0x0D, 0x0D, 0x0C, 0x0E, 0x0E, 0x0B, 0x0E, 0x0B, 0x0C, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, // 144-159
    0x0C, 0x0A, 0x0A, 0x0A, 0x0C, 0x0A, 0x0C, 0x0A, 0x0A, 0x0A, 0x0C, 0x0C, 0x07, 0x07, 0x07, 0x07, // 160-175
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, // 176-191
    0x0F, 0x0F, 0x0F, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, // 192-207
    0x08, 0x08, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, // 208-231
    // Grayscale (232-255) mapped to the 4 VGA grays
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 232-237 -> BLACK
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, // 238-243 -> DARK_GREY
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, // 244-249 -> LIGHT_GREY
    0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F  // 250-255 -> WHITE
];


ubyte make_color(Color fg, Color bg) {
    return cast(ubyte)((cast(ubyte)fg) | (cast(ubyte)bg << 4));
}

ushort make_vga_entry(ubyte c, ubyte color) { // Changed char to ubyte
    return c | (cast(ushort)color << 8);
}

void set_cursor_pos(ubyte r, ubyte c) {
    terminal_row = r;
    terminal_column = c;    
    // Optional: Update hardware cursor if you have inb/outb and want it
    // ushort pos = r * VGA_WIDTH + c;
    // outb(0x3D4, 14); // High byte
    // outb(0x3D5, cast(ubyte)(pos >> 8));
    // outb(0x3D4, 15); // Low byte
    // outb(0x3D5, cast(ubyte)(pos & 0xFF));
}

void reset_cursor_pos() {
    terminal_row = 0;
    terminal_column = 0;
}

void clear_screen() {
    for (ubyte r = 0; r < VGA_HEIGHT; ++r) {
        for (ubyte c = 0; c < VGA_WIDTH; ++c) {
            const size_t index = r * VGA_WIDTH + c;
            vga_buffer[index] = make_vga_entry(' ', terminal_color);
        }
    }    
    reset_cursor_pos();
}

void initialize_terminal() {
    default_fg_color_val = Color.LIGHT_GREY;
    default_bg_color_val = Color.BLACK;
    current_fg = default_fg_color_val;
    current_bg = default_bg_color_val;
    sgr_bold_active = false;
    terminal_color = make_color(current_fg, current_bg);

    ansi_state = AnsiParseState.NORMAL;
    ansi_param_idx = 0;
    current_param_value = 0;
    ansi_params[0..MAX_ANSI_PARAMS] = 0;

    clear_screen();
}

void scroll_terminal() {
    // Move all lines up by one
    for (ubyte r = 0; r < VGA_HEIGHT - 1; ++r) {
        for (ubyte c = 0; c < VGA_WIDTH; ++c) {
            vga_buffer[r * VGA_WIDTH + c] = vga_buffer[(r + 1) * VGA_WIDTH + c];
        }
    }
    // Clear the last line
    for (ubyte c = 0; c < VGA_WIDTH; ++c) {
        // Clear with current background but default foreground for scrolled lines
        vga_buffer[(VGA_HEIGHT - 1) * VGA_WIDTH + c] = make_vga_entry(' ', make_color(default_fg_color_val, current_bg));
    }
    terminal_row = VGA_HEIGHT - 1; // Cursor stays on the new last line
}

private Color map_xterm_idx_to_vga_color(ubyte xterm_color_idx, bool is_fg_and_bold) {
    Color base_vga_color = cast(Color)xterm_to_vga_palette_indices[xterm_color_idx];
    if (is_fg_and_bold) {
        // If the base VGA color is one of the "darker" first 8 (0-7)
        // then make it "bright" by adding 8 to its enum value.
        // This makes 'bold' behave like xterm's bright colors for the 256-color palette.
        if (base_vga_color >= Color.BLACK && base_vga_color <= Color.LIGHT_GREY) {
            return cast(Color)(base_vga_color + 8);
        }
    }
    return base_vga_color;
}

// Maps ANSI codes 30-37 (fg) and 40-47 (bg) to our Color enum
private Color ansi_standard_code_to_vga_color(ubyte ansi_code_val, bool is_bold_for_fg) {
    ubyte base_idx = cast(ubyte)((ansi_code_val >= 40) ? (ansi_code_val - 40) : (ansi_code_val - 30));
    Color base_color = cast(Color)base_idx;

    if (is_bold_for_fg && ansi_code_val < 40) { // Only apply bold to foreground
        if (base_color >= Color.BLACK && base_color <= Color.LIGHT_GREY) { // Dark colors 0-7
            return cast(Color)(base_color + 8); // Brighten them
        }
    }
    return base_color;
}

private void apply_sgr_code(ushort code) {
    if (code == 0) { // Reset
        current_fg = default_fg_color_val;
        current_bg = default_bg_color_val;
        sgr_bold_active = false;
    } else if (code == 1) { // Bold/Bright
        sgr_bold_active = true;
    } else if (code == 22) { // Normal intensity
        sgr_bold_active = false;
    } else if (code >= 30 && code <= 37) { // Standard Foreground colors
        current_fg = ansi_standard_code_to_vga_color(cast(ubyte)code, sgr_bold_active);
    } else if (code == 39) { // Default foreground
        current_fg = default_fg_color_val;
    } else if (code >= 40 && code <= 47) { // Background colors
        current_bg = ansi_standard_code_to_vga_color(cast(ubyte)code, false); // No bold for BG
    } else if (code == 49) { // Default background
        current_bg = default_bg_color_val;
    }
    terminal_color = make_color(current_fg, current_bg);
}

private void handle_ansi_command(char cmd) {
    // If no params were given, ansi_param_idx might be 0.
    // Store the last parsed numeric value if it was indeed part of the sequence.
    // This check ensures we don't add a spurious 0 if the command had no numeric params (e.g. ESC[m)
    // or if the last char was a separator ';'
    if (ansi_state == AnsiParseState.EXPECT_PARAMS && ansi_param_idx < MAX_ANSI_PARAMS) {
         ansi_params[ansi_param_idx++] = cast(ubyte)current_param_value;
    }

    switch (cmd) {
        case 'm': // Select Graphic Rendition (SGR)
            if (ansi_param_idx == 0) { // ESC[m is same as ESC[0m
                apply_sgr_code(0); // Reset all attributes
            } else {
                ubyte i = 0;
                while(i < ansi_param_idx) {
                    ushort p1 = ansi_params[i];
                    if (p1 == 38) { // Extended foreground color
                        if (i + 2 < ansi_param_idx && ansi_params[i+1] == 5) {
                            ubyte xterm_idx = ansi_params[i+2];
                            current_fg = map_xterm_idx_to_vga_color(xterm_idx, sgr_bold_active);
                            i += 3;
                        } else { i = ansi_param_idx; /* Skip malformed/unsupported (e.g. 38;2;r;g;b) */ }
                    } else if (p1 == 48) { // Extended background color
                        if (i + 2 < ansi_param_idx && ansi_params[i+1] == 5) {
                            ubyte xterm_idx = ansi_params[i+2];
                            current_bg = map_xterm_idx_to_vga_color(xterm_idx, false); // No bold for BG
                            i += 3;
                        } else { i = ansi_param_idx; /* Skip malformed/unsupported (e.g. 48;2;r;g;b) */ }
                    } else { // Standard SGR code
                        apply_sgr_code(p1);
                        i++;
                    }
                }
            }
            terminal_color = make_color(current_fg, current_bg);
            break;

        case 'J': // Erase Display
            // We only support 2J (clear entire screen and home cursor)
            // param[0] is 2 for 2J. If no param, default is 0J (erase from cursor to end)
            ubyte erase_mode = (ansi_param_idx > 0) ? ansi_params[0] : 0;
            if (erase_mode == 2) {
                clear_screen(); // clear_screen also homes cursor and sets default colors
                // Restore current SGR attributes
                terminal_color = make_color(current_fg, current_bg);
            }
            // Other J modes (0, 1, 3) not implemented for simplicity
            break;
        case 'H': // Cursor Position
        case 'f': // Horizontal and Vertical Position (same as H)
            ubyte r = (ansi_param_idx > 0 && ansi_params[0] > 0) ? cast(ubyte)(ansi_params[0] - 1) : 0;
            ubyte c = (ansi_param_idx > 1 && ansi_params[1] > 0) ? cast(ubyte)(ansi_params[1] - 1) : 0;
            if (r >= VGA_HEIGHT) r = VGA_HEIGHT - 1;
            if (c >= VGA_WIDTH) c = VGA_WIDTH - 1;
            set_cursor_pos(r, c);
            break;
        default:
            // Unknown ANSI command, ignore
            break;
    }

    // Reset ANSI parsing state
    ansi_state = AnsiParseState.NORMAL;
    ansi_param_idx = 0;
    current_param_value = 0;
}

private void put_char_at_cursor(ubyte c) { // Changed char to ubyte
    if (c == '\n') {
        terminal_column = 0;
        terminal_row++;
    } else if (c == '\r') {
        terminal_column = 0;
    } else if (c == '\b') { // Basic backspace
        if (terminal_column > 0) {
            terminal_column--;
             // Clear with current background, space with default foreground
            vga_buffer[terminal_row * VGA_WIDTH + terminal_column] = make_vga_entry(' ', make_color(default_fg_color_val, current_bg));
        } else if (terminal_row > 0) { // Backspace from start of line to end of previous
            terminal_row--;
            terminal_column = VGA_WIDTH -1;
            vga_buffer[terminal_row * VGA_WIDTH + terminal_column] = make_vga_entry(' ', make_color(default_fg_color_val, current_bg));
        }
    } else {
        vga_buffer[terminal_row * VGA_WIDTH + terminal_column] = make_vga_entry(c, terminal_color);
        terminal_column++;
    }

    if (terminal_column >= VGA_WIDTH) {
        terminal_column = 0;
        terminal_row++;
    }
    if (terminal_row >= VGA_HEIGHT) {
        scroll_terminal();
        // After scroll, cursor is on new last line, column 0
        // set_cursor_pos(VGA_HEIGHT - 1, terminal_column); // terminal_column would be 0
    }
    // set_cursor_pos(terminal_row, terminal_column); // If hardware cursor is active and updated frequently
}

void terminal_putchar(ubyte c) { // Changed char to ubyte
    // ubyte c = cast(ubyte)c_in; // No longer needed if param is ubyte

    switch (ansi_state) {
        case AnsiParseState.NORMAL:
            if (c == 0x1B) { // ESC
                ansi_state = AnsiParseState.EXPECT_BRACKET;
            } else {
                put_char_at_cursor(c);
            }
            break;

        case AnsiParseState.EXPECT_BRACKET:
            if (c == '[') {
                ansi_state = AnsiParseState.EXPECT_PARAMS;
                ansi_param_idx = 0;
                current_param_value = 0; // Default for first param if not specified
                // Clear params array for new sequence
                for(int i=0; i < MAX_ANSI_PARAMS; ++i) ansi_params[i] = 0;
            } else {
                // Not a valid CSI sequence, print ESC and then this char
                put_char_at_cursor(cast(ubyte)'\x1B');
                put_char_at_cursor(c);
                ansi_state = AnsiParseState.NORMAL;
            }
            break;

        case AnsiParseState.EXPECT_PARAMS:
            if (c >= '0' && c <= '9') {
                current_param_value = cast(ushort)(current_param_value * 10 + (c - '0'));
            } else if (c == ';') {
                if (ansi_param_idx < MAX_ANSI_PARAMS) {
                    ansi_params[ansi_param_idx++] = cast(ubyte)current_param_value;
                }
                current_param_value = 0; // Reset for next param
            } else if (c >= 0x40 && c <= 0x7E) { // Final command character
                // Last parameter is in current_param_value, handle_ansi_command will add it.
                handle_ansi_command(cast(char)c); // handle_ansi_command expects char for cmd
                // State is reset in handle_ansi_command
            } else {
                // Invalid character in parameter sequence, abort ANSI parsing
                // Optionally print the partial sequence if debugging
                ansi_state = AnsiParseState.NORMAL;
                // Maybe print the char that broke it? For now, just drop it.
            }
            break;
        default: // Should not happen
            ansi_state = AnsiParseState.NORMAL;
            put_char_at_cursor(c);
            break;
    }
}

void terminal_writestring(const char* data) {
    for (size_t i = 0; data[i] != 0; ++i) {
        terminal_putchar(cast(ubyte)data[i]);
    }
}

void terminal_display_ansi_buffer(const(ubyte)[] data) {
    for (size_t i = 0; i < data.length; ++i) {
        terminal_putchar(data[i]);
    }
}