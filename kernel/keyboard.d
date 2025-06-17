// kernel/keyboard.d

module kernel.keyboard;

public: // Export scancode_to_char

// Basic scancode map (US QWERTY, lowercase, no modifiers)
char[256] scancode_to_char = init_scancode_map();

// Helper to initialize scancode_to_char
private char[256] init_scancode_map() {
    char[256] map;
    for (size_t i = 0; i < map.length; i++) {
        map[i] = 0;
    }

    map[0x02] = '1'; map[0x03] = '2'; map[0x04] = '3'; map[0x05] = '4';
    map[0x06] = '5'; map[0x07] = '6'; map[0x08] = '7'; map[0x09] = '8';
    map[0x0A] = '9'; map[0x0B] = '0'; map[0x0C] = '-'; map[0x0D] = '=';

    map[0x10] = 'q'; map[0x11] = 'w'; map[0x12] = 'e'; map[0x13] = 'r';
    map[0x14] = 't'; map[0x15] = 'y'; map[0x16] = 'u'; map[0x17] = 'i';
    map[0x18] = 'o'; map[0x19] = 'p'; map[0x1A] = '['; map[0x1B] = ']';
    map[0x1E] = 'a'; map[0x1F] = 's'; map[0x20] = 'd'; map[0x21] = 'f';
    map[0x22] = 'g'; map[0x23] = 'h'; map[0x24] = 'j'; map[0x25] = 'k';
    map[0x26] = 'l'; map[0x27] = ';'; map[0x28] = '\''; map[0x29] = '`';

    map[0x2C] = 'z'; map[0x2D] = 'x'; map[0x2E] = 'c'; map[0x2F] = 'v';
    map[0x30] = 'b'; map[0x31] = 'n'; map[0x32] = 'm'; map[0x33] = ',';
    map[0x34] = '.'; map[0x35] = '/';

    map[0x1C] = '\n'; // Enter Key
    map[0x39] = ' '; // Spacebar

    return map;
}