module minimal_os.drivers.hid_keyboard;

import minimal_os.display.input_pipeline : InputQueue, InputEvent, enqueue;

@nogc:
nothrow:

/// HID keyboard boot protocol report (8 bytes)
struct HIDKeyboardReport
{
    ubyte modifiers;    // Bit flags for modifier keys
    ubyte reserved;     // Always 0
    ubyte[6] keycodes;  // Up to 6 simultaneous key presses
}

/// Modifier key bit flags
enum KeyModifier : ubyte
{
    leftCtrl  = 0x01,
    leftShift = 0x02,
    leftAlt   = 0x04,
    leftGui   = 0x08,  // Windows/Super key
    rightCtrl = 0x10,
    rightShift = 0x20,
    rightAlt  = 0x40,
    rightGui  = 0x80,
}

/// Keyboard state tracker
struct KeyboardState
{
    HIDKeyboardReport lastReport;
    bool[256] keyDown;  // Track which keys are currently pressed
}

private __gshared KeyboardState g_keyboardState;

/// Process a HID keyboard report and generate input events
void processKeyboardReport(ref const HIDKeyboardReport report, ref InputQueue queue) @nogc nothrow
{
    // Detect newly pressed keys
    foreach (keycode; report.keycodes)
    {
        if (keycode == 0) continue;
        
        // Check if this is a new key press
        bool wasPressed = false;
        foreach (oldKey; g_keyboardState.lastReport.keycodes)
        {
            if (oldKey == keycode)
            {
                wasPressed = true;
                break;
            }
        }
        
        if (!wasPressed && keycode != 0)
        {
            // New key press
            InputEvent event;
            event.type = InputEvent.Type.keyDown;
            event.data1 = translateScancode(keycode, report.modifiers);
            event.data2 = keycode;
            event.data3 = report.modifiers;
            enqueue(queue, event);
            
            g_keyboardState.keyDown[keycode] = true;
        }
    }
    
    // Detect released keys
    foreach (oldKey; g_keyboardState.lastReport.keycodes)
    {
        if (oldKey == 0) continue;
        
        bool stillPressed = false;
        foreach (keycode; report.keycodes)
        {
            if (keycode == oldKey)
            {
                stillPressed = true;
                break;
            }
        }
        
        if (!stillPressed)
        {
            // Key released
            InputEvent event;
            event.type = InputEvent.Type.keyUp;
            event.data1 = translateScancode(oldKey, g_keyboardState.lastReport.modifiers);
            event.data2 = oldKey;
            event.data3 = g_keyboardState.lastReport.modifiers;
            enqueue(queue, event);
            
            g_keyboardState.keyDown[oldKey] = false;
        }
    }
    
    // Save current report for next comparison
    g_keyboardState.lastReport = report;
}

/// Translate HID scancode to ASCII character
private int translateScancode(ubyte scancode, ubyte modifiers) @nogc nothrow pure
{
    const bool shift = (modifiers & (KeyModifier.leftShift | KeyModifier.rightShift)) != 0;
    const bool ctrl = (modifiers & (KeyModifier.leftCtrl | KeyModifier.rightCtrl)) != 0;
    const bool alt = (modifiers & (KeyModifier.leftAlt | KeyModifier.rightAlt)) != 0;
    
    // HID Usage IDs for keyboard (Boot Protocol)
    switch (scancode)
    {
        // Letters (a-z)
        case 0x04: return shift ? 'A' : 'a';
        case 0x05: return shift ? 'B' : 'b';
        case 0x06: return shift ? 'C' : 'c';
        case 0x07: return shift ? 'D' : 'd';
        case 0x08: return shift ? 'E' : 'e';
        case 0x09: return shift ? 'F' : 'f';
        case 0x0A: return shift ? 'G' : 'g';
        case 0x0B: return shift ? 'H' : 'h';
        case 0x0C: return shift ? 'I' : 'i';
        case 0x0D: return shift ? 'J' : 'j';
        case 0x0E: return shift ? 'K' : 'k';
        case 0x0F: return shift ? 'L' : 'l';
        case 0x10: return shift ? 'M' : 'm';
        case 0x11: return shift ? 'N' : 'n';
        case 0x12: return shift ? 'O' : 'o';
        case 0x13: return shift ? 'P' : 'p';
        case 0x14: return shift ? 'Q' : 'q';
        case 0x15: return shift ? 'R' : 'r';
        case 0x16: return shift ? 'S' : 's';
        case 0x17: return shift ? 'T' : 't';
        case 0x18: return shift ? 'U' : 'u';
        case 0x19: return shift ? 'V' : 'v';
        case 0x1A: return shift ? 'W' : 'w';
        case 0x1B: return shift ? 'X' : 'x';
        case 0x1C: return shift ? 'Y' : 'y';
        case 0x1D: return shift ? 'Z' : 'z';
        
        // Numbers
        case 0x1E: return shift ? '!' : '1';
        case 0x1F: return shift ? '@' : '2';
        case 0x20: return shift ? '#' : '3';
        case 0x21: return shift ? '$' : '4';
        case 0x22: return shift ? '%' : '5';
        case 0x23: return shift ? '^' : '6';
        case 0x24: return shift ? '&' : '7';
        case 0x25: return shift ? '*' : '8';
        case 0x26: return shift ? '(' : '9';
        case 0x27: return shift ? ')' : '0';
        
        // Special characters
        case 0x28: return '\n';  // Enter
        case 0x29: return 0x1B;  // Escape
        case 0x2A: return '\b';  // Backspace
        case 0x2B: return '\t';  // Tab
        case 0x2C: return ' ';   // Space
        case 0x2D: return shift ? '_' : '-';
        case 0x2E: return shift ? '+' : '=';
        case 0x2F: return shift ? '{' : '[';
        case 0x30: return shift ? '}' : ']';
        case 0x31: return shift ? '|' : '\\';
        case 0x33: return shift ? ':' : ';';
        case 0x34: return shift ? '"' : '\'';
        case 0x35: return shift ? '~' : '`';
        case 0x36: return shift ? '<' : ',';
        case 0x37: return shift ? '>' : '.';
        case 0x38: return shift ? '?' : '/';
        
        // Function keys (represented as special codes)
        case 0x3A: return 0x100;  // F1
        case 0x3B: return 0x101;  // F2
        case 0x3C: return 0x102;  // F3
        case 0x3D: return 0x103;  // F4
        case 0x3E: return 0x104;  // F5
        case 0x3F: return 0x105;  // F6
        case 0x40: return 0x106;  // F7
        case 0x41: return 0x107;  // F8
        case 0x42: return 0x108;  // F9
        case 0x43: return 0x109;  // F10
        case 0x44: return 0x10A;  // F11
        case 0x45: return 0x10B;  // F12
        
        // Arrow keys
        case 0x4F: return 0x200;  // Right arrow
        case 0x50: return 0x201;  // Left arrow
        case 0x51: return 0x202;  // Down arrow
        case 0x52: return 0x203;  // Up arrow
        
        // Other special keys
        case 0x49: return 0x204;  // Insert
        case 0x4A: return 0x205;  // Home
        case 0x4B: return 0x206;  // Page Up
        case 0x4C: return 0x207;  // Delete
        case 0x4D: return 0x208;  // End
        case 0x4E: return 0x209;  // Page Down
        
        default: return 0;
    }
}

/// Check if a specific key is currently pressed
bool isKeyPressed(ubyte scancode) @nogc nothrow
{
    return g_keyboardState.keyDown[scancode];
}

/// Reset keyboard state
void resetKeyboardState() @nogc nothrow
{
    foreach (ref key; g_keyboardState.keyDown)
    {
        key = false;
    }
    g_keyboardState.lastReport = HIDKeyboardReport.init;
}
