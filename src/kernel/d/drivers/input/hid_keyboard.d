module drivers.input.hid_keyboard;

import display.input_pipeline : InputQueue, InputEvent, enqueue;
import core.ticks : getTickCount;

@nogc:
nothrow:

/// HID keyboard boot protocol report (8 bytes)
/// This structure represents the standard USB HID Boot Protocol report format.
struct HIDKeyboardReport
{
    ubyte modifiers;    /// Bit flags for modifier keys (Ctrl, Shift, Alt, Gui)
    ubyte reserved;     /// Reserved byte, always 0
    ubyte[6] keycodes;  /// Array of up to 6 simultaneous key presses (HID Usage IDs)
}

/// Modifier key bit flags
/// These correspond to the bits in the `modifiers` byte of the report.
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
/// Maintains the state of the keyboard between reports to detect changes.
struct KeyboardState
{
    HIDKeyboardReport lastReport;   /// The previous report received from the hardware
    bool[256] keyDown;              /// Logical state of each key (true = pressed)
    ulong[256] lastReleaseTime;     /// Timestamp of the last release event for each key (for debouncing)
}

private __gshared KeyboardState g_keyboardState;

/// Process a HID keyboard report and generate input events
///
/// This function compares the current report with the previous one to detect
/// key presses and releases. It applies debouncing logic to filter out
/// spurious events (common in some virtualization environments or noisy hardware).
///
/// Params:
///   report = The new HID report received from the hardware.
///   queue  = The input queue to enqueue generated events into.
void processKeyboardReport(ref const HIDKeyboardReport report, ref InputQueue queue) @nogc nothrow
{
    const ulong now = getTickCount();

    handleKeyPresses(report, queue, now);
    handleKeyReleases(report, queue, now);
    
    // Save current report for next comparison
    g_keyboardState.lastReport = report;
}

/// Detect and handle newly pressed keys
private void handleKeyPresses(ref const HIDKeyboardReport report, ref InputQueue queue, ulong now) @nogc nothrow
{
    foreach (keycode; report.keycodes)
    {
        if (keycode == 0) continue;
        
        if (isNewPress(keycode))
        {
            if (shouldDebounce(keycode, now))
            {
                continue;
            }

            enqueueKeyDown(keycode, report.modifiers, queue);
            g_keyboardState.keyDown[keycode] = true;
        }
    }
}

/// Detect and handle released keys
private void handleKeyReleases(ref const HIDKeyboardReport report, ref InputQueue queue, ulong now) @nogc nothrow
{
    foreach (oldKey; g_keyboardState.lastReport.keycodes)
    {
        if (oldKey == 0) continue;
        
        if (isReleased(oldKey, report))
        {
            // Only emit KeyUp if we previously emitted a KeyDown (logical state check)
            if (g_keyboardState.keyDown[oldKey])
            {
                enqueueKeyUp(oldKey, g_keyboardState.lastReport.modifiers, queue);
                g_keyboardState.keyDown[oldKey] = false;
            }
            g_keyboardState.lastReleaseTime[oldKey] = now;
        }
    }
}

/// Check if a keycode represents a new press (not present in the last report)
private bool isNewPress(ubyte keycode) @nogc nothrow
{
    foreach (oldKey; g_keyboardState.lastReport.keycodes)
    {
        if (oldKey == keycode) return false;
    }
    return true;
}

/// Check if a keycode represents a release (present in last report but not in current)
private bool isReleased(ubyte oldKey, ref const HIDKeyboardReport report) @nogc nothrow
{
    foreach (keycode; report.keycodes)
    {
        if (keycode == oldKey) return false;
    }
    return true;
}

/// Check if a key press should be ignored due to debouncing
/// Returns true if the key was released too recently (within 80ms).
private bool shouldDebounce(ubyte keycode, ulong now) @nogc nothrow
{
    // 8 ticks = 80ms (assuming 100Hz timer)
    return (now > g_keyboardState.lastReleaseTime[keycode] && 
           (now - g_keyboardState.lastReleaseTime[keycode]) < 8);
}

/// Helper to enqueue a KeyDown event
private void enqueueKeyDown(ubyte keycode, ubyte modifiers, ref InputQueue queue) @nogc nothrow
{
    InputEvent event;
    event.type = InputEvent.Type.keyDown;
    event.data1 = translateScancode(keycode, modifiers);
    event.data2 = keycode;
    event.data3 = modifiers;
    enqueue(queue, event);
}

/// Helper to enqueue a KeyUp event
private void enqueueKeyUp(ubyte keycode, ubyte modifiers, ref InputQueue queue) @nogc nothrow
{
    InputEvent event;
    event.type = InputEvent.Type.keyUp;
    event.data1 = translateScancode(keycode, modifiers);
    event.data2 = keycode;
    event.data3 = modifiers;
    enqueue(queue, event);
}

/// Translate HID scancode to ASCII character or internal keycode
private int translateScancode(ubyte scancode, ubyte modifiers) @nogc nothrow pure
{
    const bool shift = (modifiers & (KeyModifier.leftShift | KeyModifier.rightShift)) != 0;
    
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
