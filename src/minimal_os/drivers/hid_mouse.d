module minimal_os.drivers.hid_mouse;

import minimal_os.display.input_pipeline : InputQueue, InputEvent, enqueue;
import minimal_os.display.framebuffer : framebufferMoveCursor;

@nogc:
nothrow:

/// HID mouse boot protocol report (3-4 bytes)
struct HIDMouseReport
{
    ubyte buttons;    // Bit flags for buttons
    byte deltaX;      // Relative X movement
    byte deltaY;      // Relative Y movement
    byte deltaWheel;  // Scroll wheel (optional, may be 0)
}

/// Mouse button bit flags
enum MouseButton : ubyte
{
    left   = 0x01,
    right  = 0x02,
    middle = 0x04,
}

/// Mouse cursor position and state
struct MouseState
{
    int x;              // Absolute X position
    int y;              // Absolute Y position
    ubyte buttons;      // Current button state
    ubyte lastButtons;  // Previous button state
    int wheelDelta;     // Accumulated wheel movement
}

private __gshared MouseState g_mouseState;

/// Initialize mouse state with screen bounds
void initializeMouseState(uint screenWidth, uint screenHeight) @nogc nothrow
{
    g_mouseState.x = cast(int)(screenWidth / 2);
    g_mouseState.y = cast(int)(screenHeight / 2);
    g_mouseState.buttons = 0;
    g_mouseState.lastButtons = 0;
    g_mouseState.wheelDelta = 0;
}

/// Process a HID mouse report and generate input events
void processMouseReport(ref const HIDMouseReport report, ref InputQueue queue, 
                       uint screenWidth, uint screenHeight) @nogc nothrow
{
    bool stateChanged = false;
    
    // Update position with delta movement
    if (report.deltaX != 0 || report.deltaY != 0)
    {
        g_mouseState.x += report.deltaX;
        g_mouseState.y += report.deltaY;
        
        // Clamp to screen bounds
        if (g_mouseState.x < 0) g_mouseState.x = 0;
        if (g_mouseState.y < 0) g_mouseState.y = 0;
        if (g_mouseState.x >= screenWidth) g_mouseState.x = cast(int)screenWidth - 1;
        if (g_mouseState.y >= screenHeight) g_mouseState.y = cast(int)screenHeight - 1;


        // Generate pointer move event
        InputEvent event;
        event.type = InputEvent.Type.pointerMove;
        event.data1 = g_mouseState.x;
        event.data2 = g_mouseState.y;
        event.data3 = g_mouseState.buttons;
        enqueue(queue, event);
        
        stateChanged = true;
    }
    
    // Detect button presses
    ubyte pressedButtons = report.buttons & ~g_mouseState.lastButtons;
    if (pressedButtons != 0)
    {
        InputEvent event;
        event.type = InputEvent.Type.buttonDown;
        event.data1 = g_mouseState.x;
        event.data2 = g_mouseState.y;
        event.data3 = pressedButtons;
        enqueue(queue, event);
        
        stateChanged = true;
    }
    
    // Detect button releases
    ubyte releasedButtons = g_mouseState.lastButtons & ~report.buttons;
    if (releasedButtons != 0)
    {
        InputEvent event;
        event.type = InputEvent.Type.buttonUp;
        event.data1 = g_mouseState.x;
        event.data2 = g_mouseState.y;
        event.data3 = releasedButtons;
        enqueue(queue, event);
        
        stateChanged = true;
    }
    
    // Update button state
    g_mouseState.lastButtons = g_mouseState.buttons;
    g_mouseState.buttons = report.buttons;
    
    // Handle scroll wheel (if present)
    if (report.deltaWheel != 0)
    {
        g_mouseState.wheelDelta += report.deltaWheel;
        stateChanged = true;
    }
}

/// Get current mouse position
void getMousePosition(out int x, out int y) @nogc nothrow
{
    x = g_mouseState.x;
    y = g_mouseState.y;
}

/// Check if a mouse button is currently pressed
bool isMouseButtonPressed(MouseButton button) @nogc nothrow
{
    return (g_mouseState.buttons & button) != 0;
}

/// Reset mouse state
void resetMouseState() @nogc nothrow
{
    g_mouseState.x = 0;
    g_mouseState.y = 0;
    g_mouseState.buttons = 0;
    g_mouseState.lastButtons = 0;
    g_mouseState.wheelDelta = 0;
}
