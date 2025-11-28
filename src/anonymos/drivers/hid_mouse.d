module anonymos.drivers.hid_mouse;

import anonymos.display.input_pipeline : InputQueue, InputEvent, enqueue;
import anonymos.display.framebuffer : framebufferMoveCursor;
import anonymos.console : print, printLine, printUnsigned;

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

    int wheelDelta;     // Accumulated wheel movement
}

private __gshared MouseState g_mouseState;

/// Initialize mouse state with screen bounds
void initializeMouseState(uint screenWidth, uint screenHeight) @nogc nothrow
{
    g_mouseState.x = cast(int)(screenWidth / 2);
    g_mouseState.y = cast(int)(screenHeight / 2);
    g_mouseState.buttons = 0;

    g_mouseState.wheelDelta = 0;
}

/// Process a HID mouse report and generate input events
void processMouseReport(ref const HIDMouseReport report, ref InputQueue queue, 
                       uint screenWidth, uint screenHeight) @nogc nothrow
{
    import anonymos.console : print, printLine, printUnsigned, printHex;
    
    static uint reportCount = 0;
    static uint moveCount = 0;
    static uint buttonDownCount = 0;
    static uint buttonUpCount = 0;
    
    reportCount++;
    
    // Log every report for debugging
    if (reportCount % 10 == 1 || report.deltaX != 0 || report.deltaY != 0 || report.buttons != g_mouseState.buttons)
    {
        print("[mouse] Report #");
        printUnsigned(reportCount);
        print(": delta=(");
        if (report.deltaX < 0)
        {
            print("-");
            printUnsigned(cast(uint)(-report.deltaX));
        }
        else
        {
            printUnsigned(cast(uint)report.deltaX);
        }
        print(", ");
        if (report.deltaY < 0)
        {
            print("-");
            printUnsigned(cast(uint)(-report.deltaY));
        }
        else
        {
            printUnsigned(cast(uint)report.deltaY);
        }
        print(") buttons=0x");
        printHex(report.buttons);
        print(" pos=(");
        printUnsigned(cast(uint)g_mouseState.x);
        print(", ");
        printUnsigned(cast(uint)g_mouseState.y);
        print(")");
        printLine("");
    }
    
    bool stateChanged = false;
    
    // Update position with delta movement
    if (report.deltaX != 0 || report.deltaY != 0)
    {
        int oldX = g_mouseState.x;
        int oldY = g_mouseState.y;
        
        g_mouseState.x += report.deltaX;
        g_mouseState.y += report.deltaY;
        
        // Clamp to screen bounds
        if (g_mouseState.x < 0) g_mouseState.x = 0;
        if (g_mouseState.y < 0) g_mouseState.y = 0;
        if (g_mouseState.x >= screenWidth) g_mouseState.x = cast(int)screenWidth - 1;
        if (g_mouseState.y >= screenHeight) g_mouseState.y = cast(int)screenHeight - 1;

        moveCount++;
        
        // Log significant movements
        int dx = g_mouseState.x - oldX;
        int dy = g_mouseState.y - oldY;
        int absDelta = (dx < 0 ? -dx : dx) + (dy < 0 ? -dy : dy);
        
        if (absDelta > 50)
        {
            print("[mouse] LARGE MOVE #");
            printUnsigned(moveCount);
            print(": (");
            printUnsigned(cast(uint)oldX);
            print(", ");
            printUnsigned(cast(uint)oldY);
            print(") -> (");
            printUnsigned(cast(uint)g_mouseState.x);
            print(", ");
            printUnsigned(cast(uint)g_mouseState.y);
            print(") delta=");
            printUnsigned(cast(uint)absDelta);
            printLine("");
        }

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
    ubyte pressedButtons = report.buttons & ~g_mouseState.buttons;
    if (pressedButtons != 0)
    {
        buttonDownCount++;
        print("[mouse] BUTTON DOWN #");
        printUnsigned(buttonDownCount);
        print(": buttons=0x");
        printHex(pressedButtons);
        print(" at (");
        printUnsigned(cast(uint)g_mouseState.x);
        print(", ");
        printUnsigned(cast(uint)g_mouseState.y);
        print(")");
        printLine("");
        
        InputEvent event;
        event.type = InputEvent.Type.buttonDown;
        event.data1 = g_mouseState.x;
        event.data2 = g_mouseState.y;
        event.data3 = pressedButtons;
        enqueue(queue, event);
        
        stateChanged = true;
    }
    
    // Detect button releases
    ubyte releasedButtons = g_mouseState.buttons & ~report.buttons;
    if (releasedButtons != 0)
    {
        buttonUpCount++;
        print("[mouse] BUTTON UP #");
        printUnsigned(buttonUpCount);
        print(": buttons=0x");
        printHex(releasedButtons);
        print(" at (");
        printUnsigned(cast(uint)g_mouseState.x);
        print(", ");
        printUnsigned(cast(uint)g_mouseState.y);
        print(")");
        printLine("");
        
        InputEvent event;
        event.type = InputEvent.Type.buttonUp;
        event.data1 = g_mouseState.x;
        event.data2 = g_mouseState.y;
        event.data3 = releasedButtons;
        enqueue(queue, event);
        
        stateChanged = true;
    }
    
    // Update button state
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

    g_mouseState.wheelDelta = 0;
}
