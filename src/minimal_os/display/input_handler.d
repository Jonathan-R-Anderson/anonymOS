module minimal_os.display.input_handler;

import minimal_os.display.input_pipeline : InputEvent, InputQueue, dequeue;
import minimal_os.display.window_manager.manager : WindowManager, Window;
import minimal_os.display.framebuffer : g_fb;

@nogc:
nothrow:

/// Mouse cursor state for window interactions
struct CursorState
{
    int x;
    int y;
    bool dragging;
    size_t dragWindowId;
    int dragStartX;
    int dragStartY;
    int windowStartX;
    int windowStartY;
}

private __gshared CursorState g_cursor;

private bool fetchWindow(ref const WindowManager manager, size_t id, out const Window* window) @nogc nothrow
{
    foreach (ref const candidate; manager.windows())
    {
        if (candidate.id == id)
        {
            window = &candidate;
            return true;
        }
    }
    return false;
}

private void dispatchToWindow(ref const InputEvent event, ref WindowManager manager, size_t id) @nogc nothrow
{
    if (id == size_t.max)
    {
        return;
    }

    InputEvent translated = event;
    const Window* window;
    if (fetchWindow(manager, id, window))
    {
        if (event.type == InputEvent.Type.pointerMove ||
            event.type == InputEvent.Type.buttonDown ||
            event.type == InputEvent.Type.buttonUp)
        {
            translated.data1 -= window.x;
            translated.data2 -= window.y;
        }
    }

    manager.queueInputForWindow(id, translated);
}

/// Initialize the input handler with screen dimensions
void initializeInputHandler(uint screenWidth, uint screenHeight) @nogc nothrow
{
    g_cursor.x = cast(int)(screenWidth / 2);
    g_cursor.y = cast(int)(screenHeight / 2);
    g_cursor.dragging = false;
    g_cursor.dragWindowId = size_t.max;
}

/// Process all pending input events and update window manager state
void processInputEvents(ref InputQueue queue, ref WindowManager manager) @nogc nothrow
{
    InputEvent event;
    
    while (dequeue(queue, event))
    {
        final switch (event.type)
        {
            case InputEvent.Type.unknown:
                break;
                
            case InputEvent.Type.keyDown:
                handleKeyDown(event, manager);
                break;
                
            case InputEvent.Type.keyUp:
                handleKeyUp(event, manager);
                break;
                
            case InputEvent.Type.pointerMove:
                handlePointerMove(event, manager);
                break;
                
            case InputEvent.Type.buttonDown:
                handleButtonDown(event, manager);
                break;
                
            case InputEvent.Type.buttonUp:
                handleButtonUp(event, manager);
                break;
        }
    }
}

private void handleKeyDown(ref const InputEvent event, ref WindowManager manager) @nogc nothrow
{
    const int key = event.data1;
    const int scancode = event.data2;
    const ubyte modifiers = cast(ubyte)event.data3;
    
    // Check for Alt+Tab (cycle focus)
    const bool altPressed = (modifiers & 0x44) != 0;  // Left or right Alt
    if (altPressed && key == '\t')
    {
        cycleWindowFocus(manager);
        return;
    }
    
    // Check for Ctrl+W (close window)
    const bool ctrlPressed = (modifiers & 0x11) != 0;  // Left or right Ctrl
    if (ctrlPressed && (key == 'w' || key == 'W'))
    {
        const focusedId = manager.focusedWindowId();
        if (focusedId != size_t.max)
        {
            manager.destroyWindow(focusedId);
        }
        return;
    }
    
    // Check for window manager shortcuts
    // F1-F3 switch desktops
    if (key >= 0x100 && key <= 0x102)  // F1, F2, F3
    {
        const desktop = cast(size_t)(key - 0x100);
        manager.switchDesktop(desktop);
        return;
    }

    // Arrow keys for window movement (with Alt modifier)
    if (altPressed)
    {
        const focusedId = manager.focusedWindowId();
        if (focusedId != size_t.max)
        {
            const moveAmount = 16;
            
            if (key == 0x200)  // Right arrow
                manager.moveWindow(focusedId, moveAmount, 0);
            else if (key == 0x201)  // Left arrow
                manager.moveWindow(focusedId, -moveAmount, 0);
            else if (key == 0x202)  // Down arrow
                manager.moveWindow(focusedId, 0, moveAmount);
            else if (key == 0x203)  // Up arrow
                manager.moveWindow(focusedId, 0, -moveAmount);
        }
        return;
    }

    dispatchToWindow(event, manager, manager.focusedWindowId());
}

private void handleKeyUp(ref const InputEvent event, ref WindowManager manager) @nogc nothrow
{
    dispatchToWindow(event, manager, manager.focusedWindowId());
}

private void handlePointerMove(ref const InputEvent event, ref WindowManager manager) @nogc nothrow
{
    g_cursor.x = event.data1;
    g_cursor.y = event.data2;
    
    // Handle window dragging
    if (g_cursor.dragging && g_cursor.dragWindowId != size_t.max)
    {
        const int deltaX = g_cursor.x - g_cursor.dragStartX;
        const int deltaY = g_cursor.y - g_cursor.dragStartY;
        
        manager.moveWindow(g_cursor.dragWindowId, 
                          deltaX, 
                          deltaY);
        
        // Update drag start position for next frame
        g_cursor.dragStartX = g_cursor.x;
        g_cursor.dragStartY = g_cursor.y;
    }

    dispatchToWindow(event, manager, manager.focusedWindowId());
}

private void handleButtonDown(ref const InputEvent event, ref WindowManager manager) @nogc nothrow
{
    const int mouseX = event.data1;
    const int mouseY = event.data2;
    const ubyte buttons = cast(ubyte)event.data3;
    
    // Left button click
    if ((buttons & 0x01) != 0)
    {
        // Find which window was clicked
        const clickedId = findWindowAtPosition(manager, mouseX, mouseY);
        
        if (clickedId != size_t.max)
        {
            // Focus the clicked window
            manager.focusWindow(clickedId);
            
            // Check if click is in title bar (for dragging)
            if (isInTitleBar(manager, clickedId, mouseX, mouseY))
            {
                g_cursor.dragging = true;
                g_cursor.dragWindowId = clickedId;
                g_cursor.dragStartX = mouseX;
                g_cursor.dragStartY = mouseY;
            }

            dispatchToWindow(event, manager, clickedId);
        }
    }
}

private void handleButtonUp(ref const InputEvent event, ref WindowManager manager) @nogc nothrow
{
    const ubyte buttons = cast(ubyte)event.data3;

    // Left button released - stop dragging
    if ((buttons & 0x01) == 0 && g_cursor.dragging)
    {
        g_cursor.dragging = false;
        g_cursor.dragWindowId = size_t.max;
    }

    dispatchToWindow(event, manager, manager.focusedWindowId());
}

private void cycleWindowFocus(ref WindowManager manager) @nogc nothrow
{
    const windows = manager.windows();
    if (windows.length == 0)
    {
        return;
    }
    
    const currentFocused = manager.focusedWindowId();
    size_t nextIndex = 0;
    
    // Find current focused window index
    foreach (i, ref const window; windows)
    {
        if (window.id == currentFocused && window.desktop == manager.activeDesktop())
        {
            nextIndex = (i + 1) % windows.length;
            break;
        }
    }
    
    // Find next non-minimized window on current desktop
    foreach (offset; 0 .. windows.length)
    {
        const idx = (nextIndex + offset) % windows.length;
        if (windows[idx].desktop == manager.activeDesktop() && !windows[idx].minimized)
        {
            manager.focusWindow(windows[idx].id);
            return;
        }
    }
}

private size_t findWindowAtPosition(ref const WindowManager manager, int x, int y) @nogc nothrow
{
    const windows = manager.windows();
    
    // Check from front to back (highest z-order first)
    for (size_t i = windows.length; i > 0; --i)
    {
        const idx = i - 1;
        const window = windows[idx];
        
        if (window.desktop != manager.activeDesktop() || window.minimized)
        {
            continue;
        }
        
        if (x >= window.x && x < window.x + window.width &&
            y >= window.y && y < window.y + window.height)
        {
            return window.id;
        }
    }
    
    return size_t.max;
}

private bool isInTitleBar(ref const WindowManager manager, size_t windowId, int x, int y) @nogc nothrow
{
    const windows = manager.windows();
    
    foreach (ref const window; windows)
    {
        if (window.id == windowId)
        {
            const titleHeight = 24;
            return (y >= window.y && y < window.y + titleHeight);
        }
    }
    
    return false;
}

/// Get current cursor position
void getCursorPosition(out int x, out int y) @nogc nothrow
{
    x = g_cursor.x;
    y = g_cursor.y;
}
