# Installer Not Responding to Clicks - Fix

## Problem

When clicking the "Next" button in the installer, nothing happened. The installer UI was visible but completely unresponsive to mouse clicks.

## Root Cause Analysis

Looking at the desktop loop in `desktop.d`:

```d
// Installer Input Logic
if (g_installer.active)
{
    size_t idx = g_inputQueue.head;
    while (idx != g_inputQueue.tail)
    {
        if (handleInstallerInput(g_inputQueue.events[idx]))
        {
            damage.add(0, 0, g_fb.width, g_fb.height);
        }
        idx = (idx + 1) % g_inputQueue.capacity;
    }
}

// Process all pending input events
processInputEvents(g_inputQueue, g_windowManager, &damage);  // ← Problem!
```

**The issue:** The installer code was iterating over the input queue but **NOT consuming it**. Then `processInputEvents()` would consume the entire queue for the window manager, so the installer never actually received the events!

The installer was reading events but the queue pointers (`head` and `tail`) were never updated, so:
1. Installer reads events from queue ✅
2. Installer doesn't consume/clear queue ❌
3. Window manager consumes entire queue ✅
4. Installer events are lost ❌

## The Fix

Changed the logic to:
1. **Only process installer events when installer is active**
2. **Clear the queue after installer processes events**
3. **Skip window manager processing when installer is active**

```d
// Installer Input Logic - process BEFORE window manager
if (g_installer.active)
{
    import anonymos.display.input_pipeline : InputEvent;
    import anonymos.console : print, printLine, printUnsigned;
    
    size_t idx = g_inputQueue.head;
    while (idx != g_inputQueue.tail)
    {
        const ref event = g_inputQueue.events[idx];
        
        // Log button events for debugging
        if (event.type == InputEvent.Type.buttonDown)
        {
            print("[desktop] Installer received BUTTON DOWN at (");
            printUnsigned(cast(uint)event.data2);
            print(", ");
            printUnsigned(cast(uint)event.data3);
            printLine(")");
        }
        
        if (handleInstallerInput(event))
        {
            damage.add(0, 0, g_fb.width, g_fb.height);
        }
        idx = (idx + 1) % g_inputQueue.capacity;
    }
    
    // Clear the queue so window manager doesn't process installer events
    g_inputQueue.head = g_inputQueue.tail;
}
else
{
    // Process all pending input events for window manager
    processInputEvents(g_inputQueue, g_windowManager, &damage);
}
```

## What Changed

1. **Added logging** for button down events to verify installer receives them
2. **Clear the queue** after installer processes events (`g_inputQueue.head = g_inputQueue.tail`)
3. **Skip window manager** input processing when installer is active (use `else` block)

## Expected Behavior

After rebuilding, when you click in the installer:

**In logs.txt:**
```
[mouse] BUTTON DOWN #X: buttons=0x0000000000000001 at (X, Y)
[desktop] Installer received BUTTON DOWN at (X, Y)
```

And the installer should respond to clicks on:
- Navigation buttons (Back/Next)
- Sidebar menu items
- Input fields

## Files Modified

- `/home/jonny/Documents/internetcomputer/src/anonymos/display/desktop.d`
  - Modified installer input handling in `runSimpleDesktopLoop()` (lines 489-522)
  - Added event logging and queue clearing

## Build and Test

```bash
./scripts/buildscript.sh
qemu-system-x86_64 -cdrom build/os.iso -m 512 -serial stdio 2>&1 | tee logs.txt
```

Click the "Next" button and verify:
1. Logs show `[desktop] Installer received BUTTON DOWN`
2. Installer advances to the next screen
3. Sidebar items are clickable
