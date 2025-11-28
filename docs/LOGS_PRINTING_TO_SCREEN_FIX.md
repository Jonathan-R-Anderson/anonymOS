# Logs Printing to Screen - Fix

## Problem

When moving the cursor, verbose mouse logging was being printed to the screen, pushing the desktop upward and obscuring the installer UI.

## Root Cause

The `print()` and `printLine()` functions in `console.d` write to **three** outputs:
1. **VGA text buffer** (0xB8000)
2. **Framebuffer** (graphical screen)
3. **Serial port** (logs.txt)

When the desktop is running, we only want logs to go to the serial port, not the screen.

## The Fix

Added a call to `setFramebufferConsoleEnabled(false)` in `desktop.d` when the desktop loop starts:

```d
static bool loggedStart;
if (!loggedStart)
{
    import anonymos.console : printLine, setFramebufferConsoleEnabled;
    printLine("[desktop] runSimpleDesktopOnce start");
    
    // Disable console output to framebuffer so logs don't appear on screen
    setFramebufferConsoleEnabled(false);
    printLine("[desktop] framebuffer console disabled - logs go to serial only");
    
    loggedStart = true;
}
```

This function was already available in `console.d` (line 41-44) and controls whether `putChar()` writes to the framebuffer.

## How It Works

After calling `setFramebufferConsoleEnabled(false)`:
- ✅ Logs still go to **serial port** (logs.txt)
- ✅ Logs still go to **VGA text buffer** (for debugging)
- ❌ Logs **NO LONGER** go to the **framebuffer** (graphical screen)

This means all the detailed mouse logging (`[mouse] Report #...`) will only appear in `logs.txt`, not on the screen.

## Result

- The installer UI remains clean and visible
- Mouse movements don't cause screen scrolling
- All diagnostic logs are still captured in `logs.txt` for debugging
- The desktop rendering is not disturbed by console output

## Files Modified

- `/home/jonny/Documents/internetcomputer/src/anonymos/display/desktop.d`
  - Added `setFramebufferConsoleEnabled(false)` call in `runSimpleDesktopOnce()` (lines 164-169)

## Build and Test

```bash
./scripts/buildscript.sh
qemu-system-x86_64 -cdrom build/os.iso -m 512 -serial stdio 2>&1 | tee logs.txt
```

The installer should now be visible without logs scrolling on screen!
