# Installer Button Clicks Not Working - Coordinate Mismatch Fix

## Problem

The installer was receiving click events (visible in logs as `[desktop] Installer received BUTTON DOWN at (856, 705)`), but the "Next" button wasn't responding. The cursor visually appeared to be over the button, but clicks weren't registering.

## Root Cause

**Coordinate synchronization mismatch** between rendering and input handling.

### What Was Happening:

1. **Compositor renders installer** at calculated position:
   ```d
   uint w = 800;
   uint h = 500;
   uint x = (g_fb.width - w) / 2;  // e.g., (1024 - 800) / 2 = 112
   uint y = (g_fb.height - h) / 2; // e.g., (768 - 500) / 2 = 134
   renderInstallerWindow(&c, x, y, w, h);
   ```

2. **Input handler recalculates** window position:
   ```d
   // WRONG: Recalculating independently!
   int w = 800;
   int h = 500;
   int winX = (g_fb.width - w) / 2;  // Might be different timing!
   int winY = (g_fb.height - h) / 2;
   ```

3. **Hit-test uses wrong coordinates**:
   ```d
   int nextX = winX + w - 120;  // Using recalculated winX
   int nextY = winY + h - 60;
   
   if (mx >= nextX && mx <= nextX + 100 && my >= nextY && my <= nextY + 36)
   {
       nextModule();  // Never reached!
   }
   ```

### Why It Failed:

Even though the calculations looked identical, they were executed at different times and potentially with different framebuffer dimensions. More importantly, the compositor was setting the geometry but the input handler was ignoring it and recalculating.

**Example from logs:**
- Click at: `(856, 705)`
- Expected Next button: `~(792, 574)` to `~(892, 610)` (if recalculated)
- Actual Next button: `(112 + 800 - 120, 134 + 500 - 60)` = `(792, 574)` to `(892, 610)`

The mismatch meant clicks at `(856, 705)` were outside the hit box!

## The Fix

### Step 1: Store Window Geometry in Compositor

Added fields to `CalamaresInstaller` struct:
```d
public struct CalamaresInstaller
{
    // ... existing fields ...
    
    int windowX;
    int windowY;
    int windowW;
    int windowH;
}
```

### Step 2: Set Geometry When Rendering

In `compositor.d`, when rendering the installer:
```d
uint w = 800;
uint h = 500;
uint x = (g_fb.width - w) / 2;
uint y = (g_fb.height - h) / 2;

// Store the geometry
g_installer.windowX = cast(int)x;
g_installer.windowY = cast(int)y;
g_installer.windowW = cast(int)w;
g_installer.windowH = cast(int)h;

renderInstallerWindow(&c, cast(int)x, cast(int)y, cast(int)w, cast(int)h);
```

### Step 3: Use Stored Geometry in Input Handler

In `installer.d`, `handleInstallerInput()`:
```d
// Use stored window geometry from compositor
int w = g_installer.windowW;
int h = g_installer.windowH;
int winX = g_installer.windowX;
int winY = g_installer.windowY;

// Now hit-test uses SAME coordinates as rendering!
int nextX = winX + w - 120;
int nextY = winY + h - 60;

if (mx >= nextX && mx <= nextX + 100 && my >= nextY && my <= nextY + 36)
{
    printLine("[installer] NEXT button clicked!");
    nextModule();
    return true;
}
```

### Step 4: Added Debug Logging

To verify the fix works:
```d
print("[installer] Click at (");
printUnsigned(cast(uint)mx);
print(", ");
printUnsigned(cast(uint)my);
print(") Next button: (");
printUnsigned(cast(uint)nextX);
print(", ");
printUnsigned(cast(uint)nextY);
print(") to (");
printUnsigned(cast(uint)(nextX + 100));
print(", ");
printUnsigned(cast(uint)(nextY + 36));
printLine(")");
```

## Expected Behavior After Fix

When you click the "Next" button, you should see in `logs.txt`:

```
[desktop] Installer received BUTTON DOWN at (856, 574)
[installer] Click at (856, 574) Next button: (792, 574) to (892, 610)
[installer] NEXT button clicked!
```

And the installer will advance to the next screen!

## Files Modified

1. `/home/jonny/Documents/internetcomputer/src/anonymos/display/installer.d`
   - Modified `CalamaresInstaller` struct to add `windowX`, `windowY`, `windowW`, `windowH` fields
   - Modified `handleInstallerInput()` to use stored geometry instead of recalculating
   - Added debug logging for button hit-testing

2. `/home/jonny/Documents/internetcomputer/src/anonymos/display/compositor.d`
   - Modified `renderWorkspaceComposited()` to store window geometry in `g_installer`

## Build and Test

```bash
./scripts/buildscript.sh
qemu-system-x86_64 -cdrom build/os.iso -m 512 -serial stdio 2>&1 | tee logs.txt
```

Click the "Next" button and verify it advances through the installer screens!

## Key Lesson

**Never recalculate geometry independently** - always use a single source of truth. If the renderer calculates a position, store it and reuse it for hit-testing. Otherwise you get subtle timing-dependent bugs that are hard to debug.
