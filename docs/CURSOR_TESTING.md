# Cursor Movement Testing and Diagnostics

## Overview

This document describes the cursor movement testing framework and diagnostic tools added to AnonymOS to identify and fix cursor flashing and jumping issues.

## Issues Identified

### 1. **Screen Flashing**
**Symptom**: The screen flickers when the mouse moves.

**Root Cause**: 
- The compositor was redrawing the entire screen every frame
- Cursor save/restore logic was conflicting with full-screen redraws
- Cursor visibility state was not properly tracked

**Fix Applied**:
- Added `cursorCurrentlyVisible` state tracking
- Only hide/show cursor when damage occurs
- Use `framebufferForgetCursor()` in compositor mode to avoid background corruption
- Proper state management to prevent redundant show/hide calls

### 2. **Cursor Jumping**
**Symptom**: The cursor occasionally jumps to unexpected positions.

**Root Cause**:
- Mouse button state was being compared against `lastButtons` instead of current `buttons`
- Edge detection logic was incorrect, causing missed or duplicate events

**Fix Applied**:
- Corrected button edge detection in `hid_mouse.d`
- Removed unused `lastButtons` field
- Simplified state tracking to use only `buttons` field

## Testing Framework

### Unit Tests

Location: `tests/cursor_movement_test.d`

The test suite includes:

1. **Basic Movement Test**: Validates movement in all four cardinal directions
2. **Boundary Clamping Test**: Ensures cursor stays within screen bounds
3. **Button Detection Test**: Verifies button press/release events
4. **Rapid Movement Test**: Stress test with 100 rapid movements
5. **Zero-Delta Test**: Ensures no spurious events for zero movement
6. **Diagonal Movement Test**: Tests combined X/Y movement

### Running Tests

**Keyboard Shortcut**: Press `Ctrl+Shift+T` in the desktop environment

**Expected Output**:
```
=== Cursor Movement Test Suite ===
[test] Testing basic movement...
[PASS] Basic movement test
[test] Testing boundary clamping...
[PASS] Boundary clamping test
[test] Testing button detection...
[PASS] Button detection test
[test] Testing rapid movement...
[PASS] Rapid movement test
[test] Testing zero-delta reports...
[PASS] Zero-delta test
[test] Testing diagonal movement...
[PASS] Diagonal movement test
=== Test Results ===
Passed: 6
Failed: 0
```

### Diagnostics

Location: `src/anonymos/display/cursor_diagnostics.d`

The diagnostic module tracks:

- **Frame count**: Total frames rendered
- **Cursor moves**: Number of cursor position changes
- **Cursor shows/hides**: Visibility state changes
- **Jump detections**: Movements > 100 pixels in one frame
- **Flash detections**: Excessive show/hide calls
- **Performance metrics**: Average and max movement deltas

**Viewing Diagnostics**: Automatically printed after running tests with `Ctrl+Shift+T`

**Sample Output**:
```
=== Cursor Diagnostics Report ===
Frames rendered: 1234
Cursor moves: 456
Cursor shows: 234
Cursor hides: 233
Cursor forgets: 1
Average move delta: 5
Max single move delta: 15
Jump detections: 0
Flash detections: 0
Last position: (512, 384)
Cursor visible: yes
```

## Implementation Details

### Cursor Rendering Flow

```
Input Event (PS/2 or USB)
    ↓
processMouseReport() [hid_mouse.d]
    ↓
Update g_mouseState.x, g_mouseState.y
    ↓
Generate InputEvent.pointerMove
    ↓
Desktop Loop [desktop.d]
    ↓
getMousePosition() → (mx, my)
    ↓
Check for damage
    ↓
If damage:
    - Hide cursor (if visible)
    - Render desktop
    - Show cursor at new position
Else if moved:
    - Move cursor (handles save/restore)
    - Ensure visible
Else:
    - Ensure visible
```

### Key Functions

**Mouse State** (`hid_mouse.d`):
- `initializeMouseState()`: Initialize to screen center
- `processMouseReport()`: Update position and generate events
- `getMousePosition()`: Query current position

**Cursor Rendering** (`framebuffer.d`):
- `framebufferMoveCursor()`: Move cursor with save/restore
- `framebufferShowCursor()`: Make cursor visible
- `framebufferHideCursor()`: Hide and restore background
- `framebufferForgetCursor()`: Mark cursor invalid without restore

**Desktop Loop** (`desktop.d`):
- Tracks `cursorCurrentlyVisible` state
- Only hides/shows when necessary
- Uses compositor mode for better performance

## Performance Considerations

### Before Fixes
- Screen redraw: Every frame (~60 FPS)
- Cursor show/hide: 2x per frame = 120 calls/sec
- Result: Visible flashing

### After Fixes
- Screen redraw: Only on damage (~1-10 FPS typical)
- Cursor show/hide: Only on damage
- Cursor move: Only when mouse moves
- Result: Smooth, flicker-free cursor

## Debugging Tips

### Enable Verbose Logging

Add to `hid_mouse.d`:
```d
print("[mouse] delta=("); 
printUnsigned(cast(uint)report.deltaX); 
print(", "); 
printUnsigned(cast(uint)report.deltaY); 
printLine(")");
```

### Monitor Cursor State

Check `g_cursorDiag` values during runtime to identify issues.

### Test Scenarios

1. **Idle Test**: Leave mouse still - should see zero moves, zero jumps
2. **Slow Movement**: Move mouse slowly - should see smooth tracking
3. **Fast Movement**: Move mouse rapidly - should see no jumps
4. **Boundary Test**: Move to screen edges - should clamp correctly
5. **Click Test**: Click buttons - should see press/release events

## Known Limitations

1. **Compositor Performance**: Full compositor mode may be slower on some hardware
2. **PS/2 Polling**: Relies on IRQ-driven input; polling mode is throttled
3. **USB HID**: Full USB stack not yet implemented; relies on PS/2 legacy routing

## Future Improvements

1. **Hardware Cursor**: Use GPU hardware cursor when available
2. **Acceleration**: Implement mouse acceleration curves
3. **Multi-Monitor**: Support for multiple displays
4. **Touch Input**: Add touchscreen support
5. **Gesture Recognition**: Implement multi-touch gestures

## References

- `src/anonymos/drivers/hid_mouse.d`: Mouse input processing
- `src/anonymos/display/framebuffer.d`: Cursor rendering
- `src/anonymos/display/desktop.d`: Desktop event loop
- `tests/cursor_movement_test.d`: Unit tests
- `src/anonymos/display/cursor_diagnostics.d`: Diagnostic tools
