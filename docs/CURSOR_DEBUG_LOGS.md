# Cursor Debugging Logs - Quick Reference

## Overview
Comprehensive logging has been added to track cursor movement and screen flashing issues. All logs will appear in your `logs.txt` file.

## Log Categories

### 1. Mouse Input Reports (`hid_mouse.d`)

**Every 10th report or when there's activity:**
```
[mouse] Report #123: delta=(5, -3) buttons=0x00 pos=(512, 384)
```
- `Report #`: Sequential report number
- `delta`: X/Y movement from PS/2 or USB
- `buttons`: Button state (0x01=left, 0x02=right, 0x04=middle)
- `pos`: Current cursor position

**Large movements (>50 pixels):**
```
[mouse] LARGE MOVE #45: (100, 200) -> (180, 250) delta=130
```
- Indicates potential cursor jumping
- Shows old position, new position, and total delta

**Button events:**
```
[mouse] BUTTON DOWN #12: buttons=0x01 at (512, 384)
[mouse] BUTTON UP #12: buttons=0x01 at (512, 384)
```
- Tracks every button press and release
- Shows position where button event occurred

### 2. Framebuffer Cursor Operations (`framebuffer.d`)

**Cursor movement (every 100th or large moves >50px):**
```
[fb-cursor] Move #456: (512, 384) visible=yes
```
- Tracks cursor position updates
- Shows visibility state

**Cursor show (every 10th):**
```
[fb-cursor] Show #78: at (512, 384) was_visible=no
```
- Tracks when cursor is made visible
- Shows previous visibility state

**Cursor hide (every 10th):**
```
[fb-cursor] Hide #77: was_visible=yes
```
- Tracks when cursor is hidden
- Excessive hide/show indicates flashing

**Cursor forget (every 10th):**
```
[fb-cursor] Forget #5
```
- Compositor mode: invalidates cursor without restoring background
- Should be rare in normal operation

### 3. Desktop Event Loop (`desktop.d`)

**Damage events (every 1000th frame):**
```
[desktop] Frame 5000: DAMAGE at (100, 100) size 200x150
```
- Shows when screen needs redrawing
- Position and size of damaged region
- Frequent damage = performance issue

**Cursor-only movement (every 1000th frame):**
```
[desktop] Frame 5001: CURSOR MOVE (512, 384) -> (520, 390)
```
- Cursor moved without screen damage
- Should be most common case

**Cursor visibility recovery (every 1000th frame):**
```
[desktop] Frame 5002: SHOW CURSOR (was hidden)
```
- Cursor was hidden but should be visible
- Indicates state management issue if frequent

## Diagnosing Issues

### Problem: Screen Flashing

**Look for:**
1. Excessive `[fb-cursor] Hide` and `[fb-cursor] Show` messages
2. `[desktop] DAMAGE` appearing every frame
3. High ratio of Hide/Show to Move operations

**Expected behavior:**
- Hide/Show should only occur when damage happens
- Most frames should be cursor-only moves
- Damage should be infrequent (1-10 FPS typical)

**Example of GOOD logs:**
```
[mouse] Report #100: delta=(2, 1) buttons=0x00 pos=(514, 385)
[fb-cursor] Move #100: (514, 385) visible=yes
[desktop] Frame 1000: CURSOR MOVE (512, 384) -> (514, 385)
... (999 frames with no damage)
[desktop] Frame 2000: CURSOR MOVE (520, 390) -> (525, 395)
```

**Example of BAD logs (flashing):**
```
[desktop] Frame 1000: DAMAGE at (0, 0) size 1024x768
[fb-cursor] Hide #500: was_visible=yes
[fb-cursor] Show #500: at (512, 384) was_visible=no
[desktop] Frame 1001: DAMAGE at (0, 0) size 1024x768
[fb-cursor] Hide #501: was_visible=yes
[fb-cursor] Show #501: at (512, 384) was_visible=no
```

### Problem: Cursor Jumping

**Look for:**
1. `[mouse] LARGE MOVE` messages
2. Sudden position changes in `[mouse] Report` logs
3. Delta values that don't match expected mouse movement

**Expected behavior:**
- No LARGE MOVE messages during normal use
- Delta values should be small (typically -10 to +10)
- Position should change smoothly

**Example of GOOD logs:**
```
[mouse] Report #100: delta=(2, 1) buttons=0x00 pos=(512, 384)
[mouse] Report #101: delta=(3, -1) buttons=0x00 pos=(515, 383)
[mouse] Report #102: delta=(1, 2) buttons=0x00 pos=(516, 385)
```

**Example of BAD logs (jumping):**
```
[mouse] Report #100: delta=(2, 1) buttons=0x00 pos=(512, 384)
[mouse] LARGE MOVE #50: (512, 384) -> (700, 200) delta=372
[mouse] Report #101: delta=(188, -184) buttons=0x00 pos=(700, 200)
```

### Problem: Buttons Not Working

**Look for:**
1. `[mouse] Report` showing button changes but no BUTTON DOWN/UP
2. Button state stuck (always 0x01 or never changing)
3. BUTTON DOWN without matching BUTTON UP

**Expected behavior:**
- Every button press should generate BUTTON DOWN
- Every button release should generate BUTTON UP
- Button state should toggle cleanly

**Example of GOOD logs:**
```
[mouse] Report #100: delta=(0, 0) buttons=0x01 pos=(512, 384)
[mouse] BUTTON DOWN #1: buttons=0x01 at (512, 384)
[mouse] Report #105: delta=(0, 0) buttons=0x00 pos=(512, 384)
[mouse] BUTTON UP #1: buttons=0x01 at (512, 384)
```

**Example of BAD logs (not working):**
```
[mouse] Report #100: delta=(0, 0) buttons=0x01 pos=(512, 384)
[mouse] Report #101: delta=(0, 0) buttons=0x01 pos=(512, 384)
[mouse] Report #102: delta=(0, 0) buttons=0x00 pos=(512, 384)
(no BUTTON DOWN or BUTTON UP messages)
```

## Log Analysis Commands

If you can access the logs via serial or file:

```bash
# Count cursor operations
grep -c "\[fb-cursor\]" logs.txt

# Find large movements
grep "LARGE MOVE" logs.txt

# Count damage events
grep -c "DAMAGE" logs.txt

# Show button events
grep "BUTTON" logs.txt

# Calculate hide/show ratio (should be close to 1:1)
grep -c "Hide" logs.txt
grep -c "Show" logs.txt
```

## Performance Metrics

**Healthy system:**
- Reports: 60-120/sec (depends on mouse movement)
- Cursor moves: 60-120/sec (matches reports)
- Cursor show/hide: 1-10/sec (only on damage)
- Damage events: 1-10/sec (only when needed)
- Large moves: 0/sec (none expected)

**Unhealthy system (flashing):**
- Reports: 60-120/sec (normal)
- Cursor moves: 60-120/sec (normal)
- Cursor show/hide: 120-240/sec (TOO HIGH)
- Damage events: 60/sec (TOO HIGH - every frame)
- Large moves: varies

**Unhealthy system (jumping):**
- Reports: 60-120/sec (normal)
- Cursor moves: varies
- Large moves: >0/sec (PROBLEM)
- Sudden position changes in reports

## Next Steps

1. **Rebuild**: `./scripts/buildscript.sh`
2. **Run**: Boot the OS and move the mouse
3. **Collect logs**: Check `logs.txt` or serial output
4. **Analyze**: Look for patterns described above
5. **Report**: Share relevant log excerpts showing the issue

The logs will help identify exactly where the problem is occurring in the cursor rendering pipeline.
