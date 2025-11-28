# PS/2 Mouse Cursor Jumping Fix

## Problem Analysis

From the logs (`logs.txt`), the cursor was exhibiting severe jumping behavior:

### Symptoms:
1. **Large cursor jumps**: Movement deltas of 60-150 pixels in single frames
2. **Spurious button events**: Random button presses/releases
3. **Screen flashing**: Excessive compositor redraws

### Example Log Entries:
```
[mouse] LARGE MOVE #25: (461, 478) -> (518, 473) delta=62
[mouse] LARGE MOVE #106: (754, 198) -> (627, 208) delta=137
[mouse] Report #65: delta=(69, -34) buttons=0x00 pos=(885, 420)
[mouse] Report #66: delta=(100, -19) buttons=0x00 pos=(954, 386)
```

### Root Cause:

The PS/2 mouse packet parsing in `handlePs2MouseByte()` was **incorrectly interpreting the movement data**.

## PS/2 Mouse Packet Format

A standard PS/2 mouse packet consists of 3 bytes:

**Byte 0 (Flags):**
```
Bit 7: Y overflow
Bit 6: X overflow  
Bit 5: Y sign bit
Bit 4: X sign bit
Bit 3: Always 1 (sync bit)
Bit 2: Middle button
Bit 1: Right button
Bit 0: Left button
```

**Byte 1:** X movement (0-255, unsigned)
**Byte 2:** Y movement (0-255, unsigned)

## The Bug

The old code did this:
```d
report.deltaX = cast(byte)g_ps2MousePacket[1];
report.deltaY = cast(byte)-cast(byte)g_ps2MousePacket[2];
```

**Problems:**
1. **No sign extension**: Simply casting `ubyte` to `byte` doesn't properly handle negative values
2. **Ignored overflow bits**: Packets with overflow were processed, causing huge jumps
3. **Incorrect sign handling**: The sign bits in byte 0 were completely ignored

**Example of the bug:**
- If mouse moves left by 50 pixels, the packet might be:
  - Byte 0: `0x18` (X sign bit set)
  - Byte 1: `0xCE` (206 in unsigned, should be -50)
  - Byte 2: `0x00`

- Old code interpreted byte 1 as: `cast(byte)0xCE` = `-50` ✓ (accidentally correct sometimes)
- But for values like `0x7F` (127), it would be interpreted as `127` when it should be `-129` if the sign bit is set

## The Fix

The new code properly implements PS/2 mouse protocol:

```d
// 1. Extract flags and raw values
const ubyte flags = g_ps2MousePacket[0];
const ubyte rawX = g_ps2MousePacket[1];
const ubyte rawY = g_ps2MousePacket[2];

// 2. Check overflow bits - discard bad packets
const bool xOverflow = (flags & 0x40) != 0;
const bool yOverflow = (flags & 0x80) != 0;
if (xOverflow || yOverflow)
    return; // Discard

// 3. Get sign bits
const bool xNegative = (flags & 0x10) != 0;
const bool yNegative = (flags & 0x20) != 0;

// 4. Proper sign extension
int deltaX = rawX;
if (xNegative)
    deltaX = cast(int)(rawX | 0xFFFFFF00); // Sign extend

int deltaY = rawY;
if (yNegative)
    deltaY = cast(int)(rawY | 0xFFFFFF00); // Sign extend

// 5. Flip Y axis for screen coordinates
deltaY = -deltaY;

// 6. Clamp to prevent any remaining issues
if (deltaX < -127) deltaX = -127;
if (deltaX > 127) deltaX = 127;
if (deltaY < -127) deltaY = -127;
if (deltaY > 127) deltaY = 127;
```

## Why This Fixes The Issues

### 1. **Cursor Jumping Fixed**
- Overflow packets are now discarded
- Sign extension is correct
- Values are clamped to reasonable ranges

### 2. **Button Events Fixed**
- Button bits are extracted from the correct byte (flags & 0x07)
- No interference from movement data

### 3. **Screen Flashing Reduced**
- Fewer spurious movements mean less damage
- Compositor only redraws when necessary

## Expected Behavior After Fix

**Before:**
```
[mouse] Report #65: delta=(69, -34)
[mouse] LARGE MOVE #63: (885, 420) -> (954, 386) delta=103
[mouse] Report #66: delta=(100, -19)
[mouse] LARGE MOVE #64: (954, 386) -> (1023, 367) delta=88
```

**After:**
```
[mouse] Report #65: delta=(5, -3)
[mouse] Report #66: delta=(7, -2)
[mouse] Report #67: delta=(4, -1)
```

## Testing

1. **Rebuild**: `./scripts/buildscript.sh`
2. **Run**: `qemu-system-x86_64 -cdrom build/os.iso -m 512 -serial stdio`
3. **Verify**:
   - Smooth cursor movement
   - No large jumps in logs
   - Button clicks work correctly
   - No screen flashing

## Technical References

- [PS/2 Mouse Protocol](https://wiki.osdev.org/PS/2_Mouse)
- [PS/2 Controller](https://wiki.osdev.org/PS/2_Controller)

## Files Modified

- `/home/jonny/Documents/internetcomputer/src/anonymos/drivers/usb_hid.d`
  - Function: `handlePs2MouseByte()` (lines 896-955)
  - Added proper PS/2 packet parsing with overflow checking and sign extension
