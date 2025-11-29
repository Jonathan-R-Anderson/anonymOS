# Debug Output Toggle

## Overview

The system has multiple debug logging controls to prevent verbose output from cluttering the screen while still maintaining logs for debugging.

## Debug Controls

### 1. **Screen Debug Logging** (Runtime Toggle)
- **Location**: `src/anonymos/console.d`
- **Default**: `false` (disabled)
- **Control Functions**:
  - `setDebugLoggingEnabled(bool enabled)` - Enable/disable debug output to screen
  - `debugLoggingEnabled()` - Check current state
  - `printDebugLine(text)` - Print only if debug logging is enabled (always goes to serial)

### 2. **Timer/IRQ Debug** (Compile-time)
- **Location**: `src/anonymos/kernel/interrupts.d`
- **Status**: Now uses `printDebugLine()` so it respects the runtime toggle
- **Messages**:
  - `[irq] timer ISR entered` - Every 16th timer interrupt
  - `[irq] timer tick preempt` - When scheduler preempts

### 3. **POSIX/Scheduler Debug** (Compile-time)
- **Location**: `src/anonymos/syscalls/posix.d`
- **Control**: `ENABLE_POSIX_DEBUG` constant
- **Messages**:
  - `schedYield: reentrant call ignored`
  - `schedYield: call #N`
  - `schedYield: no other ready processes, staying on current`
  - Context switch details

### 4. **Framebuffer Console** (Runtime Toggle)
- **Location**: `src/anonymos/console.d`
- **Default**: `true` (enabled during boot, disabled when GUI starts)
- **Control**: `setFramebufferConsoleEnabled(bool enabled)`
- **Purpose**: Prevents kernel logs from corrupting the GUI

## Current Behavior

1. **Boot Phase**: All logs go to screen and serial
2. **GUI Phase**: 
   - Framebuffer console is disabled (logs only to serial)
   - Debug logging is disabled by default (timer/IRQ messages only to serial)
   - POSIX debug still prints if `ENABLE_POSIX_DEBUG` is true

## To Completely Silence Screen Output

### Option 1: Disable POSIX Debug (Recommended)
Find and set in `src/anonymos/syscalls/posix.d`:
```d
private enum bool ENABLE_POSIX_DEBUG = false;  // Change from true to false
```

### Option 2: Use printDebugLine for POSIX Messages
Replace `printLine` with `printDebugLine` in the POSIX debug blocks, then control at runtime with `setDebugLoggingEnabled(false)`.

## Summary

- ✅ Timer/IRQ debug: **Fixed** - uses `printDebugLine()`, off by default
- ⚠️  POSIX debug: **Still active** - controlled by `ENABLE_POSIX_DEBUG` compile-time flag
- ✅ Framebuffer console: **Disabled during GUI** - prevents screen corruption

The system now boots to the installer GUI without timer interrupts scrolling on screen. The remaining POSIX debug messages can be disabled by setting `ENABLE_POSIX_DEBUG = false` in `posix.d`.
