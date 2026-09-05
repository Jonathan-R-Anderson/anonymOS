module core.ticks;

@nogc nothrow:

enum ubyte PIC1_DEFAULT_MASK = 0xF8;
enum ubyte PIC2_DEFAULT_MASK = 0xFF;

private __gshared ulong g_tickCount;

// Clean wall-clock millisecond counter advanced ONLY by the PIT IRQ (1000 Hz), so
// it is not polluted by getTickCount()'s read-time increments — used for profiling.
private __gshared ulong g_pitMs;
ulong pitMs() { return g_pitMs; }

// Legacy reader that advances the counter on each call.  Kept for existing
// callers (e.g. clock_gettime) that relied on this behaviour before a real
// PIT tick existed.
ulong getTickCount()
{
    return ++g_tickCount;
}

// Advance the monotonic tick counter by one.  Called from the PIT IRQ0 handler
// at ~1000 Hz, so one tick ≈ 1 ms.
void increment_ticks()
{
    ++g_tickCount;
    ++g_pitMs;
}

// CPU time split, sampled at the 1000 Hz PIT tick: was the interrupted task the idle task or a
// real one?  /proc/stat previously served a constant "cpu  0 0 0 0 0 0 0 0 0 0", so every monitor
// computing a busy percentage from successive deltas saw no movement at all and reported 0%.
//
// Kept here rather than in the scheduler because this is the only 1000 Hz sampling point, and the
// counters must advance on the same clock as g_pitMs for a jiffy delta to mean anything.
private __gshared ulong g_jiffiesIdle;
private __gshared ulong g_jiffiesBusy;
void cpuAccountTick(bool onIdleTask)
{
    if (onIdleTask) ++g_jiffiesIdle; else ++g_jiffiesBusy;
}
ulong cpuIdleJiffies() { return g_jiffiesIdle; }
ulong cpuBusyJiffies() { return g_jiffiesBusy; }

// Read the current monotonic tick count without advancing it.  Used by timerfd
// to compute expiries.  R2: return the clean PIT-only ms (same real clock as
// clock_gettime), NOT g_tickCount which getTickCount() inflates on every read —
// so timerfd timers and clock_gettime agree (Weston's frame pacing depends on it).
ulong get_ticks()
{
    return g_pitMs;
}
