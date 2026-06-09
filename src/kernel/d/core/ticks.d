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

// Read the current monotonic tick count without advancing it.  Used by timerfd
// to compute expiries.  R2: return the clean PIT-only ms (same real clock as
// clock_gettime), NOT g_tickCount which getTickCount() inflates on every read —
// so timerfd timers and clock_gettime agree (Weston's frame pacing depends on it).
ulong get_ticks()
{
    return g_pitMs;
}
