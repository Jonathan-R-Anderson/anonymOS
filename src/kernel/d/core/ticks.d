module core.ticks;

@nogc nothrow:

enum ubyte PIC1_DEFAULT_MASK = 0xF8;
enum ubyte PIC2_DEFAULT_MASK = 0xFF;

private __gshared ulong g_tickCount;

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
}

// Read the current monotonic tick count without advancing it.  Used by timerfd
// to compute expiries.
ulong get_ticks()
{
    return g_tickCount;
}
