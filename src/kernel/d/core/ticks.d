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

// ---------------------------------------------------------------------------
// TSC-derived milliseconds, for metering work that itself suppresses interrupts.
//
// g_pitMs above only advances when the PIT IRQ is delivered, and a long stretch of
// interrupt-off kernel work (the disk installer's crypt-and-write batches are the case
// this exists for) simply loses those ticks -- under QEMU the counter can stall almost
// completely while the BSP is busy.  Anything that measures "how much of the last 100 ms
// did I spend" with pitMs therefore measures the wrong thing in exactly the situation it
// matters: the clock stops during the work being charged for.
//
// The TSC keeps counting regardless.  Calibrate it against the PIT over an interval where
// the PIT IS reliable (an idle stretch early in boot), then read milliseconds from it.
// Falls back to pitMs until a calibration lands, so callers need no special case.
private __gshared ulong g_tscPerMs = 0;   // 0 == not calibrated yet
private __gshared ulong g_tscBase  = 0;   // TSC at calibration
private __gshared ulong g_tscBaseMs = 0;  // pitMs at calibration, so the two clocks agree

private ulong rdtscRaw() {
    uint lo, hi;
    asm @nogc nothrow { rdtsc; mov lo, EAX; mov hi, EDX; }
    return (cast(ulong)hi << 32) | lo;
}

// Take one calibration sample against the PIT and keep the BEST (lowest) cycles-per-ms seen.
//
// The PIT is the only other clock here, and it is exactly the clock we distrust -- but its error
// has a known sign.  A lost IRQ0 tick makes g_pitMs advance less than real time, which inflates
// dTsc/dMs; the PIT never runs fast.  So the minimum ratio observed across many windows converges
// on the true TSC rate from above, and one bad window can no longer poison the result.  (A single
// window taken during boot read 19.9 GHz on a ~4 GHz host, which is what this replaces.)
//
// Windows must be long enough that PIT quantisation is noise, and calibration keeps refining for
// the life of the system rather than latching an early guess.
private enum ulong CAL_WINDOW_MS = 250;
bool tscCalibrate(ulong tscStart, ulong pitStart) {
    const ulong nowPit = g_pitMs;
    if (nowPit <= pitStart) return false;
    const ulong dMs = nowPit - pitStart;
    if (dMs < CAL_WINDOW_MS) return false;                  // too short: quantisation dominates
    const ulong dTsc = rdtscRaw() - tscStart;
    const ulong perMs = dTsc / dMs;
    if (perMs < 100_000 || perMs > 10_000_000) return false;  // 100 MHz .. 10 GHz sanity band
    if (g_tscPerMs != 0 && perMs >= g_tscPerMs) return false;  // not an improvement
    // Re-anchor on the CURRENT tscMs reading, not on pitMs: a better ratio must change the clock's
    // rate, never its value.  Anchoring to pitMs would step tscMs backwards by however far the PIT
    // has fallen behind, and every consumer here measures elapsed time as an unsigned subtraction --
    // one backward step would read as ~1.8e19 ms and fire every watchdog at once.
    const ulong keep = (g_tscPerMs == 0) ? nowPit : tscMs();
    g_tscPerMs = perMs;
    g_tscBase = rdtscRaw();
    g_tscBaseMs = keep;
    return true;
}

bool tscCalibrated() { return g_tscPerMs != 0; }
ulong tscHz() { return g_tscPerMs * 1000; }

// Milliseconds on the same scale as pitMs(), but counted from the TSC so they keep
// advancing through interrupt-off work.  Before calibration this IS pitMs().
ulong tscMs() {
    if (g_tscPerMs == 0) return g_pitMs;
    return g_tscBaseMs + (rdtscRaw() - g_tscBase) / g_tscPerMs;
}
