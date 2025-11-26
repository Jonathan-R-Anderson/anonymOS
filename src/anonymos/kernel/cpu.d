module anonymos.kernel.cpu;

// The canonical Proc type is defined in anonymos.posix; declare the shape we need here.
import anonymos.syscalls.posix : pid_t;

struct Proc
{
    pid_t     pid;
    pid_t     ppid;
    ubyte     state;
}

@nogc nothrow:

/// Maximum CPUs supported by this build.
private enum size_t MAX_CPUS = 4;

/// Minimal per-CPU state used by the scheduler and timer paths.
struct CPUState
{
    size_t id;
    bool   online;
    Proc*  current;
    ulong  ticks;
}

__gshared CPUState[MAX_CPUS] g_cpus;
__gshared size_t g_cpuCount = 1; // single-CPU bring-up for now

/// Return a reference to the current CPU's state. Single-CPU for now.
ref CPUState cpuCurrent() @nogc nothrow
{
    return g_cpus[0];
}

/// Initialize CPU bookkeeping for the bootstrap processor.
void initializeCPUState() @nogc nothrow
{
    foreach (i; 0 .. MAX_CPUS)
    {
        g_cpus[i] = CPUState.init;
        g_cpus[i].id = i;
    }
    g_cpuCount = 1;
    g_cpus[0].online = true;
}
