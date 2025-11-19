module minimal_os.userland;

import minimal_os.console : print, printLine, printStageHeader, printStatusValue,
    printUnsigned;

nothrow:
@nogc:

private enum size_t MAX_USER_SERVICES = 12;
private enum size_t MAX_USER_PROCESSES = 32;
private enum size_t MAX_CAPABILITIES_PER_SERVICE = 8;
private enum size_t INVALID_INDEX = size_t.max;
private enum size_t INITIAL_PID = 2000;

private enum immutable(char)[] STATE_READY = "ready";
private enum immutable(char)[] STATE_RUNNING = "running";
private enum immutable(char)[] STATE_WAITING = "waiting";

struct UserService
{
    immutable(char)[] name;
    immutable(char)[] binary;
    immutable(char)[] summary;
    immutable(char)[][MAX_CAPABILITIES_PER_SERVICE] capabilities;
    size_t capabilityCount;
    bool optional;
}

struct UserProcess
{
    size_t pid;
    immutable(char)[] name;
    immutable(char)[] binary;
    immutable(char)[] summary;
    immutable(char)[] state;
    immutable(char)[][MAX_CAPABILITIES_PER_SERVICE] capabilities;
    size_t capabilityCount;
}

struct UserlandRuntime
{
public:
nothrow:
@nogc:
    void reset()
    {
        _serviceCount = 0;
        _processCount = 0;
        _nextPid = INITIAL_PID;
    }

    size_t registerService(immutable(char)[] name,
                           immutable(char)[] binary,
                           immutable(char)[] summary,
                           const scope immutable(char)[][] capabilities,
                           bool optional)
    {
        if (!hasCapacity(_serviceCount, _services.length))
        {
            return INVALID_INDEX;
        }

        size_t index = _serviceCount++;
        auto slot = &_services[index];
        slot.name = name;
        slot.binary = binary;
        slot.summary = summary;
        slot.optional = optional;
        slot.capabilityCount = copyCapabilities(slot.capabilities, capabilities);
        return index;
    }

    bool launchService(size_t serviceIndex, immutable(char)[] requestedState)
    {
        if (serviceIndex == INVALID_INDEX)
        {
            return false;
        }
        if (!hasCapacity(_processCount, _processes.length))
        {
            return false;
        }
        if (serviceIndex >= _serviceCount)
        {
            return false;
        }

        auto service = &_services[serviceIndex];
        auto process = &_processes[_processCount++];
        process.pid = _nextPid++;
        process.name = service.name;
        process.binary = service.binary;
        process.summary = service.summary;
        process.state = normaliseState(requestedState);
        process.capabilityCount = service.capabilityCount;
        foreach (i; 0 .. service.capabilityCount)
        {
            process.capabilities[i] = service.capabilities[i];
        }
        foreach (i; service.capabilityCount .. process.capabilities.length)
        {
            process.capabilities[i] = null;
        }
        return true;
    }

    bool updateProcessState(size_t pid, immutable(char)[] requestedState)
    {
        auto process = findProcess(pid);
        if (process is null)
        {
            return false;
        }
        process.state = normaliseState(requestedState);
        return true;
    }

    bool grantCapability(size_t pid, immutable(char)[] capability)
    {
        if (capability is null || capability.length == 0)
        {
            return false;
        }

        auto process = findProcess(pid);
        if (process is null)
        {
            return false;
        }

        foreach (i; 0 .. process.capabilityCount)
        {
            if (process.capabilities[i] == capability)
            {
                return true;
            }
        }

        if (!hasCapacity(process.capabilityCount, process.capabilities.length))
        {
            return false;
        }

        process.capabilities[process.capabilityCount] = capability;
        ++process.capabilityCount;
        return true;
    }

    bool hasCapability(size_t pid, immutable(char)[] capability) const
    {
        auto process = findProcessConst(pid);
        if (process is null)
        {
            return false;
        }

        foreach (i; 0 .. process.capabilityCount)
        {
            if (process.capabilities[i] == capability)
            {
                return true;
            }
        }
        return false;
    }

    @property size_t serviceCount() const
    {
        return _serviceCount;
    }

    @property size_t processCount() const
    {
        return _processCount;
    }

    @property const(UserService)[] services() const
    {
        return _services[0 .. _serviceCount];
    }

    @property const(UserProcess)[] processes() const
    {
        return _processes[0 .. _processCount];
    }

    size_t readyProcessCount() const
    {
        size_t count = 0;
        foreach (const ref process; _processes[0 .. _processCount])
        {
            if (isReadyState(process.state))
            {
                ++count;
            }
        }
        return count;
    }

private:
    static bool hasCapacity(size_t used, size_t capacity)
    {
        return used < capacity;
    }

    static size_t copyCapabilities(ref immutable(char)[][MAX_CAPABILITIES_PER_SERVICE] destination,
                                   const scope immutable(char)[][] source)
    {
        size_t count = 0;
        if (source !is null)
        {
            foreach (cap; source)
            {
                if (cap is null || cap.length == 0)
                {
                    continue;
                }
                if (!hasCapacity(count, destination.length))
                {
                    break;
                }
                destination[count] = cap;
                ++count;
            }
        }

        foreach (i; count .. destination.length)
        {
            destination[i] = null;
        }
        return count;
    }

    UserProcess* findProcess(size_t pid)
    {
        foreach (ref process; _processes[0 .. _processCount])
        {
            if (process.pid == pid)
            {
                return &process;
            }
        }
        return null;
    }

    const(UserProcess)* findProcessConst(size_t pid) const
    {
        foreach (const ref process; _processes[0 .. _processCount])
        {
            if (process.pid == pid)
            {
                return &process;
            }
        }
        return null;
    }

    UserService[MAX_USER_SERVICES] _services;
    UserProcess[MAX_USER_PROCESSES] _processes;
    size_t _serviceCount;
    size_t _processCount;
    size_t _nextPid;
}

private immutable(char)[] normaliseState(immutable(char)[] state)
{
    if (state is null || state.length == 0)
    {
        return STATE_READY;
    }
    return state;
}

private bool isReadyState(immutable(char)[] state)
{
    return state is null || state.length == 0 || state == STATE_READY || state == STATE_RUNNING;
}

private struct ServicePlan
{
    immutable(char)[] name;
    immutable(char)[] binary;
    immutable(char)[] summary;
    immutable(char)[][] capabilities;
    immutable(char)[] desiredState;
    bool optional;
}

private enum immutable(char)[][] INIT_CAPABILITIES =
    [ "ipc.bootstrap", "scheduler.control", "namespace.grant" ];
private enum immutable(char)[][] VFS_CAPABILITIES =
    [ "vmo.map", "vmo.clone", "namespace.publish", "namespace.read" ];
private enum immutable(char)[][] PKG_CAPABILITIES =
    [ "package.open", "package.verify", "cache.commit" ];
private enum immutable(char)[][] NET_CAPABILITIES =
    [ "net.bind", "net.connect", "net.capability" ];
private enum immutable(char)[][] SHELL_CAPABILITIES =
    [ "ipc.bootstrap", "posix.exec", "console.claim" ];

private immutable ServicePlan[] DEFAULT_SERVICE_PLANS =
    [ ServicePlan("init", "/sbin/init", "Capability supervisor",
                  INIT_CAPABILITIES, STATE_RUNNING, false),
      ServicePlan("vfsd", "/bin/vfsd", "Immutable namespace + VMO store",
                  VFS_CAPABILITIES, STATE_RUNNING, false),
      ServicePlan("pkgd", "/bin/pkgd", "Package + manifest resolver",
                  PKG_CAPABILITIES, STATE_READY, false),
      ServicePlan("netd", "/bin/netd", "Network capability broker",
                  NET_CAPABILITIES, STATE_WAITING, true),
      ServicePlan("lfe-sh", "/bin/sh", "Interactive shell bridge",
                  SHELL_CAPABILITIES, STATE_READY, false) ];

void bootUserland()
{
    printStageHeader("Provision userland services");

    UserlandRuntime runtime;
    runtime.reset();

    foreach (plan; DEFAULT_SERVICE_PLANS)
    {
        immutable(char)[] desiredState = normaliseState(plan.desiredState);
        const size_t serviceIndex = runtime.registerService(plan.name,
                                                            plan.binary,
                                                            plan.summary,
                                                            plan.capabilities,
                                                            plan.optional);
        const bool registered = serviceIndex != INVALID_INDEX;
        const bool launched = registered ? runtime.launchService(serviceIndex, desiredState) : false;
        logServiceProvision(plan, desiredState, registered, launched);
    }

    logUserlandSnapshot(runtime);
}

private void logServiceProvision(const scope ServicePlan plan,
                                 immutable(char)[] desiredState,
                                 bool registered,
                                 bool launched)
{
    print("[userland] ");
    print(plan.name);
    if (plan.optional)
    {
        print(" (optional)");
    }
    print(" : ");

    if (!registered)
    {
        printLine("registry full");
        return;
    }

    if (!launched)
    {
        printLine("launch failed");
        return;
    }

    printLine(desiredState);
}

private void logUserlandSnapshot(const scope ref UserlandRuntime runtime)
{
    printStatusValue("[userland] Registered services : ", cast(long)runtime.serviceCount);
    printStatusValue("[userland] Active processes     : ", cast(long)runtime.processCount);
    printStatusValue("[userland] Ready queue depth    : ", cast(long)runtime.readyProcessCount());

    if (runtime.processCount == 0)
    {
        printLine("[userland] No user processes scheduled.");
        return;
    }

    foreach (process; runtime.processes())
    {
        printProcessDetails(process);
    }
}

private void printProcessDetails(const scope UserProcess process)
{
    print("[userland] pid ");
    printUnsigned(process.pid);
    print("  ");
    print(process.name);
    print(" -> ");
    printLine(process.state);

    print("           binary        : ");
    if (process.binary is null || process.binary.length == 0)
    {
        printLine("<unspecified>");
    }
    else
    {
        printLine(process.binary);
    }

    print("           summary       : ");
    if (process.summary is null || process.summary.length == 0)
    {
        printLine("<none>");
    }
    else
    {
        printLine(process.summary);
    }

    print("           capabilities  : ");
    if (process.capabilityCount == 0)
    {
        printLine("<none>");
        return;
    }

    foreach (i; 0 .. process.capabilityCount)
    {
        print(process.capabilities[i]);
        if (i + 1 < process.capabilityCount)
        {
            print(", ");
        }
    }
    printLine("");
}

unittest
{
    UserlandRuntime runtime;
    runtime.reset();

    immutable(char)[][] caps = ["ipc.bootstrap", "vmo.clone"];
    auto index = runtime.registerService("init", "/sbin/init", "supervisor", caps, false);
    assert(index != INVALID_INDEX);
    assert(runtime.serviceCount == 1);
    assert(runtime.services()[0].capabilityCount == 2);

    assert(runtime.launchService(index, STATE_RUNNING));
    assert(runtime.processCount == 1);
    auto pid = runtime.processes()[0].pid;
    assert(runtime.readyProcessCount() == 1);

    assert(runtime.updateProcessState(pid, STATE_WAITING));
    assert(runtime.readyProcessCount() == 0);

    assert(runtime.grantCapability(pid, "debug.inspect"));
    assert(runtime.hasCapability(pid, "debug.inspect"));
    assert(!runtime.grantCapability(pid, ""));
}
