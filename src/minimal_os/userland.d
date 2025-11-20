module minimal_os.userland;

import minimal_os.console : print, printLine, printStageHeader, printStatusValue,
    printUnsigned, putChar;

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

private struct SystemProperties
{
    bool multithreadingEnabled = true;
    bool multiprocessingEnabled = true;
    bool desktopReady;
}

private enum immutable(char)[] DESKTOP_TITLE = "aurora.rice";
private enum immutable(char)[] DESKTOP_THEME = "violet glass";
private enum immutable(char)[] DESKTOP_WALLPAPER_NAME = "userland_wallpaper.txt";
private enum size_t DESKTOP_PANEL_WIDTH = 66;
private enum immutable(char)[] DESKTOP_WALLPAPER = import("userland_wallpaper.txt");

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
private enum immutable(char)[][] XORG_CAPABILITIES =
    [ "display.x11", "display.driver", "input.bridge", "namespace.publish" ];
private enum immutable(char)[][] XINIT_CAPABILITIES =
    [ "display.x11", "session.launch", "ipc.userland", "posix.exec" ];
private enum immutable(char)[][] DM_CAPABILITIES =
    [ "display.login", "session.control", "ipc.userland" ];
private enum immutable(char)[][] I3_CAPABILITIES =
    [ "display.manage", "ipc.userland", "workspace.control", "console.claim" ];

private immutable ServicePlan[] DEFAULT_SERVICE_PLANS =
    [ ServicePlan("init", "/sbin/init", "Capability supervisor",
                  INIT_CAPABILITIES, STATE_RUNNING, false),
      ServicePlan("vfsd", "/bin/vfsd", "Immutable namespace + VMO store",
                  VFS_CAPABILITIES, STATE_RUNNING, false),
      ServicePlan("pkgd", "/bin/pkgd", "Package + manifest resolver",
                  PKG_CAPABILITIES, STATE_READY, false),
      ServicePlan("netd", "/bin/netd", "Network capability broker",
                  NET_CAPABILITIES, STATE_RUNNING, true),
      ServicePlan("xorg-server", "/bin/Xorg", "X11 display server",
                  XORG_CAPABILITIES, STATE_RUNNING, false),
      ServicePlan("xinit", "/bin/xinit", "X11 session bootstrapper",
                  XINIT_CAPABILITIES, STATE_RUNNING, false),
      ServicePlan("display-manager", "/bin/xdm", "Graphical login + session manager",
                  DM_CAPABILITIES, STATE_RUNNING, false),
      ServicePlan("i3", "/bin/i3", "Tiling window manager and desktop",
                  I3_CAPABILITIES, STATE_RUNNING, false),
      ServicePlan("lfe-sh", "/bin/sh", "Interactive shell bridge",
                  SHELL_CAPABILITIES, STATE_READY, false) ];

@nogc nothrow void bootUserland()
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

    SystemProperties systemProperties;
    immutable(char)[][] desktopStack =
        [ "xorg-server", "xinit", "display-manager", "i3" ];

    systemProperties.desktopReady = true;
    foreach (service; desktopStack)
    {
        if (!processReady(runtime, service))
        {
            systemProperties.desktopReady = false;
            break;
        }
    }

    logUserlandSnapshot(runtime, systemProperties);
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

private bool processReady(const scope ref UserlandRuntime runtime, immutable(char)[] name)
{
    foreach (process; runtime.processes())
    {
        if (process.name == name && isReadyState(process.state))
        {
            return true;
        }
    }
    return false;
}

private void logUserlandSnapshot(const scope ref UserlandRuntime runtime,
                                 const scope SystemProperties properties)
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

    renderRicedDesktop(runtime, properties);
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

private void renderRicedDesktop(const scope ref UserlandRuntime runtime,
                                const scope SystemProperties properties)
{
    printLine("");
    printLine("[userland] booting aurora.rice desktop...");

    printFrameLine('+', '-', '+');
    printPanelLine(DESKTOP_TITLE);
    printPanelKeyValue("theme", DESKTOP_THEME);
    printPanelKeyValue("wallpaper", DESKTOP_WALLPAPER_NAME);
    printPanelKeyValue("multithreading", properties.multithreadingEnabled ? "enabled" : "disabled");
    printPanelKeyValue("multiprocessing", properties.multiprocessingEnabled ? "enabled" : "disabled");
    printPanelKeyValue("desktop ready", properties.desktopReady ? "yes" : "no");
    printPanelMetric("services", runtime.serviceCount);
    printPanelMetric("processes", runtime.processCount);
    printPanelMetric("ready queue", runtime.readyProcessCount());
    printSectionDivider();
    printPanelLine("wallpaper preview");
    renderWallpaperPane();
    printSectionDivider();
    printPanelLine("process dock");
    renderProcessDock(runtime);
    printFrameLine('+', '-', '+');
}

private void renderWallpaperPane()
{
    size_t lineStart = 0;
    for (size_t index = 0; index < DESKTOP_WALLPAPER.length; ++index)
    {
        if (DESKTOP_WALLPAPER[index] == '\n')
        {
            renderWallpaperLine(DESKTOP_WALLPAPER[lineStart .. index]);
            lineStart = index + 1;
        }
    }

    if (lineStart < DESKTOP_WALLPAPER.length)
    {
        renderWallpaperLine(DESKTOP_WALLPAPER[lineStart .. $]);
    }
}

private void renderWallpaperLine(const(char)[] line)
{
    print("| ");
    size_t used = printLimited(line, DESKTOP_PANEL_WIDTH);
    padPanel(used);
    printLine(" |");
}

private void renderProcessDock(const scope ref UserlandRuntime runtime)
{
    if (runtime.processCount == 0)
    {
        printPanelLine("no user processes scheduled");
        return;
    }

    foreach (process; runtime.processes())
    {
        printProcessDockLine(process);
    }
}

private void printProcessDockLine(const scope UserProcess process)
{
    immutable(char)[] binary = process.binary;
    immutable(char)[] summary = process.summary;

    if (binary is null || binary.length == 0)
    {
        binary = "<unspecified binary>";
    }

    if (summary is null || summary.length == 0)
    {
        summary = "no summary provided";
    }

    print("| ");
    size_t used = 0;
    used += printLimited("pid ", DESKTOP_PANEL_WIDTH);
    used += printUnsignedWithCount(process.pid);
    if (used < DESKTOP_PANEL_WIDTH)
    {
        used += printLimited(" - ", DESKTOP_PANEL_WIDTH - used);
    }
    used += printLimited(process.name, DESKTOP_PANEL_WIDTH - used);
    if (used < DESKTOP_PANEL_WIDTH)
    {
        used += printLimited("  [", DESKTOP_PANEL_WIDTH - used);
        used += printLimited(process.state, DESKTOP_PANEL_WIDTH - used);
        used += printLimited("]", DESKTOP_PANEL_WIDTH - used);
    }
    padPanel(used);
    printLine(" |");

    print("| ");
    size_t infoUsed = 0;
    infoUsed += printLimited("binary: ", DESKTOP_PANEL_WIDTH);
    infoUsed += printLimited(binary, DESKTOP_PANEL_WIDTH - infoUsed);
    if (infoUsed < DESKTOP_PANEL_WIDTH)
    {
        infoUsed += printLimited(" - ", DESKTOP_PANEL_WIDTH - infoUsed);
    }
    infoUsed += printLimited(summary, DESKTOP_PANEL_WIDTH - infoUsed);
    padPanel(infoUsed);
    printLine(" |");
}

private void printPanelLine(const(char)[] text)
{
    print("| ");
    size_t used = printLimited(text, DESKTOP_PANEL_WIDTH);
    padPanel(used);
    printLine(" |");
}

private void printPanelKeyValue(immutable(char)[] key, immutable(char)[] value)
{
    print("| ");
    size_t used = 0;
    used += printLimited(key, DESKTOP_PANEL_WIDTH);
    if (used < DESKTOP_PANEL_WIDTH)
    {
        used += printLimited(" : ", DESKTOP_PANEL_WIDTH - used);
    }
    used += printLimited(value, DESKTOP_PANEL_WIDTH - used);
    padPanel(used);
    printLine(" |");
}

private void printPanelMetric(immutable(char)[] key, size_t value)
{
    print("| ");
    size_t used = 0;
    used += printLimited(key, DESKTOP_PANEL_WIDTH);
    if (used < DESKTOP_PANEL_WIDTH)
    {
        used += printLimited(" : ", DESKTOP_PANEL_WIDTH - used);
    }
    used += printUnsignedWithCount(value);
    padPanel(used);
    printLine(" |");
}

private void printSectionDivider()
{
    printFrameLine('+', '-', '+');
}

private void printFrameLine(char start, char fill, char end)
{
    putChar(start);
    foreach (i; 0 .. DESKTOP_PANEL_WIDTH + 2)
    {
        putChar(fill);
    }
    putChar(end);
    putChar('\n');
}

private size_t printLimited(const(char)[] text, size_t maxChars)
{
    size_t printed = 0;
    if (text is null)
    {
        return printed;
    }

    foreach (index; 0 .. text.length)
    {
        if (printed >= maxChars)
        {
            break;
        }
        putChar(text[index]);
        ++printed;
    }
    return printed;
}

private void padPanel(size_t used)
{
    while (used < DESKTOP_PANEL_WIDTH)
    {
        putChar(' ');
        ++used;
    }
}

private size_t printUnsignedWithCount(size_t value)
{
    const size_t digits = countDigits(value);
    printUnsigned(value);
    return digits;
}

private size_t countDigits(size_t value)
{
    size_t digits = 1;
    while (value >= 10)
    {
        value /= 10;
        ++digits;
    }
    return digits;
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
