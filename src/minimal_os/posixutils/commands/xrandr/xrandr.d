module xrandr;

import std.algorithm : filter;
import std.array : empty;
import std.format : format;
import std.range : walkLength;
import std.stdio : stderr, writeln, writefln;

private enum string stubNote =
    "This build ships a mock xrandr implementation. It reports a static\n" ~
    "virtual display layout so scripts can query geometry, but it cannot\n" ~
    "apply configuration changes because no real X11/Wayland backend is\n" ~
    "available.";

private struct Mode
{
    string label;
    int width;
    int height;
    double refreshHz;
    bool preferred;
    bool current;
}

private struct Output
{
    string name;
    bool connected;
    bool primary;
    int posX;
    int posY;
    int physWidthMm;
    int physHeightMm;
    Mode[] modes;

    const(Mode)* currentMode() const
    {
        foreach (ref mode; modes)
        {
            if (mode.current)
            {
                return &mode;
            }
        }
        return modes.empty ? null : &modes[0];
    }
}

private immutable Mode[] defaultModes = [
    Mode("1920x1080", 1920, 1080, 60.00, true, true),
    Mode("1600x900", 1600, 900, 60.00, false, false),
    Mode("1366x768", 1366, 768, 60.00, false, false),
    Mode("1280x720", 1280, 720, 60.00, false, false),
    Mode("1024x768", 1024, 768, 60.00, false, false),
];

private immutable Output[] outputs = [
    Output("Virtual-1", true, true, 0, 0, 510, 287, defaultModes.dup),
    Output("Virtual-2", false, false, 1920, 0, 0, 0, defaultModes[1 .. 2].dup),
];

private struct Options
{
    bool showHelp;
    bool showVersion;
    bool verbose;
    bool listMonitors;
    bool listActiveMonitors;
    bool listProviders;
    bool configRequested;
}

private bool isQueryOnlyFlag(string arg)
{
    return arg == "-q" || arg == "--query" || arg == "--current" || arg == "--nograb" ||
        arg == "--verbose" || arg == "--prop" || arg == "--properties" || arg == "--dryrun";
}

private Options parseOptions(string[] args)
{
    Options opts;
    foreach (arg; args[1 .. $])
    {
        final switch (arg)
        {
        case "--help", "-h":
            opts.showHelp = true;
            break;
        case "--version", "-V":
            opts.showVersion = true;
            break;
        case "--verbose":
        case "--prop":
        case "--properties":
            opts.verbose = true;
            break;
        case "--listmonitors":
            opts.listMonitors = true;
            break;
        case "--listactivemonitors":
            opts.listActiveMonitors = true;
            break;
        case "--listproviders":
            opts.listProviders = true;
            break;
        default:
            if (arg.length && arg[0] == '-')
            {
                if (!isQueryOnlyFlag(arg))
                {
                    opts.configRequested = true;
                }
            }
            else
            {
                // Positional arguments imply a configuration request.
                opts.configRequested = true;
            }
            break;
        }
    }
    return opts;
}

private void printUsage()
{
    writeln("Usage: xrandr [options]");
    writeln("A read-only mock that reports a static virtual display layout.");
    writeln("\nOptions:");
    writeln("  -h, --help               Show this help text");
    writeln("  -V, --version            Show the mock xrandr version");
    writeln("      --listmonitors       List all monitors (connected and disconnected)");
    writeln("      --listactivemonitors List only active monitors");
    writeln("      --listproviders      Show display providers");
    writeln("      --verbose            Include per-mode detail in query output");
    writeln("  Other flags that would modify configuration are not supported.");
}

private void printVersion()
{
    writeln("xrandr (mock) 1.0");
    writeln("Based on a static virtual screen; configuration changes are disabled.");
}

private void printModeLine(const Mode mode, bool verbose)
{
    string marks;
    if (mode.current) marks ~= "*";
    if (mode.preferred) marks ~= "+";

    if (verbose)
    {
        writefln("   %sx%s %7.2f%s", mode.width, mode.height, mode.refreshHz, marks);
        writeln("        h: width  " ~ format("%d", mode.width) ~ "  start  0  end  0 total 0");
        writeln("        v: height " ~ format("%d", mode.height) ~ "  start  0  end  0 total 0");
    }
    else
    {
        writefln("   %sx%s %7.2f%s", mode.width, mode.height, mode.refreshHz, marks);
    }
}

private void printQuery(bool verbose)
{
    enum minWidth = 320, minHeight = 200;
    enum maxWidth = 8192, maxHeight = 8192;

    const current = outputs[0].currentMode();
    writefln("Screen 0: minimum %s x %s, current %s x %s, maximum %s x %s",
        minWidth, minHeight,
        current is null ? 0 : current.width,
        current is null ? 0 : current.height,
        maxWidth, maxHeight);

    foreach (outp; outputs)
    {
        if (!outp.connected)
        {
            writeln(outp.name ~ " disconnected");
            continue;
        }

        auto mode = outp.currentMode();
        string primaryMark = outp.primary ? " primary" : "";
        string modeInfo = mode is null ? "0x0" : format("%dx%d", mode.width, mode.height);
        writefln("%s connected%s %s+%s+%s %s",
            outp.name,
            primaryMark,
            modeInfo,
            outp.posX,
            outp.posY,
            "normal (normal left inverted right x axis y axis)");

        foreach (mode; outp.modes)
        {
            printModeLine(mode, verbose);
        }
    }
}

private void printMonitors(bool activeOnly)
{
    auto connected = outputs.filter!(o => o.connected);
    size_t count = activeOnly ? connected.walkLength : outputs.walkLength;
    writefln("Monitors: %s", count);

    size_t idx = 0;
    foreach (outp; outputs)
    {
        if (activeOnly && !outp.connected)
        {
            continue;
        }

        auto mode = outp.currentMode();
        string prefix = outp.primary ? "+*" : "+";
        string geometry = mode is null ? "0x0" : format("%s/%sx%s/%s+%s+%s",
            mode.width, outp.physWidthMm,
            mode.height, outp.physHeightMm,
            outp.posX, outp.posY);

        writefln(" %s: %s%s %s  %s", idx, prefix, outp.name, geometry, outp.name);
        idx++;
    }
}

private void printProviders()
{
    writeln("Providers: number : 1");
    writeln("Provider 0: id: 0x0 cap: 0x1 name: VirtualStub");
    writeln("    CRTC count: 1, output count: 1");
    writeln("    associated providers: none");
    writeln("    name: VirtualStub");
}

private int handleConfigRequest()
{
    stderr.writeln("xrandr: configuration changes are not supported in this environment.");
    stderr.writeln(stubNote);
    return 1;
}

int main(string[] args)
{
    const opts = parseOptions(args);

    if (opts.showHelp)
    {
        printUsage();
        return 0;
    }
    if (opts.showVersion)
    {
        printVersion();
        return 0;
    }
    if (opts.configRequested)
    {
        return handleConfigRequest();
    }

    bool emitted = false;
    if (opts.listProviders)
    {
        printProviders();
        emitted = true;
    }
    if (opts.listMonitors)
    {
        printMonitors(false);
        emitted = true;
    }
    if (opts.listActiveMonitors)
    {
        printMonitors(true);
        emitted = true;
    }

    if (!emitted)
    {
        printQuery(opts.verbose);
    }

    return 0;
}
