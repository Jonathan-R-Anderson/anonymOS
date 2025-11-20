module xset;

import std.conv : to;
import std.format : format;
import std.algorithm.comparison : clamp;
import std.stdio : stderr, writeln, writefln;
import std.string : startsWith, strip;

private enum string stubNote =
    "This build runs without a graphical server. xset operates in mock\n" ~
    "mode, updating transient in-memory state so scripts can proceed, but\n" ~
    "no real display power or keyboard settings are changed.";

private struct XsetState
{
    bool preferBlanking = true;
    bool allowExposures = true;
    bool screensaverEnabled = true;
    int screensaverTimeout = 600;
    int screensaverCycle = 600;

    bool dpmsEnabled = true;
    int dpmsStandby = 1200;
    int dpmsSuspend = 1800;
    int dpmsOff = 2400;
    string dpmsLastAction = "On";

    bool bellEnabled = true;
    int bellPercent = 50;
    int bellPitch = 400;
    int bellDurationMs = 100;

    bool ledActive = false;
}

private int handleHelpAndVersion(string[] args)
{
    foreach (arg; args[1 .. $])
    {
        final switch (arg)
        {
        case "--version", "-V":
            writeln("xset (mock) 1.0");
            writeln("A headless-safe implementation with static defaults.");
            return 0;
        case "--help", "-h":
            writeln("Usage: xset [options] [settings]");
            writeln("A mock xset that accepts common DPMS, screen saver, bell, and LED flags.");
            writeln("\nExamples:");
            writeln("  xset q                Query the current mock state");
            writeln("  xset s off            Disable the screen saver");
            writeln("  xset -dpms            Disable DPMS");
            writeln("  xset b off            Silence the bell");
            writeln("\nAll settings are transient and do not touch real hardware.\n" ~ stubNote);
            return 0;
        default:
            break;
        }
    }
    return -1;
}

private int parseInt(string value, int defaultValue)
{
    try
    {
        return value.strip.to!int;
    }
    catch (Exception)
    {
        return defaultValue;
    }
}

private bool tryParseInt(string value, out int result)
{
    try
    {
        result = value.strip.to!int;
        return true;
    }
    catch (Exception)
    {
        result = 0;
        return false;
    }
}

private void handleScreensaver(ref XsetState state, string[] args, ref size_t i)
{
    if (i + 1 >= args.length)
    {
        return;
    }

    string next = args[i + 1];
    final switch (next)
    {
    case "on":
        state.screensaverEnabled = true;
        state.preferBlanking = true;
        i++;
        return;
    case "off":
        state.screensaverEnabled = false;
        i++;
        return;
    case "blank":
        state.preferBlanking = true;
        i++;
        return;
    case "noblank":
        state.preferBlanking = false;
        i++;
        return;
    case "expose":
        state.allowExposures = true;
        i++;
        return;
    case "noexpose":
        state.allowExposures = false;
        i++;
        return;
    default:
        break;
    }

    // Numeric forms: timeout [cycle]
    int timeout = parseInt(next, state.screensaverTimeout);
    if (timeout != state.screensaverTimeout || next == format("%s", timeout))
    {
        state.screensaverTimeout = clamp(timeout, 0, 86400);
        if (i + 2 < args.length)
        {
            int cycle = parseInt(args[i + 2], state.screensaverCycle);
            state.screensaverCycle = clamp(cycle, 0, 86400);
            i += 2;
        }
        else
        {
            i++;
        }
    }
}

private void handleDpms(ref XsetState state, string[] args, ref size_t i)
{
    if (i + 1 >= args.length)
    {
        return;
    }

    string next = args[i + 1];
    final switch (next)
    {
    case "force":
        if (i + 2 < args.length)
        {
            string mode = args[i + 2];
            state.dpmsLastAction = mode[0 .. $].length ? mode : "On";
            i += 2;
        }
        return;
    case "standby":
    case "suspend":
    case "off":
    case "on":
        state.dpmsLastAction = next[0 .. $].length ? next : "On";
        i++;
        return;
    case "enable":
        state.dpmsEnabled = true;
        i++;
        return;
    case "disable":
        state.dpmsEnabled = false;
        i++;
        return;
    default:
        break;
    }

    // Numeric timeout form: standby suspend off
    int standby;
    if (!tryParseInt(next, standby))
    {
        return;
    }

    int suspend = state.dpmsSuspend;
    int off = state.dpmsOff;
    bool haveSuspend = false;
    bool haveOff = false;

    if (i + 2 < args.length && tryParseInt(args[i + 2], suspend))
    {
        haveSuspend = true;
    }
    if (i + 3 < args.length && tryParseInt(args[i + 3], off))
    {
        haveOff = true;
    }

    state.dpmsStandby = clamp(standby, 0, 86400);
    if (haveSuspend)
    {
        state.dpmsSuspend = clamp(suspend, 0, 86400);
    }
    if (haveOff)
    {
        state.dpmsOff = clamp(off, 0, 86400);
    }

    if (haveOff)
    {
        i += 3;
    }
    else if (haveSuspend)
    {
        i += 2;
    }
    else
    {
        i++;
    }
}

private void handleBell(ref XsetState state, string[] args, ref size_t i)
{
    if (i + 1 >= args.length)
    {
        return;
    }

    string next = args[i + 1];
    final switch (next)
    {
    case "on":
        state.bellEnabled = true;
        i++;
        return;
    case "off":
        state.bellEnabled = false;
        i++;
        return;
    case "default":
        state.bellEnabled = true;
        state.bellPercent = 50;
        state.bellPitch = 400;
        state.bellDurationMs = 100;
        i++;
        return;
    default:
        break;
    }

    // Numeric forms: percent [pitch [duration]]
    int percent = parseInt(next, state.bellPercent);
    state.bellPercent = clamp(percent, 0, 100);
    if (i + 2 < args.length)
    {
        state.bellPitch = clamp(parseInt(args[i + 2], state.bellPitch), 10, 20000);
    }
    if (i + 3 < args.length)
    {
        state.bellDurationMs = clamp(parseInt(args[i + 3], state.bellDurationMs), 10, 10000);
        i += 3;
    }
    else if (i + 2 < args.length)
    {
        i += 2;
    }
    else
    {
        i++;
    }
}

private void handleLed(ref XsetState state, string[] args, ref size_t i)
{
    if (args[i] == "+led")
    {
        state.ledActive = true;
        return;
    }
    if (args[i] == "-led")
    {
        state.ledActive = false;
        return;
    }

    if (i + 1 < args.length)
    {
        string value = args[i + 1];
        if (value == "on")
        {
            state.ledActive = true;
            i++;
        }
        else if (value == "off")
        {
            state.ledActive = false;
            i++;
        }
        else
        {
            // Numeric masks: treat zero as off, non-zero as on.
            int mask = parseInt(value, state.ledActive ? 1 : 0);
            state.ledActive = mask != 0;
            i++;
        }
    }
}

private void printQuery(const XsetState state)
{
    writeln("Keyboard Control:");
    writefln("  auto repeat:  on    key click percent:  0    LED mask:  %s", state.ledActive ? "00000001" : "00000000");
    writeln("  auto repeat delay:  500    repeat rate:  33");
    writefln("  bell percent:  %d    bell pitch:  %d    bell duration:  %d", state.bellEnabled ? state.bellPercent : 0, state.bellPitch, state.bellDurationMs);
    writeln("Pointer Control:");
    writeln("  acceleration:  2/1    threshold:  4");
    writeln("Screen Saver:");
    writefln("  prefer blanking:  %s    allow exposures:  %s", state.preferBlanking ? "yes" : "no", state.allowExposures ? "yes" : "no");
    writefln("  timeout:  %d    cycle:  %d", state.screensaverEnabled ? state.screensaverTimeout : 0, state.screensaverEnabled ? state.screensaverCycle : 0);
    writeln("DPMS (Energy Star):");
    writefln("  Standby: %d    Suspend: %d    Off: %d", state.dpmsStandby, state.dpmsSuspend, state.dpmsOff);
    writefln("  DPMS is %s", state.dpmsEnabled ? "Enabled" : "Disabled");
    writefln("  Monitor is %s", state.dpmsLastAction.length ? state.dpmsLastAction : "On");
    writeln("\nMock note: " ~ stubNote);
}

int main(string[] args)
{
    auto help = handleHelpAndVersion(args);
    if (help >= 0)
    {
        return help;
    }

    XsetState state;
    bool queryRequested = false;

    for (size_t i = 1; i < args.length; ++i)
    {
        auto arg = args[i];
        final switch (arg)
        {
        case "q", "-q", "--query":
            queryRequested = true;
            break;
        case "s":
            handleScreensaver(state, args, i);
            break;
        case "dpms":
            handleDpms(state, args, i);
            break;
        case "+dpms":
            state.dpmsEnabled = true;
            break;
        case "-dpms":
            state.dpmsEnabled = false;
            break;
        case "b", "bell":
            handleBell(state, args, i);
            break;
        case "led", "+led", "-led":
            handleLed(state, args, i);
            break;
        default:
            if (arg.startsWith("-"))
            {
                stderr.writefln("xset: unsupported option '%s' in mock implementation", arg);
                stderr.writeln(stubNote);
                return 1;
            }
            // Positional values are ignored but do not error to stay script-friendly.
            break;
        }
    }

    if (queryRequested || args.length == 1)
    {
        printQuery(state);
        return 0;
    }

    return 0;
}
