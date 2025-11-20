module xrandr;

import std.stdio : stderr, writeln, writefln;

private enum string stubNote =
    "This build does not include an X11/Wayland display server; display\n" ~
    "configuration is unavailable. The stub exists so scripts can detect\n" ~
    "the command and fall back gracefully.";

private int handleCommonFlags(string[] args, string tool)
{
    foreach (arg; args[1 .. $])
    {
        if (arg == "--version" || arg == "-V")
        {
            writeln(tool ~ " (stub) - no display backend available");
            return 0;
        }
        if (arg == "--help" || arg == "-h")
        {
            writeln(tool ~ ": display configuration is not supported in this environment.");
            writeln("\n" ~ stubNote);
            return 0;
        }
    }
    return -1; // no common flag handled
}

int main(string[] args)
{
    auto flagResult = handleCommonFlags(args, "xrandr");
    if (flagResult >= 0)
    {
        return flagResult;
    }

    stderr.writefln("xrandr: display configuration is unavailable in this environment.");
    stderr.writeln(stubNote);
    return 1;
}
