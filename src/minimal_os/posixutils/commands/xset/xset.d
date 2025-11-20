module xset;

import std.stdio : stderr, writeln, writefln;

private enum string stubNote =
    "This build does not include an X11/Wayland display server; display\n" ~
    "power management and keyboard/LED controls are unavailable. The stub\n" ~
    "is provided so scripts can detect the command and choose alternate paths.";

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
            writeln(tool ~ ": display power management is not supported in this environment.");
            writeln("\n" ~ stubNote);
            return 0;
        }
    }
    return -1;
}

int main(string[] args)
{
    auto flagResult = handleCommonFlags(args, "xset");
    if (flagResult >= 0)
    {
        return flagResult;
    }

    stderr.writefln("xset: display power/keyboard controls are unavailable in this environment.");
    stderr.writeln(stubNote);
    return 1;
}
