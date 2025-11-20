module xclip;

import std.stdio : stderr, writeln, writefln;

private enum string stubNote =
    "Clipboard access requires an X11/Wayland server; this environment\n" ~
    "runs without a display stack, so clipboard operations are unavailable.\n" ~
    "The stub keeps scripts that probe for xclip from crashing.";

private int handleCommonFlags(string[] args, string tool)
{
    foreach (arg; args[1 .. $])
    {
        if (arg == "--version" || arg == "-V")
        {
            writeln(tool ~ " (stub) - no clipboard backend available");
            return 0;
        }
        if (arg == "--help" || arg == "-h")
        {
            writeln(tool ~ ": clipboard access is not supported in this environment.");
            writeln("\n" ~ stubNote);
            return 0;
        }
    }
    return -1;
}

int main(string[] args)
{
    auto flagResult = handleCommonFlags(args, "xclip");
    if (flagResult >= 0)
    {
        return flagResult;
    }

    stderr.writefln("xclip: clipboard access is unavailable in this environment.");
    stderr.writeln(stubNote);
    return 1;
}
