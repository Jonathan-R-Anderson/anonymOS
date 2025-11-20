module xsel;

import std.stdio : stderr, writeln, writefln;

private enum string stubNote =
    "Clipboard and selection access requires an X11/Wayland server; this\n" ~
    "environment runs headless, so selection buffers are unavailable. The\n" ~
    "stub ensures scripts that expect xsel can degrade gracefully.";

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
            writeln(tool ~ ": selection/clipboard access is not supported in this environment.");
            writeln("\n" ~ stubNote);
            return 0;
        }
    }
    return -1;
}

int main(string[] args)
{
    auto flagResult = handleCommonFlags(args, "xsel");
    if (flagResult >= 0)
    {
        return flagResult;
    }

    stderr.writefln("xsel: clipboard/selection access is unavailable in this environment.");
    stderr.writeln(stubNote);
    return 1;
}
