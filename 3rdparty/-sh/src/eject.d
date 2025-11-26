module eject;

import std.stdio;
import std.string : join, toStringz;
import syswrap : system;

/// Execute the system eject command with the provided arguments.
void ejectCommand(string[] tokens)
{
    string args = tokens.length > 1 ? tokens[1 .. $].join(" ") : "";
    string cmd = "eject" ~ (args.length ? " " ~ args : "");
    auto rc = system(cmd);
    if(rc != 0)
        writeln("eject failed with code ", rc);
}
