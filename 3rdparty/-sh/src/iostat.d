module iostat;

import std.stdio;
import std.string : join;
import syswrap : system;

/// Execute the system iostat command with the provided arguments.
void iostatCommand(string[] tokens)
{
    string args = tokens.length > 1 ? tokens[1 .. $].join(" ") : "";
    string cmd = "iostat" ~ (args.length ? " " ~ args : "");
    auto rc = system(cmd);
    if(rc != 0)
        writeln("iostat failed with code ", rc);
}
