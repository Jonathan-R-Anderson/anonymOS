module join;

import std.stdio;
import std.string : join;
import syswrap : system;

/// Execute the system join command with the provided arguments.
void joinCommand(string[] tokens)
{
    string args = tokens.length > 1 ? tokens[1 .. $].join(" ") : "";
    string cmd = "join" ~ (args.length ? " " ~ args : "");
    auto rc = system(cmd);
    if(rc != 0)
        writeln("join failed with code ", rc);
}
