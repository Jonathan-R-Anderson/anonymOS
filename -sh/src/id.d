module id;

import std.stdio;
import std.string : join;
import syswrap : system;

/// Execute the system id command with the provided arguments.
void idCommand(string[] tokens)
{
    string args = tokens.length > 1 ? tokens[1 .. $].join(" ") : "";
    string cmd = "id" ~ (args.length ? " " ~ args : "");
    auto rc = system(cmd);
    if(rc != 0)
        writeln("id failed with code ", rc);
}
