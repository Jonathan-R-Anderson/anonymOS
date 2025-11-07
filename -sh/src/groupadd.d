module groupadd;

import std.stdio;
import std.string : join;
import syswrap : system;

/// Execute the system groupadd command with the provided arguments.
void groupaddCommand(string[] tokens)
{
    string args = tokens.length > 1 ? tokens[1 .. $].join(" ") : "";
    string cmd = "groupadd" ~ (args.length ? " " ~ args : "");
    auto rc = system(cmd);
    if(rc != 0)
        writeln("groupadd failed with code ", rc);
}
