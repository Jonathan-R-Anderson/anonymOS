module groupdel;

import std.stdio;
import std.string : join;
import syswrap : system;

/// Execute the system groupdel command with the provided arguments.
void groupdelCommand(string[] tokens)
{
    string args = tokens.length > 1 ? tokens[1 .. $].join(" ") : "";
    string cmd = "groupdel" ~ (args.length ? " " ~ args : "");
    auto rc = system(cmd);
    if(rc != 0)
        writeln("groupdel failed with code ", rc);
}
