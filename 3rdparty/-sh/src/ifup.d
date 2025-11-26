module ifup;

import std.stdio;
import std.string : join;
import syswrap : system;

/// Execute the system ifup command with the provided arguments.
void ifupCommand(string[] tokens)
{
    string args = tokens.length > 1 ? tokens[1 .. $].join(" ") : "";
    string cmd = "ifup" ~ (args.length ? " " ~ args : "");
    auto rc = system(cmd);
    if(rc != 0)
        writeln("ifup failed with code ", rc);
}
