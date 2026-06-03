module ifdown;

import std.stdio;
import std.string : join;
import syswrap : system;

/// Execute the system ifdown command with the provided arguments.
void ifdownCommand(string[] tokens)
{
    string args = tokens.length > 1 ? tokens[1 .. $].join(" ") : "";
    string cmd = "ifdown" ~ (args.length ? " " ~ args : "");
    auto rc = system(cmd);
    if(rc != 0)
        writeln("ifdown failed with code ", rc);
}
