module dmesg;

import std.stdio;
import std.string : join, toStringz;
import syswrap : system;

/// Execute the system dmesg command with the provided arguments.
void dmesgCommand(string[] tokens)
{
    string args = tokens.length > 1 ? tokens[1 .. $].join(" ") : "";
    string cmd = "dmesg" ~ (args.length ? " " ~ args : "");
    auto rc = system(cmd);
    if(rc != 0)
        writeln("dmesg failed with code ", rc);
}

