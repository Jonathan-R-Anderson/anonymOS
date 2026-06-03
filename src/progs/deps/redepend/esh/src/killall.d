module killall;

import std.stdio;
import std.string : join;
import syswrap : system;

/// Execute the system killall command with the provided arguments.
void killallCommand(string[] tokens)
{
    string args = tokens.length > 1 ? tokens[1 .. $].join(" ") : "";
    string cmd = "killall" ~ (args.length ? " " ~ args : "");
    auto rc = system(cmd);
    if(rc != 0)
        writeln("killall failed with code ", rc);
}
