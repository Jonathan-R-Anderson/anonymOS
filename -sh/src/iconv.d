module iconv;

import std.stdio;
import std.string : join;
import syswrap : system;

/// Execute the system iconv command with the provided arguments.
void iconvCommand(string[] tokens)
{
    string args = tokens.length > 1 ? tokens[1 .. $].join(" ") : "";
    string cmd = "iconv" ~ (args.length ? " " ~ args : "");
    auto rc = system(cmd);
    if(rc != 0)
        writeln("iconv failed with code ", rc);
}
