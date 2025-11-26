module gzip;

import std.stdio;
import std.string : join;
import syswrap : system;

/// Execute the system gzip command with the provided arguments.
void gzipCommand(string[] tokens)
{
    string args = tokens.length > 1 ? tokens[1 .. $].join(" ") : "";
    string cmd = "gzip" ~ (args.length ? " " ~ args : "");
    auto rc = system(cmd);
    if(rc != 0)
        writeln("gzip failed with code ", rc);
}
