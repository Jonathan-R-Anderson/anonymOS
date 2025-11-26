module logname;

import std.stdio;
import std.process : environment;

/// Print the current login name.
void lognameCommand(string[] tokens)
{
    if("LOGNAME" in environment)
        writeln(environment["LOGNAME"]);
    else if("USER" in environment)
        writeln(environment["USER"]);
    else
        writeln("unknown");
}
