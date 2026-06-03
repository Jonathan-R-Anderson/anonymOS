module logname;

import std.stdio;
import std.process : environment;

void lognameCommand(string[] tokens) {
    auto u = environment.get("LOGNAME", environment.get("USER", ""));
    if (u.length) writeln(u);
    else writeln("root");
}
