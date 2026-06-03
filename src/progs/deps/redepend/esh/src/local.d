module local;

import std.stdio;
import std.string : indexOf;

// Simple in-memory variable storage
__gshared string[string] g_local_vars;

void localCommand(string[] tokens) {
    if (tokens.length < 2) {
        // List all local variables
        foreach (key, value; g_local_vars) {
            writeln(key, "=", value);
        }
        return;
    }
    
    // Set local variables
    foreach (arg; tokens[1..$]) {
        auto eq = arg.indexOf('=');
        if (eq >= 0) {
            string key = arg[0..eq];
            string value = arg[eq+1..$];
            g_local_vars[key] = value;
        } else {
            writeln("local: ", arg, ": not a valid identifier");
        }
    }
}
