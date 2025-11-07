module local;

import std.stdio;
import std.string : indexOf;
import interpreter : variables;

/// Minimal local implementation - assigns variables in the global map.

void localCommand(string[] tokens)
{
    if(tokens.length < 2)
    {
        writeln("Usage: local name [value]");
        return;
    }
    for(size_t i=1;i<tokens.length;i++)
    {
        auto arg = tokens[i];
        auto eq = arg.indexOf('=');
        string name;
        string val;
        if(eq > 0)
        {
            name = arg[0 .. eq];
            val = arg[eq+1 .. $];
        }
        else if(i + 1 < tokens.length)
        {
            name = arg;
            val = tokens[++i];
        }
        else
        {
            name = arg;
            val = "";
        }
        variables[name] = val;
    }
}
