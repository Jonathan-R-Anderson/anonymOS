module letcmd;

import std.stdio;
import std.string : split, replace, indexOf;
import std.conv : to;
import bc : bcEval;
import interpreter : variables;

/// Evaluate arithmetic expressions and assign to variables.
void letCommand(string[] tokens)
{
    if(tokens.length < 2) {
        writeln("let: missing expression");
        return;
    }
    long last = 0;
    foreach(arg; tokens[1 .. $]) {
        auto expr = arg;
        string name;
        auto eq = expr.indexOf('=');
        if(eq > 0) {
            name = expr[0 .. eq];
            expr = expr[eq+1 .. $];
        }
        foreach(k, v; variables)
            expr = expr.replace(k, v);
        try {
            auto res = bcEval(expr);
            last = cast(long)res;
            if(name.length)
                variables[name] = to!string(last);
        } catch(Exception) {
            writeln("let: invalid expression ", arg);
            return;
        }
    }
    writeln(to!string(last));
}

