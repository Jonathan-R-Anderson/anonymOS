module logout;

import std.stdio;
import std.conv : to;
import core.stdc.stdlib : exit;

/// Terminate the shell session.
void logoutCommand(string[] tokens)
{
    int code = 0;
    if(tokens.length > 1)
    {
        try
            code = to!int(tokens[1]);
        catch(Exception) {}
    }
    exit(code);
}
