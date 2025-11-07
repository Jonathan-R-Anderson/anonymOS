module login;

import std.stdio;
import std.process : environment;

/// Very simple login command that sets the LOGNAME and USER environment.
void loginCommand(string[] tokens)
{
    if(tokens.length < 2)
    {
        writeln("login: missing username");
        return;
    }
    string user = tokens[1];
    environment["LOGNAME"] = user;
    environment["USER"] = user;
    writeln("logged in as " ~ user);
}
