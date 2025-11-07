module dirname;

import std.stdio;
import std.path : dirName;

void dirnameCommand(string[] tokens)
{
    if(tokens.length < 2) {
        writeln("Usage: dirname path");
        return;
    }
    auto path = tokens[1];
    auto dir = dirName(path);
    if(dir.length == 0)
        dir = ".";
    writeln(dir);
}

