module dirname;

import std.stdio;
import std.string;

void dirnameCommand(string[] tokens) {
    if(tokens.length < 2) {
        writeln("Usage: dirname NAME");
        return;
    }
    string path = tokens[1];
    
    // Strip trailing slashes unless path is just "/"
    while(path.length > 1 && path[$-1] == '/')
        path = path[0 .. $-1];
        
    long idx = path.lastIndexOf('/');
    if(idx == -1) {
        writeln(".");
    } else if(idx == 0) {
        writeln("/");
    } else {
        writeln(path[0 .. idx]);
    }
}
