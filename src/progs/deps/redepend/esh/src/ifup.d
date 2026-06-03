module ifup;

import std.stdio;

void ifupCommand(string[] tokens) {
    if (tokens.length < 2) {
        writeln("Usage: ifup INTERFACE");
        return;
    }
    
    writeln("ifup: network configuration not supported in minimal mode");
    writeln("Interface: ", tokens[1]);
}
