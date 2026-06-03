module getopts;

import std.stdio;
import std.string;
import std.conv;
import interpreter; // variables

void getoptsCommand(string[] tokens) {
    if(tokens.length < 3) {
        writeln("Usage: getopts optstring name [args]");
        return;
    }
    string optstring = tokens[1];
    string varname = tokens[2];
    
    // In shell usage, args are usually implied "$@".
    // But tokens here are [getopts, optstring, name, ...] ??
    // Standard getopts uses shell's positional params if args not provided.
    // Here we might receive them as tokens[3..$], but simplified shell execution might not pass them?
    // Interpreter executing a script should expand "$@" before call.
    // So arguments to getopts are explicit. 
    
    string[] args = tokens.length > 3 ? tokens[3 .. $] : [];
    
    int optind = 1;
    if("OPTIND" in variables) {
        try { optind = to!int(variables["OPTIND"]); } catch(Exception){}
    }
    if(optind < 1) optind = 1;

    if(optind > args.length) {
        // Done
        // Return status 1
        // How to return status? wrapper returns void.
        // Interpreter uses exit status?
        // We can't easily control exit status from here without 'interpreter' support or `exit`.
        // Usually built-ins return status.
        // We'll set variable to "?" maybe? Or just do nothing and rely on logic.
        // Actually, successful getopts returns 0 (true), finished returns 1 (false).
        // Since we return void, we can't signal loop termination easily unless interpreter checks something.
        // Assume interpreter ignores return value of void function.
        // We'll reset variable to "?" to signal end if customary.
        return; 
    }
    
    string currentArg = args[optind-1];
    if(!currentArg.startsWith("-") || currentArg == "--") {
        // End of options
        // If "--", consume it?
        if(currentArg == "--") {
            optind++;
            variables["OPTIND"] = to!string(optind);
        }
        // Return failure (1) logic?
        // We can't.
        return;
    }
    
    // Parse option
    // Simple case: -a
    // Not handling bundled -abc
    char opt = currentArg[1];
    if(optstring.indexOf(opt) >= 0) {
        variables[varname] = "" ~ opt;
        // Check if argument needed (:)
        auto idx = optstring.indexOf(opt);
        if(idx + 1 < optstring.length && optstring[idx+1] == ':') {
             // Take next arg
             if(optind < args.length) {
                 variables["OPTARG"] = args[optind];
                 optind++; 
             } else {
                 writeln("getopts: option requires argument -- ", opt);
                 variables[varname] = "?";
             }
        } else {
            variables["OPTARG"] = "";
        }
    } else {
        variables[varname] = "?";
        variables["OPTARG"] = "";
    }
    optind++;
    variables["OPTIND"] = to!string(optind);
}
