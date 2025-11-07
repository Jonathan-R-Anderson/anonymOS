module getopts;

import std.stdio;
import std.string : strip, indexOf;
import std.conv : to;
import interpreter : variables;

/// Simplified getopts implementation.
void getoptsCommand(string[] tokens)
{
    if(tokens.length < 3) {
        writeln("Usage: getopts optstring name [args]");
        return;
    }
    auto optstring = tokens[1];
    auto name = tokens[2];
    string[] args = tokens.length > 3 ? tokens[3 .. $] : [];

    size_t optind = 1;
    if("OPTIND" in variables) {
        try optind = to!size_t(variables["OPTIND"]); catch(Exception) {}
    }

    if(optind == 0) optind = 1;
    if(optind > args.length) {
        variables[name] = "?";
        return;
    }

    auto arg = args[optind - 1];
    if(arg.length < 2 || arg[0] != '-' || arg == "-") {
        variables[name] = "?";
        return;
    }
    if(arg == "--") {
        optind++;
        variables[name] = "?";
        variables["OPTIND"] = to!string(optind);
        return;
    }
    char opt = arg[1];
    bool expectArg = false;
    auto pos = optstring.indexOf(opt);
    if(pos == -1) {
        variables[name] = "?";
        variables["OPTARG"] = to!string(opt);
        optind++;
        variables["OPTIND"] = to!string(optind);
        return;
    }
    if(pos + 1 < optstring.length && optstring[pos+1] == ':')
        expectArg = true;

    string optarg;
    if(expectArg) {
        if(arg.length > 2) {
            optarg = arg[2 .. $];
        } else if(optind < args.length) {
            optind++;
            optarg = args[optind - 1];
        } else {
            variables[name] = expectArg ? ":" : "?";
            variables["OPTIND"] = to!string(optind);
            return;
        }
    }

    optind++;
    variables[name] = to!string(opt);
    variables["OPTIND"] = to!string(optind);
    if(expectArg) variables["OPTARG"] = optarg; else variables.remove("OPTARG");
}

