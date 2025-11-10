// nice.d — run a program with modified scheduling priority (nice(1))
module nice_d;

version (Posix) {} else static assert(0, "This utility requires a POSIX system.");

import std.stdio         : stderr, writefln, writeln;
import std.getopt        : getopt, GetoptResult, defaultGetoptPrinter;
import std.string        : toStringz, fromStringz;
import core.stdc.stdlib  : EXIT_FAILURE, EXIT_SUCCESS, exit;
import core.stdc.stdio   : perror;
import core.sys.posix.unistd : nice, execvp; // <-- only these two

enum NICE_MIN = -30;
enum NICE_MAX =  30;
enum NICE_DEF =  10;

void usage(string prog)
{
    stderr.writefln("Usage: %s [-n INC] command [arg...]", prog);
    exit(1); // does not return
}

extern(C) int main(int argc, char** argv)
{
    // Convert argv -> D strings
    string[] args;
    args.length = argc;
    foreach (i; 0 .. argc)
        args[i] = fromStringz(argv[i]).idup;

    int  inc      = NICE_DEF;
    bool showHelp = false;

    // getopt mutates `args` to leave non-option args (prog remains at args[0])
    GetoptResult gr = getopt(
        args,
        "n|adjustment", &inc,
        "h|help",       &showHelp
    );

    if (showHelp)
    {
        defaultGetoptPrinter("nice - run a program with modified scheduling priority", gr.options);
        writeln();
        writeln("Usage:\n  ", args[0], " [-n INC] command [arg...]");
        return EXIT_SUCCESS;
    }

    if (args.length < 2) // need a command to exec
        usage(args[0]);

    if (inc < NICE_MIN || inc > NICE_MAX)
    {
        stderr.writefln("%s: -n INC must be in [%d,%d]", args[0], NICE_MIN, NICE_MAX);
        return EXIT_FAILURE;
    }

    // Apply niceness (classic tools treat <0 as error)
    if (nice(inc) < 0)
    {
        perror("nice");
        return 1;
    }

    // Exec: command is args[1], followed by any remaining args
    auto rest = args[1 .. $];  // [command, arg1, arg2, ...]
    auto cmd  = rest[0];

    // Build C argv[] (null-terminated)
    auto cargv = new const(char)*[rest.length + 1];
    foreach (i, s; rest)
        cargv[i] = s.toStringz;
    cargv[rest.length] = null;

    // Call execvp (only returns on error)
    execvp(cmd.toStringz, cargv.ptr);

    // If we’re here, exec failed
    perror("execvp");
    return 1;
}
