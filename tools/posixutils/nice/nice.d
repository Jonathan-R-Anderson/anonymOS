// nice.d — D translation of the provided C nice(1)
module nice_d;

version (Posix) {} else static assert(0, "This utility requires a POSIX system.");

import std.stdio       : stderr, writefln, writeln;
import std.getopt      : getopt, GetoptResult, defaultGetoptPrinter;
import std.conv        : to;
import std.string      : toStringz;
import core.stdc.stdlib: EXIT_FAILURE, EXIT_SUCCESS, exit;
import core.stdc.stdio : perror;
import core.stdc.errno : errno;
import core.sys.posix.unistd : nice, execvp;

enum NICE_MIN = -30;
enum NICE_MAX =  30;
enum NICE_DEF =  10;

noreturn void usage(string prog) {
    stderr.writefln("Usage: %s [-n INC] command [arg...]", prog);
    exit(1);
}

extern(C) int main(int argc, char** argv) {
    // Collect argv as D strings
    string[] args; args.length = argc;
    foreach (i; 0 .. argc) args[i] = argv[i].ptr[0 .. args[i].length].idup; // ensure stable

    int inc = NICE_DEF;
    bool showHelp = false;

    GetoptResult gr = getopt(
        args,
        "n|adjustment", &inc,
        "h|help",       &showHelp
    );

    if (showHelp) {
        defaultGetoptPrinter("nice - run a program with modified scheduling priority", gr.options);
        writeln("\nUsage:\n  ", args[0], " [-n INC] command [arg...]");
        return 0;
    }

    auto rest = gr.args;            // remaining args after option parsing
    if (rest.length < 2) usage(args[0]); // need program + command at minimum

    // Bounds check like the C version
    if (inc < NICE_MIN || inc > NICE_MAX) {
        stderr.writefln("%s: -n INC must be in [%d,%d]", args[0], NICE_MIN, NICE_MAX);
        return EXIT_FAILURE;
    }

    // Apply niceness
    // Note: Linux nice(2) returns new nice value (could be -1 validly); the original
    // code error-checked < 0, so we keep that behavior here.
    if (nice(inc) < 0) {
        perror("nice(2)");
        return 1;
    }

    // Prepare execvp argv: command is rest[1], followed by its args
    auto cmdAndArgs = rest[1 .. $];
    // Build C-style argv array (null-terminated)
    auto cargv = new char*[cmdAndArgs.length + 1];
    foreach (i, s; cmdAndArgs)
        cargv[i] = cast(char*) s.toStringz; // execvp expects char* const*
    cargv[$-1] = null;

    // exec (only returns on error)
    execvp(cmdAndArgs[0].toStringz, cargv.ptr);

    // If we get here, exec failed
    perror("execvp(3)");
    return 1;
}
