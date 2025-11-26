// logger.d — simple syslog logger
module logger_d;

version (Posix) {} else static assert(0, "This utility requires a POSIX system.");

import std.string : join, toStringz;
import core.stdc.stdlib : EXIT_SUCCESS;
import core.stdc.string : strlen;
import core.sys.posix.syslog : openlog, syslog, closelog,
                               LOG_USER, LOG_NOTICE, LOG_PID;

extern(C) int main(int argc, char** argv)
{
    // Convert argv to D strings: slice up to NUL and duplicate to immutable
    string[] args;
    args.length = argc;
    foreach (i; 0 .. argc) {
        // `argv[i]` is a C string; take [0 .. strlen] then make it immutable with `.idup`
        auto s = (cast(char*)argv[i])[0 .. strlen(argv[i])];
        args[i] = s.idup; // `string` = immutable(char)[]
    }

    // Everything after program name is the message
    auto msgTokens = (args.length > 1) ? args[1 .. $] : [];
    string message = msgTokens.join(" ");

    // Send to syslog as NOTICE in the USER facility
    openlog(argv[0], LOG_PID, LOG_USER);
    scope(exit) closelog();

    syslog(LOG_USER | LOG_NOTICE, "%s".toStringz, message.toStringz);

    return EXIT_SUCCESS;
}
