// logger.d — D translation of the provided C++ logger
module logger_d;

version (Posix) {} else static assert(0, "This utility requires a POSIX system.");

import std.stdio          : stderr, writefln;
import std.getopt         : getopt, GetoptResult, defaultGetoptPrinter;
import std.string         : join, toStringz;
import std.conv           : to;
import core.stdc.stdlib   : EXIT_FAILURE, EXIT_SUCCESS;
import core.stdc.string   : strerror;
import core.stdc.errno    : errno;
import core.sys.posix.syslog : openlog, syslog, closelog,
                               LOG_USER, LOG_NOTICE, LOG_PID;

extern(C) int main(int argc, char** argv)
{
    // Collect args as D strings
    string[] args;
    args.length = argc;
    foreach (i; 0 .. argc) args[i] = argv[i].to!string;

    // No options; everything is treated as message tokens
    GetoptResult res = getopt(args /* no flags */);
    auto msgTokens = res.args;               // everything after program name
    auto message   = msgTokens.join(" ");

    // syslog(LOG_USER | LOG_NOTICE, "%s", message.c_str());
    openlog(argv[0], LOG_PID, LOG_USER);
    scope(exit) closelog();

    // Use %s style formatting like the C version
    syslog(LOG_USER | LOG_NOTICE, "%s".ptr, message.toStringz);

    return EXIT_SUCCESS;
}
