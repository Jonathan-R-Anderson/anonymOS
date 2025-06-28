import std.stdio;
import std.file;
import std.getopt;

void main(string[] args) {
    bool parents;
    bool verbose;
    auto helpInformation = getopt(args,
        "p|parents", &parents,
        "v|verbose", &verbose
    );

    if (helpInformation.helpWanted || helpInformation.errors.length) {
        writeln("Usage: mkdir [-p] [-v] DIR...");
        return;
    }

    auto dirs = helpInformation.rest;
    if (dirs.length == 0) {
        stderr.writeln("mkdir: missing operand");
        return;
    }

    foreach (d; dirs) {
        try {
            if (parents) {
                mkdirRecurse(d);
            } else {
                mkdir(d);
            }
            if (verbose) writeln("created directory: ", d);
        } catch (FileException e) {
            stderr.writeln("mkdir: cannot create directory '", d, "': ", e.msg);
        }
    }
}
