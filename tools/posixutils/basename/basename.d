/**
 * D port of:
 *   basename PATH [SUFFIX]
 *
 * - Prints the last path component of PATH.
 * - If SUFFIX is provided and exactly matches the end of the basename
 *   (and is shorter than the basename), that suffix is stripped.
 */

import std.stdio : writeln, stderr, writefln;
import std.path : baseName;
import std.string : stripRight;
import std.algorithm.searching : endsWith;

int main(string[] args)
{
    // Expect 1 or 2 user arguments: PATH [SUFFIX]
    if (args.length != 2 && args.length != 3) {
        stderr.writefln("Usage: %s PATH [SUFFIX]", args[0]);
        return 1;
    }

    auto path    = args[1];
    string suffix;
    if (args.length == 3) {
        suffix = args[2];
    }

    // Get basename (handles trailing slashes too)
    string bn = baseName(path);

    // If suffix is non-empty, shorter than bn, and matches the end, strip it
    if (!suffix.empty && suffix.length < bn.length && bn.endsWith(suffix)) {
        bn = bn[0 .. $ - suffix.length];
    }

    writeln(bn);
    return 0;
}
