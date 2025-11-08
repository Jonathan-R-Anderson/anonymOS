// dirname.d — D translation of the provided C++ dirname tool
module dirname_d;

import std.stdio : writeln, writef, stderr;
import std.string : fromStringz;
import core.stdc.stdio : fprintf;
import core.sys.posix.libgen : dirname;

int main(string[] args)
{
    // too few or too many args
    if (args.length != 2)
    {
        // Match original: "Usage: %s PATH\n"
        // args[0] is the program name
        stderr.writef("Usage: %s PATH\n", args[0]);
        return 1;
    }

    // dirname(3) may modify its input, so pass a mutable, NUL-terminated copy
    auto pathBuf = (args[1] ~ "\0").dup; // char[] buffer with trailing NUL
    auto res = dirname(pathBuf.ptr);     // may modify pathBuf in place

    // Print result
    writeln(fromStringz(res));
    return 0;
}
