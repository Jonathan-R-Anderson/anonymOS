import std.stdio : writeln, stderr, writefln;
import std.path : baseName;
import std.algorithm.searching : endsWith;

int main(string[] args)
{
    if (args.length != 2 && args.length != 3) {
        stderr.writefln("Usage: %s PATH [SUFFIX]", args[0]);
        return 1;
    }

    auto path = args[1];
    string suffix;
    if (args.length == 3)
        suffix = args[2];

    string bn = baseName(path);

    if (suffix.length != 0 && suffix.length < bn.length && bn.endsWith(suffix)) {
        bn = bn[0 .. $ - suffix.length];
    }

    writeln(bn);
    return 0;
}
