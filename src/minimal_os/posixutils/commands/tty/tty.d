// tty.d — D port of the simple `tty` utility
import std.stdio : writeln, stderr;
import std.string : fromStringz;
import core.sys.posix.unistd : isatty, ttyname;

// Some platforms expose this in core.sys.posix.unistd; define if missing.
enum STDIN_FILENO = 0;

int main(string[] args)
{
    // no options to parse (the original argp block had none)
    if (isatty(STDIN_FILENO) == 0)
    {
        writeln("not a tty");
        return 1; // EXIT_FAILURE
    }

    auto name = ttyname(STDIN_FILENO);
    if (name is null)
    {
        stderr.writeln("ttyname failed");
        return 1;
    }

    writeln(fromStringz(name));
    return 0; // EXIT_SUCCESS
}
