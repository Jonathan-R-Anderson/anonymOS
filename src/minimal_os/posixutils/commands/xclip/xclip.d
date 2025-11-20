module xclip;

import std.array : appender;
import std.file : exists, read, write;
import std.getopt : defaultGetoptPrinter, getopt, GetoptResult;
import std.path : buildPath;
import std.stdio : stderr, stdin, stdout, writeln;
import std.string : toLower;

private enum string VERSION = "xclip 1.0 (minimal replacement)";

/// Location on disk used to emulate clipboard selections.
private enum string CLIPBOARD_DIR = "/tmp";

struct Options
{
    bool output = false;      // -o / --out
    bool input = true;        // -i / --in (default)
    string selection = "primary";
    bool showHelp = false;
    bool showVersion = false;
}

private void printUsage(GetoptResult res)
{
    writeln("Usage: xclip [-i|-o] [-selection {primary|secondary|clipboard}]");
    writeln("Copies stdin to a selection or prints a stored selection to stdout.");
    writeln();
    defaultGetoptPrinter("Options:", res.options, stderr);
}

private string normalizeSelection(string sel)
{
    auto lower = toLower(sel);
    if (lower.length == 0)
    {
        return "";
    }

    // Accept both full names and shorthand (p/s/c).
    if (lower[0] == 'p') return "primary";
    if (lower[0] == 's') return "secondary";
    if (lower[0] == 'c') return "clipboard";
    return ""; // invalid
}

private string clipboardPath(string selection)
{
    return buildPath(CLIPBOARD_DIR, "xclip-" ~ selection ~ ".buf");
}

private int writeSelection(const Options opts)
{
    auto buf = appender!(ubyte[])();
    ubyte[4096] chunk;
    while (true)
    {
        auto readCount = stdin.rawRead(chunk[]);
        if (readCount == 0)
        {
            break;
        }
        buf.put(chunk[0 .. readCount]);
    }

    auto path = clipboardPath(opts.selection);
    write(path, buf.data);
    return 0;
}

private int readSelection(const Options opts)
{
    auto path = clipboardPath(opts.selection);
    if (!exists(path))
    {
        stderr.writeln("xclip: no data available for selection '" ~ opts.selection ~ "'");
        return 1;
    }

    auto data = read(path);
    stdout.rawWrite(data);
    return 0;
}

int main(string[] args)
{
    Options opts;
    auto res = getopt(args,
        "i|in", "Read standard input into the selection (default).", &opts.input,
        "o|out", "Print the contents of the selection to standard output.", &opts.output,
        "selection|sel", "Target selection: primary, secondary, or clipboard.", &opts.selection,
        "help|h", "Show help message and exit.", &opts.showHelp,
        "version|V", "Show version information and exit.", &opts.showVersion,
    );

    if (opts.output)
    {
        opts.input = false;
    }

    if (opts.showHelp)
    {
        printUsage(res);
        return 0;
    }

    if (opts.showVersion)
    {
        writeln(VERSION);
        return 0;
    }

    opts.selection = normalizeSelection(opts.selection);
    if (!opts.selection.length)
    {
        stderr.writeln("xclip: invalid selection; choose primary, secondary, or clipboard");
        return 1;
    }

    if (!opts.input && !opts.output)
    {
        stderr.writeln("xclip: choose either input (-i) or output (-o) mode");
        return 1;
    }

    if (opts.input && opts.output)
    {
        stderr.writeln("xclip: -i/--in and -o/--out are mutually exclusive");
        return 1;
    }

    try
    {
        if (opts.output)
        {
            return readSelection(opts);
        }
        return writeSelection(opts);
    }
    catch (Exception e)
    {
        stderr.writeln("xclip: " ~ e.msg);
        return 1;
    }
}
