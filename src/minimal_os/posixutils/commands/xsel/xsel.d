module xsel;

import std.array : appender;
import std.exception : enforce;
import std.file : exists, read, remove, write;
import std.getopt : defaultGetoptPrinter, getopt, GetoptResult;
import std.path : buildPath;
import std.stdio : stderr, stdin, stdout, writeln;
import std.string : toLower;

private enum string VERSION = "xsel 1.0 (minimal replacement)";

/// Location on disk used to emulate clipboard selections.
private enum string CLIPBOARD_DIR = "/tmp";

struct Options
{
    bool output = false;      // -o / --output
    bool input = true;        // -i / --input (default)
    bool append = false;      // -a / --append
    bool clear = false;       // -c / --clear
    bool del = false;         // -k / --delete
    string selection = "primary";
    bool showHelp = false;
    bool showVersion = false;
}

private void printUsage(GetoptResult res)
{
    writeln("Usage: xsel [-i|-o|-k|-c] [-a] [-p|-s|-b]");
    writeln("Copies stdin to a selection or prints a stored selection to stdout.");
    writeln();
    defaultGetoptPrinter("Options:", res.options);
}

private string normalizeSelection(string sel)
{
    auto lower = toLower(sel);
    if (lower.length == 0)
    {
        return "";
    }

    if (lower[0] == 'p') return "primary";
    if (lower[0] == 's') return "secondary";
    if (lower[0] == 'b' || lower[0] == 'c') return "clipboard";
    return "";
}

private string clipboardPath(string selection)
{
    return buildPath(CLIPBOARD_DIR, "xsel-" ~ selection ~ ".buf");
}

private int writeSelection(const Options opts)
{
    auto buf = appender!(ubyte[])();
    foreach (chunk; stdin.byChunk(4096))
    {
        buf.put(chunk);
    }

    auto path = clipboardPath(opts.selection);
    if (opts.append && exists(path))
    {
        auto existing = read(path);
        existing ~= buf.data;
        write(path, existing);
    }
    else
    {
        write(path, buf.data);
    }

    return 0;
}

private int readSelection(const Options opts)
{
    auto path = clipboardPath(opts.selection);
    if (!exists(path))
    {
        stderr.writeln("xsel: no data available for selection '" ~ opts.selection ~ "'");
        return 1;
    }

    auto data = read(path);
    stdout.rawWrite(data);
    return 0;
}

private int clearSelection(const Options opts)
{
    auto path = clipboardPath(opts.selection);
    if (exists(path))
    {
        remove(path);
    }
    return 0;
}

int main(string[] args)
{
    Options opts;
    auto res = getopt(args,
        "i|input", "Read standard input into the selection (default).", &opts.input,
        "o|output", "Print the contents of the selection to standard output.", &opts.output,
        "a|append", "Append to the selection instead of overwriting.", &opts.append,
        "p|primary", "Use the primary selection.", { opts.selection = "primary"; },
        "s|secondary", "Use the secondary selection.", { opts.selection = "secondary"; },
        "b|clipboard", "Use the clipboard selection.", { opts.selection = "clipboard"; },
        "k|delete", "Delete the contents of the selection.", &opts.del,
        "c|clear", "Clear the selection (alias for --delete).", &opts.clear,
        "help|h", "Show help message and exit.", &opts.showHelp,
        "version|V", "Show version information and exit.", &opts.showVersion,
    );

    // Clear overrides delete so we only need to check one flag downstream.
    if (opts.clear)
    {
        opts.del = true;
    }

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
        stderr.writeln("xsel: invalid selection; choose primary, secondary, or clipboard");
        return 1;
    }

    int activeModes = 0;
    if (opts.input) activeModes++;
    if (opts.output) activeModes++;
    if (opts.del) activeModes++;

    if (activeModes == 0)
    {
        stderr.writeln("xsel: choose an action such as --input, --output, or --delete");
        return 1;
    }

    if (activeModes > 1)
    {
        stderr.writeln("xsel: input, output, and delete modes are mutually exclusive");
        return 1;
    }

    if (opts.append && !opts.input)
    {
        stderr.writeln("xsel: --append is only valid in input mode");
        return 1;
    }

    try
    {
        if (opts.output)
        {
            return readSelection(opts);
        }
        if (opts.del)
        {
            return clearSelection(opts);
        }
        enforce(opts.input);
        return writeSelection(opts);
    }
    catch (Exception e)
    {
        stderr.writeln("xsel: " ~ e.msg);
        return 1;
    }
}
