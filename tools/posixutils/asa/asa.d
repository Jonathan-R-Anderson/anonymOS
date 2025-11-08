/**
 * D port of "asa - interpret carriage-control characters"
 * Original (C) 2004-2006 Jeff Garzik <jgarzik@pobox.com>
 * D version (c) 2025, same GPL-2.0 terms as original (if you keep compatibility).
 *
 * Behavior:
 * - For each input line, the *first* character is a control code:
 *     ' '  : print the rest of the line
 *     '0'  : print a newline, then the rest
 *     '1'  : print a form feed ('\f'), then the rest
 *     '+'  : print a carriage return ('\r'), then the rest
 * - The rest-of-line is printed without its trailing newline.
 * - If no files are given, read stdin. A lone "-" means stdin too.
 */

import std.stdio : File, stdin, stdout, stderr, write, writef, writefln, writeln, KeepTerminator;
import std.getopt : getopt, defaultGetoptPrinter;
import std.string : chomp, stripRight;
import std.algorithm : any;
import std.file : exists, isDir;
import std.exception : enforce;

private int processStream(File f, string srcName)
{
    // Read line-by-line, preserving the newline so we can trim exactly like the C tool.
    // byLine!string with KeepTerminator.yes preserves '\n'.
    foreach (rawLine; f.byLine!string(KeepTerminator.yes))
    {
        // Each line must be at least 1 char (the control char). The C code also
        // expected the newline to be present, but we just require >= 1.
        if (rawLine.length == 0)
        {
            // Malformed (empty) line — mirror the original behavior (print a warning).
            stderr.writeln("malformed line");
            continue;
        }

        // Control character is the very first byte/char.
        immutable ch = rawLine[0];

        // The "payload" text starts after the control char.
        string payload = (rawLine.length > 1) ? rawLine[1 .. $] : "";

        // Trim a single trailing newline (if present) to match the original.
        if (!payload.empty && payload[$ - 1] == '\n')
            payload = payload[0 .. $ - 1];

        // Output according to ASA carriage-control.
        final switch (ch)
        {
            case ' ':
                // Just print the line (without an extra newline)
                write(payload);
                break;
            case '0':
                // Print an extra newline, then the line
                writeln();
                write(payload);
                break;
            case '1':
                // Form feed, then the line
                write('\f');
                write(payload);
                break;
            case '+':
                // Carriage return, then the line
                write('\r');
                write(payload);
                break;
            default:
                // If the control char is unknown, mimic "do nothing extra" and just print payload.
                // (The original C had no default; falling through meant printing nothing.
                //  Here we choose to be slightly forgiving. If you prefer strictness, uncomment:)
                // stderr.writeln("malformed control character on line from ", srcName);
                write(payload);
                break;
        }
    }
    return 0;
}

private int processFile(string path)
{
    if (path == "-" || path.length == 0)
    {
        // Stdin
        return processStream(stdin, "<stdin>");
    }
    // Basic sanity checks (optional)
    enforce(exists(path), "asa: no such file: "~path);
    enforce(!isDir(path), "asa: is a directory: "~path);

    auto f = File(path, "r");
    scope (exit) f.close();
    return processStream(f, path);
}

int main(string[] args)
{
    // No options to parse (to match the original). Keep a help banner anyway.
    bool showHelp = false;
    auto helpInfo = getopt(args,
        "h|help", "Show help", &showHelp
    );
    if (showHelp)
    {
        defaultGetoptPrinter(
            "asa - interpret carriage-control characters\n\n"
            ~ "Usage:\n"
            ~ "  asa                (read stdin)\n"
            ~ "  asa -              (read stdin)\n"
            ~ "  asa file1 [file2 ...]\n\n"
            ~ "For each input line, the first character controls printing of the remainder:\n"
            ~ "  ' ' : print as-is\n"
            ~ "  '0' : print a newline, then the line\n"
            ~ "  '1' : print a form feed, then the line\n"
            ~ "  '+' : print a carriage return, then the line\n",
            helpInfo.options);
        return 0;
    }

    // Remaining args are files.
    // If none provided, read stdin (like WF_NO_FILES_STDIN in the original).
    int status = 0;
    if (args.length <= 1)
    {
        // no file args — stdin
        status |= processFile("-");
    }
    else
    {
        foreach (i; 1 .. args.length)
        {
            try
            {
                status |= processFile(args[i]);
            }
            catch (Exception e)
            {
                stderr.writeln(e.msg);
                status = 1;
            }
        }
    }
    return status;
}
