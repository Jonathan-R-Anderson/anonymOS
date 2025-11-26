/**
 * D port of "asa - interpret carriage-control characters"
 * Behavior:
 *   ' ' : print the rest of the line
 *   '0' : print a newline, then the rest
 *   '1' : print a form feed ('\f'), then the rest
 *   '+' : print a carriage return ('\r'), then the rest
 */
module posixutils.asa;

import std.stdio : File, stdin, stderr, write, writeln, KeepTerminator;
import std.getopt : getopt, defaultGetoptPrinter;
import std.file : exists, isDir;
import std.exception : enforce;

private int processStream(File f, string srcName)
{
    // Preserve the newline so we can trim exactly one if present.
    foreach (const(char)[] rawLine; f.byLine(KeepTerminator.yes))
    {
        if (rawLine.length == 0)
        {
            stderr.writeln("asa: malformed empty line from ", srcName);
            continue;
        }

        const char ch = rawLine[0];

        // Payload starts after control char
        const(char)[] payload = (rawLine.length > 1) ? rawLine[1 .. $] : null;

        // Trim a single trailing '\n' if present
        if (payload.length != 0 && payload[$ - 1] == '\n')
            payload = payload[0 .. $ - 1];

        // Do the ASA action
        switch (ch)
        {
            case ' ':
                write(payload);
                break;
            case '0':
                writeln();          // extra newline
                write(payload);
                break;
            case '1':
                write('\f');        // form feed
                write(payload);
                break;
            case '+':
                write('\r');        // carriage return
                write(payload);
                break;
            default:
                // Be forgiving: just print payload like space control.
                // (If you want strict POSIX behavior, you could warn instead.)
                write(payload);
                break;
        }
    }
    return 0;
}

private int processFile(string path)
{
    if (path == "-" || path.length == 0)
        return processStream(stdin, "<stdin>");

    enforce(exists(path), "asa: " ~ path ~ ": No such file");
    enforce(!isDir(path), "asa: " ~ path ~ ": Is a directory");

    auto f = File(path, "r");
    scope (exit) f.close();
    return processStream(f, path);
}

int main(string[] args)
{
    bool showHelp = false;
    auto info = getopt(args,
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
            ~ "Control chars (first char of each line):\n"
            ~ "  ' ' : print as-is\n"
            ~ "  '0' : print a newline, then the line\n"
            ~ "  '1' : print a form feed, then the line\n"
            ~ "  '+' : print a carriage return, then the line\n",
            info.options);
        return 0;
    }

    int status = 0;
    if (args.length <= 1)
    {
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
