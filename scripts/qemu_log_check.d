module scripts.qemu_log_check;

import std.stdio;
import std.algorithm.searching : canFind;
import std.getopt;

/// Search `logFile` for a given `pattern`. Prints the first matching line
/// number and text if found. Otherwise notifies that the pattern was not found.
void searchAndPrint(string logFile, string pattern)
{
    size_t lineNo = 0;
    foreach (line; File(logFile).byLine())
    {
        lineNo++;
        if (line.canFind(pattern))
        {
            writeln(pattern, " found at line ", lineNo, ": ", line);
            return;
        }
    }
    writeln(pattern, " not found in ", logFile);
}

void main(string[] args)
{
    string logFile = "qemu.log";
    getopt(args,
        "file|f", &logFile
    );

    const patterns = [
        "long_mode_start",
        // The kernel outputs this message before launching the ttyShelly shell
        // when the boot process succeeds.  Look for it in the QEMU log to
        // verify that the system reached the shell startup phase.
        "Starting ttyShelly shell"
    ];

    foreach (p; patterns)
    {
        searchAndPrint(logFile, p);
    }
}

