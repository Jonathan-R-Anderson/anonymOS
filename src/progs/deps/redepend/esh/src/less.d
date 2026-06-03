module less;

import std.stdio;
import std.string : splitLines, toStringz;
import shell.syscalls;

void lessCommand(string[] tokens) {
    if (tokens.length < 2) {
        writeln("Missing filename");
        return;
    }
    string fname = tokens[1];
    auto fd = sys_open(fname.toStringz, 0);
    if (fd < 0) {
        writeln("less: ", fname, ": No such file");
        return;
    }

    ubyte[4096] buf;
    long n;
    string pending;
    int lineCount = 0;
    int maxLines = 23; // standard term height approx

    while ((n = sys_read(cast(int)fd, buf.ptr, 4096)) > 0) {
        string chunk = pending ~ cast(string)buf[0..n];
        auto lines = chunk.splitLines();
        
        // Handle last potentially partial line? 
        // splitLines usually handles it well but if buffer splits \n...
        // Simplified for minimal shell.
        
        foreach (line; lines) {
            writeln(line);
            lineCount++;
            if (lineCount >= maxLines) {
                write(":"); // minimal prompt
                ubyte[1] k;
                sys_read(0, k.ptr, 1); // Wait for key
                if (k[0] == 'q') {
                    sys_close(cast(int)fd);
                    return;
                }
                lineCount = 0;
            }
        }
        pending = ""; // In a robust impl, handle split line at end of buffer
    }
    sys_close(cast(int)fd);
    writeln("(END)");
}
