module dos2unix;

import std.stdio;
import std.string : toStringz;
import std.algorithm : startsWith;
import shell.syscalls;

void convertFile(string inFile, string outFile, bool quiet) {
    auto fdIn = sys_open(inFile.toStringz, 0);
    if (fdIn < 0) {
        if (!quiet) writeln("dos2unix: cannot read ", inFile);
        return;
    }

    // Since we need to write to output, if outFile same as inFile we might need temp file
    // For simplicity, we'll read all to memory buffer then write. Not ideal for huge files but works for minimal.
    // Or just read/write chunks. But replacing \r\n with \n shrinks data, so in-place write is tricky without buffer.
    
    // We'll read everything.
    ubyte[] content;
    ubyte[4096] buffer;
    long nread;
    while ((nread = sys_read(cast(int)fdIn, buffer.ptr, buffer.length)) > 0) {
        content ~= buffer[0..nread];
    }
    sys_close(cast(int)fdIn);

    auto fdOut = sys_open(outFile.toStringz, 0x241, 420); // O_WRONLY|O_CREAT|O_TRUNC, 0644 = 420
    if (fdOut < 0) {
        if (!quiet) writeln("dos2unix: cannot write ", outFile);
        return;
    }

    // Write converting \r\n or \r to \n
    // Simple state machine
    for (size_t i = 0; i < content.length; i++) {
        if (content[i] == '\r') {
            if (i + 1 < content.length && content[i+1] == '\n') {
                continue; // skip \r, write \n next
            }
            // bare \r -> \n
            sys_write(cast(int)fdOut, "\n".ptr, 1);
        } else {
            sys_write(cast(int)fdOut, &content[i], 1);
        }
    }
    
    sys_close(cast(int)fdOut);
}

void dos2unixCommand(string[] tokens) {
    // dos2unix [options] [file ...]
    // standard behavior: convert in place
    // if no args, stdin to stdout (not supported well by this func signature yet, but we'll assume files)
    
    size_t idx = 1;
    bool quiet = false;
    
    // Check for flags
    while (idx < tokens.length && tokens[idx].startsWith("-")) {
        if (tokens[idx] == "-q") quiet = true;
        idx++;
    }
    
    if (idx >= tokens.length) {
        // Standard behavior is filter stdin->stdout if no files
        // For now, minimal implementation expects files
        if (!quiet) writeln("dos2unix: missing file operand");
        return;
    }

    foreach (file; tokens[idx .. $]) {
        convertFile(file, file, quiet);
    }
}
