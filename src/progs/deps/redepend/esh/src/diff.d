module diff;

import std.stdio;
import std.string : splitLines, toStringz;
import std.algorithm : max;
import shell.syscalls;

string[] readLines(string fname) {
    if (fname == "-") {
        ubyte[4096] buf;
        long n;
        string content;
        while ((n = sys_read(0, buf.ptr, 4096)) > 0) content ~= cast(string)buf[0..n];
        return content.splitLines;
    }
    auto fd = sys_open(fname.toStringz, 0);
    if (fd < 0) return [];
    ubyte[4096] buf;
    long n;
    string content;
    while ((n = sys_read(cast(int)fd, buf.ptr, 4096)) > 0) content ~= cast(string)buf[0..n];
    sys_close(cast(int)fd);
    return content.splitLines;
}

// Simple LCS based diff
void diffCommand(string[] tokens) {
    if (tokens.length < 3) {
        writeln("Usage: diff FILE1 FILE2");
        return;
    }
    auto f1 = readLines(tokens[1]);
    auto f2 = readLines(tokens[2]);
    
    // Compute LCS matrix
    int[][] C;
    C.length = f1.length + 1;
    foreach(ref row; C) row.length = f2.length + 1;
    
    for(size_t i=1; i<=f1.length; i++) {
        for(size_t j=1; j<=f2.length; j++) {
            if (f1[i-1] == f2[j-1]) C[i][j] = C[i-1][j-1] + 1;
            else C[i][j] = max(C[i][j-1], C[i-1][j]);
        }
    }
    
    // Backtrack to print diff
    printDiff(C, f1, f2, f1.length, f2.length);
}

void printDiff(int[][] C, string[] f1, string[] f2, size_t i, size_t j) {
    if (i > 0 && j > 0 && f1[i-1] == f2[j-1]) {
        printDiff(C, f1, f2, i-1, j-1);
        // writeln("  ", f1[i-1]); // Same
    } else if (j > 0 && (i == 0 || C[i][j-1] >= C[i-1][j])) {
        printDiff(C, f1, f2, i, j-1);
        writeln("> ", f2[j-1]);
    } else if (i > 0 && (j == 0 || C[i][j-1] < C[i-1][j])) {
        printDiff(C, f1, f2, i-1, j);
        writeln("< ", f1[i-1]);
    }
}
