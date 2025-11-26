module diff;

import std.stdio;
import std.file : readText;
import std.string : splitLines, toLower, strip, join, split, startsWith;
import std.algorithm : max, map;
import std.array : array;

struct DiffOp {
    char tag; // ' ' for same, '-' removed from first, '+' added in second
    string line;
}

string[] readLines(string name)
{
    string[] lines;
    if(name == "-") {
        foreach(line; stdin.byLine())
            lines ~= line.idup;
    } else {
        try {
            lines = readText(name).splitLines();
        } catch(Exception) {
            writeln("diff: cannot read " ~ name);
        }
    }
    return lines;
}

string normalize(string line, bool ignoreCase, bool ignoreSpace, bool ignoreBlank)
{
    auto l = line;
    if(ignoreSpace)
        l = l.split().join(" ").strip;
    if(ignoreBlank && l.length == 0)
        l = "";
    if(ignoreCase)
        l = toLower(l);
    return l;
}

DiffOp[] buildDiff(string[] a, string[] b,
                  bool ignoreCase=false,
                  bool ignoreSpace=false,
                  bool ignoreBlank=false)
{
    auto an = a.map!(l => normalize(l, ignoreCase, ignoreSpace, ignoreBlank)).array;
    auto bn = b.map!(l => normalize(l, ignoreCase, ignoreSpace, ignoreBlank)).array;

    size_t n = an.length;
    size_t m = bn.length;
    auto dp = new size_t[][](n+1, m+1);
    foreach(i; 0..n) {
        foreach(j; 0..m) {
            if(i==0 || j==0)
                dp[i][j] = 0;
        }
    }
    for(size_t i=0;i<n;i++) {
        for(size_t j=0;j<m;j++) {
            if(an[i] == bn[j])
                dp[i+1][j+1] = dp[i][j]+1;
            else
                dp[i+1][j+1] = max(dp[i+1][j], dp[i][j+1]);
        }
    }

    DiffOp[] ops;
    void backtrack(size_t i, size_t j) {
        if(i>0 && j>0 && an[i-1] == bn[j-1]) {
            backtrack(i-1, j-1);
            ops ~= DiffOp(' ', a[i-1]);
        } else if(j>0 && (i==0 || dp[i][j-1] >= dp[i-1][j])) {
            backtrack(i, j-1);
            ops ~= DiffOp('+', b[j-1]);
        } else if(i>0) {
            backtrack(i-1, j);
            ops ~= DiffOp('-', a[i-1]);
        }
    }
    backtrack(n, m);
    return ops;
}

void diffFiles(string f1, string f2,
               bool brief=false,
               bool reportSame=false,
               bool ignoreCase=false,
               bool ignoreSpace=false,
               bool ignoreBlank=false,
               bool unified=false)
{
    auto a = readLines(f1);
    auto b = readLines(f2);
    auto ops = buildDiff(a, b, ignoreCase, ignoreSpace, ignoreBlank);

    bool different = false;
    foreach(op; ops) if(op.tag != ' ') { different = true; break; }

    if(brief) {
        if(different)
            writeln("Files " ~ f1 ~ " and " ~ f2 ~ " differ");
        else if(reportSame)
            writeln("Files " ~ f1 ~ " and " ~ f2 ~ " are identical");
        return;
    }

    if(!different) {
        if(reportSame)
            writeln("Files " ~ f1 ~ " and " ~ f2 ~ " are identical");
        return;
    }

    if(unified) {
        writeln("--- " ~ f1);
        writeln("+++ " ~ f2);
    }

    foreach(op; ops) {
        switch(op.tag) {
            case ' ': if(unified) writeln(" " ~ op.line); break;
            case '+': writeln(unified?"+" ~ op.line:"> " ~ op.line); break;
            case '-': writeln(unified?"-" ~ op.line:"< " ~ op.line); break;
            default: break;
        }
    }
}

void diffCommand(string[] tokens)
{
    bool brief = false;
    bool reportSame = false;
    bool ignoreCase = false;
    bool ignoreSpace = false;
    bool ignoreBlank = false;
    bool unified = false;
    int idx = 1;
    while(idx < tokens.length && tokens[idx].startsWith("-")) {
        auto t = tokens[idx];
        if(t == "-q" || t == "--brief") brief = true;
        else if(t == "-s" || t == "--report-identical-files") reportSame = true;
        else if(t == "-i" || t == "--ignore-case") ignoreCase = true;
        else if(t == "-w" || t == "--ignore-all-space") ignoreSpace = true;
        else if(t == "-B" || t == "--ignore-blank-lines") ignoreBlank = true;
        else if(t.startsWith("-u")) unified = true;
        else if(t.startsWith("--unified")) unified = true;
        else if(t == "--") { idx++; break; }
        else break;
        idx++;
    }
    if(idx + 2 != tokens.length) {
        if(idx >= tokens.length-1) {
            writeln("Usage: diff [OPTION]... FILE1 FILE2");
            return;
        }
    }
    if(idx >= tokens.length) {
        writeln("Usage: diff [OPTION]... FILE1 FILE2");
        return;
    }
    string f1 = tokens[idx];
    string f2 = (idx + 1 < tokens.length) ? tokens[idx+1] : "-";
    diffFiles(f1, f2, brief, reportSame, ignoreCase, ignoreSpace, ignoreBlank, unified);
}

