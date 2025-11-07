module awk;

import std.stdio;
import std.file : readText;
import std.regex : regex, matchFirst;
import std.string : split, splitLines, stripRight;
import std.algorithm.searching : canFind;
import std.conv : to;

/// Minimal awk implementation supporting simple print statements.
void awkCommand(string[] tokens)
{
    if(tokens.length < 2) {
        writeln("awk program [file...]");
        return;
    }

    string fs = " ";
    size_t idx = 1;
    if(idx + 1 < tokens.length && tokens[idx] == "-F") {
        fs = tokens[idx + 1];
        idx += 2;
    }
    if(idx >= tokens.length) {
        writeln("awk: missing program");
        return;
    }

    auto program = tokens[idx];
    idx++;
    auto files = tokens[idx .. $];

    if(program.length >= 2 &&
       ((program[0] == '\'' && program[$-1] == '\'') ||
        (program[0] == '"' && program[$-1] == '"')))
        program = program[1 .. $-1];

    auto re = regex(`^\s*(?:(.*?)\s+)?\{\s*print\s*(\$[0-9]+)?\s*\}\s*$`);
    auto m = matchFirst(program, re);
    if(m.empty) {
        writeln("awk: unsupported program");
        return;
    }
    string pattern = m.captures[1];
    string fieldStr = m.captures[2];
    int fieldIdx = 0;
    if(fieldStr.length)
        fieldIdx = to!int(fieldStr[1 .. $]);

    string[] inputLines;
    if(files.length == 0) {
        string line;
        while((line = readln()) !is null) {
            inputLines ~= line.stripRight;
        }
    } else {
        foreach(f; files) {
            try {
                inputLines ~= readText(f).splitLines();
            } catch(Exception e) {
                writeln("awk: cannot read ", f);
            }
        }
    }

    foreach(line; inputLines) {
        auto l = line;
        if(pattern.length == 0 || l.canFind(pattern)) {
            auto fields = l.split(fs);
            if(fieldIdx == 0)
                writeln(l);
            else if(fieldIdx <= cast(int)fields.length)
                writeln(fields[fieldIdx - 1]);
        }
    }
}

