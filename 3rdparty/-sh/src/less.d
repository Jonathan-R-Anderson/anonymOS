module less;

import std.stdio;
import std.file : readText;
import std.algorithm : min;
import std.string : splitLines, strip;

/// Very small pager implementation.
void lessCommand(string[] tokens)
{
    if(tokens.length < 2) {
        writeln("less: missing file operand");
        return;
    }
    string file = tokens[1];
    size_t window = 20;
    try {
        auto lines = readText(file).splitLines;
        size_t idx = 0;
        while(idx < lines.length) {
            auto end = min(lines.length, idx + window);
            foreach(line; lines[idx .. end])
                writeln(line);
            idx = end;
            if(idx >= lines.length) break;
            write("--More--");
            auto inp = readln();
            if(inp is null) break;
            inp = inp.strip;
            if(inp.length && (inp[0] == 'q' || inp[0] == 'Q'))
                break;
        }
    } catch(Exception) {
        writeln("less: cannot read ", file);
    }
}

