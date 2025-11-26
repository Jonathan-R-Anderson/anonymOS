module dos2unix;

import std.stdio;
import std.file : readText, write;
import std.string : replace, startsWith;

void convertFile(string inFile, string outFile, bool keepDate, bool quiet)
{
    string text;
    try {
        text = readText(inFile);
    } catch(Exception) {
        if(!quiet) writeln("dos2unix: cannot read ", inFile);
        return;
    }
    text = replace(text, "\r\n", "\n");
    text = replace(text, "\r", "\n");
    try {
        write(outFile, text);
    } catch(Exception) {
        if(!quiet) writeln("dos2unix: cannot write ", outFile);
    }
}

void convertStream()
{
    foreach(line; stdin.byLine()) {
        string l = line.idup;
        l = replace(l, "\r", "");
        writeln(l);
    }
}

void dos2unixCommand(string[] tokens)
{
    bool keepDate = false;
    bool quiet = false;
    bool newMode = false;
    size_t idx = 1;
    while(idx < tokens.length && tokens[idx].startsWith("-")) {
        auto t = tokens[idx];
        if(t == "-k" || t == "--keepdate") { keepDate = true; }
        else if(t == "-q" || t == "--quiet") { quiet = true; }
        else if(t == "-n" || t == "--newfile") { newMode = true; idx++; break; }
        else if(t == "-o" || t == "--oldfile") { idx++; break; }
        else if(t == "-h" || t == "--help") {
            writeln("Usage: dos2unix [OPTIONS] [FILE]...");
            return;
        }
        else if(t == "--") { idx++; break; }
        else { break; }
        idx++;
    }
    if(newMode) {
        while(idx + 1 < tokens.length) {
            auto inFile = tokens[idx];
            auto outFile = tokens[idx+1];
            convertFile(inFile, outFile, keepDate, quiet);
            idx += 2;
        }
    } else {
        if(idx >= tokens.length) {
            convertStream();
        } else {
            foreach(f; tokens[idx .. $])
                convertFile(f, f, keepDate, quiet);
        }
    }
}

