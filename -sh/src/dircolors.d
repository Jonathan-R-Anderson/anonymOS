module dircolors;

import std.stdio;
import std.file : readText;
import std.string : splitLines, strip, join, startsWith;
import std.algorithm : filter, map;

immutable string defaultDB = `
# Default color database
DIR 01;34
LINK 01;36
FIFO 40;33
SOCK 01;35
BLK 40;33;01
CHR 40;33;01
ORPHAN 40;31;01
EXEC 01;32
`;

string loadDB(string name)
{
    if(name.length) {
        try { return readText(name); } catch(Exception) {}
    }
    return defaultDB;
}

void dircolorsCommand(string[] tokens)
{
    bool printDB = false;
    string fileName;
    string shellType = "sh";
    size_t idx = 1;
    while(idx < tokens.length && tokens[idx].startsWith("-")) {
        auto t = tokens[idx];
        if(t == "-b" || t == "--sh" || t == "--bourne-shell") shellType = "sh";
        else if(t == "-c" || t == "--csh" || t == "--c-shell") shellType = "csh";
        else if(t == "-p" || t == "--print-database") printDB = true;
        else if(t == "--") { idx++; break; }
        else { idx++; break; }
        idx++;
    }
    if(idx < tokens.length)
        fileName = tokens[idx];

    auto db = loadDB(fileName);
    if(printDB) {
        writeln(db);
        return;
    }
    auto entries = db.splitLines()
        .map!(l => l.strip)
        .filter!(l => l.length && l[0] != '#')
        .join(":");
    if(shellType == "csh")
        writeln("setenv LS_COLORS \"" ~ entries ~ "\"");
    else
        writeln("LS_COLORS=\"" ~ entries ~ "\"; export LS_COLORS");
}

