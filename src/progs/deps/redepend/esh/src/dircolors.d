module dircolors;

import std.stdio;
import std.string;
import std.array;
import shell.syscalls;

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

string loadDB(string name) {
    if(name.length == 0) return defaultDB;
    auto fd = sys_open(name.toStringz, 0);
    if(fd < 0) return defaultDB;
    
    ubyte[4096] buf;
    long n;
    string content;
    while((n = sys_read(cast(int)fd, buf.ptr, 4096)) > 0)
        content ~= cast(string)buf[0..n];
    sys_close(cast(int)fd);
    return content;
}

void dircolorsCommand(string[] tokens) {
    bool printDB = false;
    bool csh = false;
    bool bourne = true;
    string file;
    
    foreach(t; tokens[1..$]) {
        if(t == "-p" || t == "--print-database") printDB = true;
        else if(t == "-c" || t == "--csh" || t == "--c-shell") { csh = true; bourne = false; }
        else if(t == "-b" || t == "--sh" || t == "--bourne-shell") { bourne = true; csh = false; }
        else if(!t.startsWith("-")) file = t;
    }
    
    if(printDB) {
        writeln(defaultDB);
        return;
    }
    
    string db = loadDB(file);
    string lsColors;
    
    foreach(line; db.splitLines) {
        auto part = line.strip;
        if(part.length == 0 || part[0] == '#') continue;
        auto kv = part.split();
        if(kv.length >= 2) {
            string key = kv[0];
            string val = kv[1];
            // key map (simplified)
            if(key == "DIR") lsColors ~= "di=" ~ val ~ ":";
            else if(key == "LINK") lsColors ~= "ln=" ~ val ~ ":";
            else if(key == "FIFO") lsColors ~= "pi=" ~ val ~ ":";
            else if(key == "SOCK") lsColors ~= "so=" ~ val ~ ":";
            else if(key == "BLK") lsColors ~= "bd=" ~ val ~ ":";
            else if(key == "CHR") lsColors ~= "cd=" ~ val ~ ":";
            else if(key == "ORPHAN") lsColors ~= "or=" ~ val ~ ":";
            else if(key == "EXEC") lsColors ~= "*" ~ val ~ ":"; // not quite right, exec usually by extension
        }
    }
    
    if (bourne) {
        writeln("LS_COLORS='", lsColors, "';");
        writeln("export LS_COLORS");
    } else {
        writeln("setenv LS_COLORS '", lsColors, "'");
    }
}
