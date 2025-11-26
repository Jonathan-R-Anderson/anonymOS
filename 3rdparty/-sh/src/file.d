module file;

import std.stdio;
import std.file : read, exists, isDir;

bool isText(ubyte[] buf) {
    foreach(b; buf) {
        if(b == 0 || (b < 32 && b != 9 && b != 10 && b != 13))
            return false;
    }
    return true;
}

void fileCommand(string[] tokens) {
    if(tokens.length < 2) {
        writeln("Usage: file file...");
        return;
    }
    foreach(path; tokens[1 .. $]) {
        string result;
        if(!exists(path)) {
            writeln(path, ": cannot open");
            continue;
        }
        if(isDir(path)) {
            result = "directory";
        } else {
            try {
                auto data = cast(ubyte[])read(path);
                if(data.length == 0)
                    result = "empty";
                else if(data.length >= 4 && data[0] == 0x7F && data[1]=='E' && data[2]=='L' && data[3]=='F')
                    result = "ELF executable";
                else if(isText(data))
                    result = "ASCII text";
                else
                    result = "data";
            } catch(Exception) {
                result = "cannot read";
            }
        }
        writeln(path, ": ", result);
    }
}

