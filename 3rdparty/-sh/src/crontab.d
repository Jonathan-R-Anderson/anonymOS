module crontab;

import std.stdio;
import std.file : readText, write, exists, remove;
import std.process : environment;
import syswrap : system;
import std.string : startsWith;

void editFile(string path)
{
    string editor;
    if(auto e = environment.get("VISUAL"))
        editor = e;
    else if(auto e2 = environment.get("EDITOR"))
        editor = e2;
    else
        editor = "vi";
    system(editor ~ " " ~ path);
}

void installFile(string src, string dest)
{
    try {
        auto text = readText(src);
        write(dest, text);
    } catch(Exception) {
        writeln("crontab: cannot read " ~ src);
    }
}

void crontabCommand(string[] args)
{
    string path = "crontab";
    bool listFlag = false;
    bool removeFlag = false;
    bool editFlag = false;

    size_t idx = 1;
    while(idx < args.length && args[idx].startsWith("-")) {
        auto t = args[idx];
        if(t == "-l") {
            listFlag = true;
        } else if(t == "-r") {
            removeFlag = true;
        } else if(t == "-e") {
            editFlag = true;
        } else if(t == "-u") {
            idx++; // skip user name
        }
        idx++;
    }

    string file;
    if(idx < args.length)
        file = args[idx];

    if(listFlag) {
        if(exists(path))
            writeln(readText(path));
        return;
    }
    if(removeFlag) {
        if(exists(path)) remove(path);
        return;
    }
    if(editFlag) {
        if(!exists(path)) write(path, "");
        editFile(path);
        return;
    }
    if(file.length) {
        installFile(file, path);
        return;
    }

    writeln("Usage: crontab [-l|-r|-e] [file]");
}

