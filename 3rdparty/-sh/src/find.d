module find;

import std.stdio;
import std.file : dirEntries, SpanMode, isFile, isDir;
import std.path : baseName, buildPath;
import std.algorithm : startsWith;
import std.path : globMatch;
import std.conv : to;

void search(string path, string pattern, bool usePattern, char ftype, int depth, int maxDepth)
{
    foreach(entry; dirEntries(path, SpanMode.shallow))
    {
        string name = entry.name;
        // match base name against pattern if provided
        bool match = true;
        if(usePattern)
            match = globMatch(baseName(name), pattern);
        if(match && ftype)
        {
            if(ftype == 'f' && !entry.isFile)
                match = false;
            else if(ftype == 'd' && !entry.isDir)
                match = false;
        }
        if(match)
            writeln(name);
        // recurse into directories
        if(entry.isDir && (maxDepth < 0 || depth < maxDepth))
            search(name, pattern, usePattern, ftype, depth+1, maxDepth);
    }
}

/// Very small subset of GNU find supporting -name, -type and -maxdepth
void findCommand(string[] tokens)
{
    string start = ".";
    string pattern;
    bool usePattern = false;
    char ftype = '\0';
    int maxDepth = -1; // unlimited

    size_t idx = 1;
    if(idx < tokens.length && !tokens[idx].startsWith("-"))
    {
        start = tokens[idx];
        idx++;
    }
    while(idx < tokens.length)
    {
        auto t = tokens[idx];
        if(t == "-name" && idx + 1 < tokens.length)
        {
            pattern = tokens[idx+1];
            usePattern = true;
            idx += 2;
        }
        else if(t == "-type" && idx + 1 < tokens.length)
        {
            ftype = tokens[idx+1][0];
            idx += 2;
        }
        else if(t == "-maxdepth" && idx + 1 < tokens.length)
        {
            maxDepth = to!int(tokens[idx+1]);
            idx += 2;
        }
        else
        {
            idx++;
        }
    }
    search(start, pattern, usePattern, ftype, 0, maxDepth);
}

