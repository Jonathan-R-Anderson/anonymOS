module comm;

import std.stdio;
import std.file : readText;
import std.string : splitLines;

string[] readLines(string name)
{
    string[] lines;
    if(name == "-") {
        foreach(line; stdin.byLine())
            lines ~= line.idup;
    } else {
        try {
            auto content = readText(name);
            lines = content.splitLines();
        } catch(Exception) {
            writeln("comm: cannot read ", name);
        }
    }
    return lines;
}

bool isSorted(string[] arr)
{
    foreach(i; 1 .. arr.length)
        if(arr[i-1] > arr[i])
            return false;
    return true;
}

string repeatDelim(string d, int n)
{
    string result;
    foreach(i; 0 .. n) result ~= d;
    return result;
}

void commFiles(string f1, string f2, bool s1=false, bool s2=false, bool s3=false,
               bool checkOrder=false, string delim="\t")
{
    auto a = readLines(f1);
    auto b = readLines(f2);
    if(checkOrder) {
        if(!isSorted(a)) { writeln("comm: ", f1, " is not in sorted order"); return; }
        if(!isSorted(b)) { writeln("comm: ", f2, " is not in sorted order"); return; }
    }
    size_t i=0, j=0;
    int pad2 = s1 ? 0 : 1;
    int pad3 = 0; if(!s1) pad3++; if(!s2) pad3++;
    while(i < a.length && j < b.length) {
        auto l1 = a[i];
        auto l2 = b[j];
        int cmp = (l1 < l2) ? -1 : ((l1 > l2) ? 1 : 0);
        if(cmp < 0) {
            if(!s1) writeln(l1);
            i++;
        } else if(cmp > 0) {
            if(!s2) writeln(repeatDelim(delim, pad2) ~ l2);
            j++;
        } else {
            if(!s3) writeln(repeatDelim(delim, pad3) ~ l1);
            i++; j++;
        }
    }
    while(i < a.length) { if(!s1) writeln(a[i]); i++; }
    while(j < b.length) { if(!s2) writeln(repeatDelim(delim, pad2) ~ b[j]); j++; }
}

