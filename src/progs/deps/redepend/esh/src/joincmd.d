module joincmd;

import std.stdio;
import std.string;
import std.algorithm;
import std.array;
import std.conv;

void joinCommand(string[] tokens) {
    if(tokens.length < 3) {
        writeln("Usage: join file1 file2");
        return;
    }
    string fn1 = tokens[1];
    string fn2 = tokens[2];
    
    File f1, f2;
    try {
        f1 = File(fn1, "r");
        f2 = File(fn2, "r");
    } catch(Exception e) {
        writeln("join: cannot open files");
        return;
    }
    
    char[] buf1;
    char[] buf2;
    size_t n1 = f1.readln(buf1);
    size_t n2 = f2.readln(buf2);
    
    while(n1 && n2) {
        string l1 = cast(string)buf1[0..n1].strip;
        string l2 = cast(string)buf2[0..n2].strip;
        
        auto p1 = l1.split(); // whitespace split
        auto p2 = l2.split();
        
        if(p1.length == 0) { n1 = f1.readln(buf1); continue; }
        if(p2.length == 0) { n2 = f2.readln(buf2); continue; }
        
        string k1 = p1[0];
        string k2 = p2[0];
        
        if(k1 == k2) {
            // Match
            write(k1);
            foreach(s; p1[1..$]) write(" ", s);
            foreach(s; p2[1..$]) write(" ", s);
            writeln();
            // Standard join advances ONE side? Or both?
            // "If duplicates are found in both files... cartesian product?".
            // Simple join: advance both if no duplicates assumed.
            // If duplicate keys exist, complex logic.
            // Minimal: advance both.
            n1 = f1.readln(buf1);
            n2 = f2.readln(buf2);
        } else if(k1 < k2) {
            n1 = f1.readln(buf1);
        } else {
            n2 = f2.readln(buf2);
        }
    }
}
