module diff3;

import std.stdio;
import std.string : splitLines, toStringz;
import shell.syscalls;

string[] readLines(string name) {
    if (name == "-") {
        // Stdin. For now returns empty or TODO. 
        // Or implement stdin reading via sys_read(0).
        string content;
        ubyte[1024] buf;
        long n;
        while((n = sys_read(0, buf.ptr, 1024)) > 0) {
            content ~= cast(string)buf[0..n];
        }
        return content.splitLines();
    }
    
    auto fd = sys_open(name.toStringz, 0);
    if (fd < 0) {
        writeln("diff3: cannot read ", name);
        return [];
    }
    
    string content;
    ubyte[4096] buf;
    long n;
    while((n = sys_read(cast(int)fd, buf.ptr, 4096)) > 0) {
        content ~= cast(string)buf[0..n];
    }
    sys_close(cast(int)fd);
    
    return content.splitLines();
}

void mergeFiles(string myfile, string oldfile, string yourfile) {
    auto my = readLines(myfile);
    auto old = readLines(oldfile);
    auto your = readLines(yourfile);

    size_t i=0, j=0, k=0;
    while(i < old.length || j < my.length || k < your.length) {
        if(i < old.length) {
            auto oline = old[i];
            string mline = j < my.length ? my[j] : null;
            string yline = k < your.length ? your[k] : null;

            if(mline == oline && yline == oline) {
                writeln(oline);
                i++; j++; k++;
            } else if(mline == oline && yline !is null && yline != oline) {
                writeln(yline);
                i++; j++; k++;
            } else if(yline == oline && mline !is null && mline != oline) {
                writeln(mline);
                i++; j++; k++;
            } else if(mline !is null && yline !is null && mline == yline) {
                writeln(mline);
                i++; j++; k++;
            } else if(mline !is null && yline !is null) {
                writeln("<<<<<<< MYFILE");
                writeln(mline);
                writeln("||||||| OLDFILE");
                writeln(oline);
                writeln("=======");
                writeln(yline);
                writeln(">>>>>>> YOURFILE");
                i++; j++; k++;
            } else if(mline !is null) {
                writeln(mline);
                i++; j++;
            } else if(yline !is null) {
                writeln(yline);
                i++; k++;
            } else {
                writeln(oline);
                i++;
            }
        } else {
            if(j < my.length && k < your.length) {
                if(my[j] == your[k])
                    writeln(my[j]);
                else {
                    writeln("<<<<<<< MYFILE");
                    writeln(my[j]);
                    writeln("=======");
                    writeln(your[k]);
                    writeln(">>>>>>> YOURFILE");
                }
                j++; k++;
            } else if(j < my.length) {
                writeln(my[j]);
                j++;
            } else if(k < your.length) {
                writeln(your[k]);
                k++;
            }
        }
    }
}

void diff3Command(string[] tokens) {
    if(tokens.length < 4) {
        writeln("Usage: diff3 MYFILE OLDFILE YOURFILE");
        return;
    }
    mergeFiles(tokens[1], tokens[2], tokens[3]);
}
