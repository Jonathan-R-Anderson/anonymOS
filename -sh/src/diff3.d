module diff3;

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
            lines = readText(name).splitLines();
        } catch(Exception) {
            writeln("diff3: cannot read " ~ name);
        }
    }
    return lines;
}

void mergeFiles(string myfile, string oldfile, string yourfile)
{
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

void diff3Command(string[] tokens)
{
    if(tokens.length < 4) {
        writeln("Usage: diff3 MYFILE OLDFILE YOURFILE");
        return;
    }
    auto myfile = tokens[1];
    auto oldfile = tokens[2];
    auto yourfile = tokens[3];
    mergeFiles(myfile, oldfile, yourfile);
}

