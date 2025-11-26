module expand;

import std.stdio;
import std.file : readText;
import std.string : split, replace, splitLines, startsWith;
import std.conv : to;
import std.array : appender, Appender;
import std.ascii : isDigit;

int[] parseStops(string spec) {
    spec = replace(spec, ",", " ");
    int[] stops;
    foreach(part; spec.split()) {
        try { stops ~= to!int(part); } catch(Exception) {}
    }
    return stops;
}

int spacesFor(size_t col, int[] stops) {
    if(stops.length <= 1) {
        int width = stops.length ? stops[0] : 8;
        return width - cast(int)(col % width);
    }
    foreach(s; stops) {
        if(col < s) return s - cast(int)col;
    }
    return 1;
}

string expandLine(string line, int[] stops, bool initialOnly) {
    auto builder = appender!string();
    size_t col = 0;
    bool initial = true;
    foreach(ch; line) {
        if(ch == '\b') {
              builder.put(ch);
            if(col > 0) col--; 
            continue;
        }
        if(ch == '\t') {
            if(initialOnly && !initial) {
                  builder.put(ch);
            } else {
                int n = spacesFor(col, stops);
                  foreach(i; 0 .. n) builder.put(' ');
                col += n;
            }
        } else {
              builder.put(ch);
            col++;
            if(ch != ' ' && ch != '\t') initial = false;
        }
    }
      return builder.data;
}

void expandFile(string name, int[] stops, bool initialOnly) {
    if(name == "-") {
        foreach(line; stdin.byLine())
            writeln(expandLine(line.idup, stops, initialOnly));
    } else {
        try {
            foreach(line; readText(name).splitLines())
                writeln(expandLine(line, stops, initialOnly));
        } catch(Exception) {
            writeln("expand: cannot read ", name);
        }
    }
}

void expandCommand(string[] tokens) {
    bool initial = false;
    int[] stops;
    size_t idx = 1;
    while(idx < tokens.length && tokens[idx].startsWith("-")) {
        auto t = tokens[idx];
        if(t == "-i" || t == "--initial") {
            initial = true;
        } else if(t.startsWith("-t")) {
            string s = t.length > 2 ? t[2..$] : (idx+1 < tokens.length ? tokens[++idx] : "");
            if(s.length) stops = parseStops(s);
        } else if(t.startsWith("--tabs=")) {
            stops = parseStops(t[7..$]);
        } else if(t.length > 1 && t[1].isDigit) {
            stops = parseStops(t[1..$]);
        } else if(t == "--") { idx++; break; } else { break; }
        idx++;
    }
    if(stops.length == 0) stops = [8];
    auto files = tokens[idx .. $];
    if(files.length == 0) files = ["-"];
    foreach(f; files) expandFile(f, stops, initial);
}

