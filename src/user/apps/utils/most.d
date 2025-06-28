import std.stdio;
import std.array;
import std.getopt;

void display(string[] lines, bool squeeze, string name="") {
    enum screenSize = 24;
    size_t idx = 0;
    if(name.length) writeln(":::::::::::::: " ~ name ~ " ::::::::::::::");
    while (idx < lines.length) {
        auto end = idx + screenSize;
        if (end > lines.length) end = lines.length;
        string lastBlank;
        foreach (line; lines[idx .. end]) {
            if (squeeze && line.strip.length == 0) {
                if (lastBlank.length) continue;
                lastBlank = line;
            } else {
                lastBlank = "";
            }
            writeln(line);
        }
        idx = end;
        if (idx >= lines.length) break;
        write("--More--");
        stdout.flush();
        auto ch = getchar();
        if (ch == 'q' || ch == 'Q') break;
    }
}

void main(string[] args) {
    bool squeeze = false;
    auto res = getopt(args, "s", &squeeze);
    if (res.helpWanted || res.rest.length == 0) {
        writeln("Usage: most [-s] FILE...");
        return;
    }
    foreach (file; res.rest) {
        try {
            auto lines = File(file).byLineCopy.array;
            display(lines, squeeze, file);
        } catch (Exception e) {
            stderr.writeln("most: cannot open ", file);
        }
    }
}
