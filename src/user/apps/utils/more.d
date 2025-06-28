import std.stdio;
import std.array;

void display(string[] lines, string name="") {
    enum screenSize = 24;
    size_t idx = 0;
    if(name.length) writeln(":::::::::::::: " ~ name ~ " ::::::::::::::");
    while (idx < lines.length) {
        auto end = idx + screenSize;
        if (end > lines.length) end = lines.length;
        foreach (line; lines[idx .. end]) {
            writeln(line);
        }
        idx = end;
        if (idx >= lines.length) break;
        write("[Press space to continue, 'q' to quit.]");
        stdout.flush();
        auto ch = getchar();
        if (ch == 'q' || ch == 'Q') break;
    }
}

void main(string[] args) {
    if (args.length == 1) {
        auto lines = stdin.byLineCopy.array;
        display(lines);
        return;
    }
    foreach (file; args[1 .. $]) {
        try {
            auto lines = File(file).byLineCopy.array;
            display(lines, file);
        } catch (Exception e) {
            stderr.writeln("more: cannot open ", file);
        }
    }
}
