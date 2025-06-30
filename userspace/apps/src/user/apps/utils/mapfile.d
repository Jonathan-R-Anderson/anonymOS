import std.stdio;

void main(string[] args) {
    string[] lines;
    foreach (line; stdin.byLine()) {
        lines ~= line.idup;
    }
    foreach (i, l; lines) {
        writeln(i, ": ", l);
    }
}
