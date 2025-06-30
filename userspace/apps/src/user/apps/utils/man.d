import std.stdio;
import std.file;
import std.path;
import std.getopt;
import std.zlib;

string[] sections = ["1", "2", "3", "4", "5", "6", "7", "8"]; // default search

string readManFile(string name) {
    foreach (sec; sections) {
        auto base = "/usr/share/man/man" ~ sec ~ "/" ~ name ~ "." ~ sec;
        if (exists(base ~ ".gz")) {
            auto comp = read(base ~ ".gz");
            auto decoded = cast(string)uncompress(comp);
            return decoded;
        } else if (exists(base)) {
            return cast(string)readText(base);
        }
    }
    return "";
}

void main(string[] args) {
    string section;
    auto res = getopt(args, "s|section", &section);
    if (res.helpWanted || res.errors.length || res.rest.length == 0) {
        writeln("Usage: man [-s section] NAME");
        return;
    }
    string name = res.rest[0];
    if (section.length) sections = [section];

    auto text = readManFile(name);
    if (text.length == 0) {
        stderr.writeln("man: no entry for ", name);
        return;
    }
    writeln(text);
}
