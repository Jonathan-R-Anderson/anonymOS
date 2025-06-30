import std.stdio;
import std.digest.md;
import std.file;
import std.path;

string digestFile(string path) {
    auto data = read(path);
    auto ctx = MD5Digest();
    ctx.put(data);
    auto hash = ctx.finish();
    return hash.toHexString();
}

void main(string[] args) {
    if (args.length == 1) {
        auto data = cast(ubyte[])stdin.readAll();
        auto ctx = MD5Digest();
        ctx.put(data);
        auto hash = ctx.finish();
        writeln(hash.toHexString(), "  -");
        return;
    }

    foreach (file; args[1..$]) {
        try {
            auto hex = digestFile(file);
            writeln(hex, "  ", file);
        } catch (Exception e) {
            stderr.writeln("md5sum: ", e.msg);
        }
    }
}
