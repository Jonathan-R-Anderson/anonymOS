module md5sum;

import std.stdio;
import std.file : read;
import std.digest.md;
import std.format : format;

string hexDigest(const(ubyte)[] data)
{
    auto ctx = MD5();
    ctx.put(data);
    auto dg = ctx.finish();
    import std.array : appender;
    auto app = appender!string();
    foreach(byte b; dg)
        app.put(format("%02x", b));
    return app.data;
}

void md5sumFile(string name)
{
    try
    {
        auto bytes = read(name);
        auto digest = hexDigest(cast(const(ubyte)[])bytes);
        writeln(digest, "  ", name);
    }
    catch(Exception)
    {
        writeln("md5sum: cannot read ", name);
    }
}

void md5sumStdin()
{
    ubyte[] data;
    foreach(chunk; stdin.byChunk(4096))
        data ~= cast(ubyte[])chunk;
    auto digest = hexDigest(data);
    writeln(digest, "  -");
}

void md5sumCommand(string[] tokens)
{
    auto files = tokens.length > 1 ? tokens[1 .. $] : null;
    if(files.length == 0)
    {
        md5sumStdin();
        return;
    }
    foreach(f; files)
    {
        if(f == "-")
            md5sumStdin();
        else
            md5sumFile(f);
    }
}

