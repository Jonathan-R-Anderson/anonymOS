/**
 * cksum_d - POSIX cksum in D
 *
 * Behavior:
 *  - Computes the POSIX CRC-32 (poly 0x04C11DB7, non-reflected, init 0),
 *    then "appends" the file length by feeding its low-order bytes and
 *    finally bitwise-not (~) the accumulator.
 *  - Prints "crc bytes" for stdin, or "crc bytes filename" for files.
 *
 * Usage:
 *   cksum_d             # reads stdin
 *   cksum_d file1 ...
 *   cksum_d - file1 ... # "-" means stdin
 */

module cksum_d;

import std.stdio : File, stdin, writeln, stderr;
import std.file : exists, isDir;
import std.string : fromStringz;
import std.conv : to;
import std.exception : enforce;
import core.stdc.errno : errno;
import core.stdc.string : strerror;

alias u32 = uint;
alias u64 = ulong;

enum size_t BUF_SZ = 8192;

/// POSIX cksum polynomial (non-reflected form)
enum u32 POLY = 0x04C11DB7u;

/// Build the POSIX cksum CRC table (non-reflected, MSB-first)
private immutable u32[256] CRC_TABLE = generateCrcTable();

private u32[256] generateCrcTable() @safe @nogc nothrow
{
    u32[256] t;
    foreach (i; 0 .. 256)
    {
        u32 c = cast(u32)i << 24;
        foreach (_; 0 .. 8)
        {
            // MSB-first: test top bit
            if ((c & 0x8000_0000u) != 0)
                c = (c << 1) ^ POLY;
            else
                c <<= 1;
        }
        t[i] = c;
    }
    return t;
}

/// Update CRC with a buffer (POSIX cksum "updcrc")
private u32 updcrc(u32 crc, const(ubyte)[] buf) @safe @nogc nothrow
{
    u32 s = crc;
    foreach (b; buf)
    {
        const idx = ((s >> 24) ^ b) & 0xff;
        s = (s << 8) ^ CRC_TABLE[idx];
    }
    return s;
}

/// Finalize CRC by folding in the length bytes and then bitwise-not (POSIX fincrc)
private u32 fincrc(u32 crc, u64 n) @safe @nogc nothrow
{
    u32 s = crc;
    u64 len = n;
    while (len != 0)
    {
        const c = cast(u32)(len & 0xFF);
        len >>= 8;
        const idx = ((s >> 24) ^ c) & 0xFF;
        s = (s << 8) ^ CRC_TABLE[idx];
    }
    return ~s;
}

private int cksumStream(ref File f, string labelForErrors, bool isStdin)
{
    ubyte[BUF_SZ] buf;
    u64 bytes = 0;
    u32 crc = 0;

    while (true)
    {
        auto n = f.rawRead(buf[]).length;
        if (n == 0)
            break;

        crc = updcrc(crc, buf[0 .. n]);
        bytes += n;
    }

    crc = fincrc(crc, bytes);

    if (isStdin)
        writeln(crc, " ", bytes);
    else
        writeln(crc, " ", bytes, " ", labelForErrors);

    return 0;
}

private int cksumPath(string path)
{
    if (path == "-" || path.length == 0)
    {
        auto f = stdin;
        return cksumStream(f, "<stdin>", true);
    }

    // Basic checks (optional, mirrors typical behavior)
    if (!exists(path))
    {
        auto msg = fromStringz(strerror(errno));
        stderr.writeln(path, ": ", msg);
        return 1;
    }
    if (isDir(path))
    {
        // POSIX cksum on directories varies by system; we match common behavior by erroring.
        stderr.writeln(path, ": Is a directory");
        return 1;
    }

    File f;
    try
    {
        f = File(path, "rb");
    }
    catch (Exception e)
    {
        stderr.writeln(path, ": ", e.msg);
        return 1;
    }

    scope (exit) f.close();
    return cksumStream(f, path, false);
}

int main(string[] args)
{
    int status = 0;

    // No args -> stdin
    if (args.length <= 1)
        return cksumPath("-");

    foreach (i; 1 .. args.length)
        status |= cksumPath(args[i]);

    return status ? 1 : 0;
}
