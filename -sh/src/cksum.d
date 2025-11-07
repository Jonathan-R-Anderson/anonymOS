module cksum;

import std.stdio;
import std.file : read;

private immutable uint[256] crcTable = generateTable();

private immutable(uint[256]) generateTable() {
    uint[256] tab;
    enum uint POLY = 0xEDB88320;
    foreach(i; 0 .. 256) {
        uint c = i;
        foreach(j; 0 .. 8) {
            if(c & 1)
                c = (c >> 1) ^ POLY;
            else
                c >>= 1;
        }
        tab[i] = c;
    }
    return tab;
}

uint cksumBytes(const(ubyte)[] data) {
    uint crc = 0;
    foreach(b; data)
        crc = (crc >> 8) ^ crcTable[(crc ^ b) & 0xFF];
    size_t len = data.length;
    if(len == 0) {
        crc = (crc >> 8) ^ crcTable[crc & 0xFF];
    } else {
        while(len != 0) {
            crc = (crc >> 8) ^ crcTable[(crc ^ (len & 0xFF)) & 0xFF];
            len >>= 8;
        }
    }
    return crc ^ 0xFFFFFFFF;
}

void cksumFile(string name) {
    try {
        auto bytes = cast(ubyte[])read(name);
        auto crc = cksumBytes(bytes);
        writeln(crc, " ", bytes.length, " ", name);
    } catch(Exception) {
        writeln("cksum: cannot read ", name);
    }
}

uint[] cksumStdin() {
    ubyte[] data;
    foreach(chunk; stdin.byChunk(4096)) {
        data ~= cast(ubyte[])chunk;
    }
    auto crc = cksumBytes(data);
    writeln(crc, " ", data.length);
    return [crc, cast(uint)data.length];
}
