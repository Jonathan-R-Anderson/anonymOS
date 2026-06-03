module base32;

import std.array : appender, Appender;
import std.string : toLower;

immutable string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

string base32Encode(const(ubyte)[] data, size_t wrap = 76)
{
    auto result = appender!string();
    uint buffer = 0;
    int bits = 0;
    size_t line = 0;
    foreach(b; data) {
        buffer = (buffer << 8) | b;
        bits += 8;
        while(bits >= 5) {
            auto idx = (buffer >> (bits - 5)) & 31;
            result.put(alphabet[idx]);
            bits -= 5;
            line++;
            if(wrap > 0 && line >= wrap) {
                result.put('\n');
                line = 0;
            }
        }
    }
    if(bits > 0) {
        buffer <<= (5 - bits);
        auto idx = buffer & 31;
        result.put(alphabet[idx]);
        line++;
        if(wrap > 0 && line >= wrap) {
            result.put('\n');
            line = 0;
        }
    }
    while(line % 8 != 0) {
        result.put('=');
        line++;
        if(wrap > 0 && line >= wrap) {
            result.put('\n');
            line = 0;
        }
    }
    return result.data;
}

ubyte[] base32Decode(string data, bool ignoreGarbage = false)
{
    int[256] map;
    map[] = -1;
    foreach(i, ch; alphabet) {
        map[cast(ubyte)ch] = cast(int)i;
        map[cast(ubyte)toLower(ch)] = cast(int)i;
    }

    auto result = appender!(ubyte[])();
    uint buffer = 0;
    int bits = 0;
    foreach(ch; data) {
        if(ch == '=' || ch == '\n' || ch == '\r')
            continue;
        int idx = -1;
        if(cast(size_t)ch < map.length)
            idx = map[cast(ubyte)ch];
        if(idx == -1) {
            if(ignoreGarbage)
                continue;
            else
                break;
        }
        buffer = (buffer << 5) | cast(uint)idx;
        bits += 5;
        if(bits >= 8) {
            auto b = (buffer >> (bits - 8)) & 0xFF;
            result.put(cast(ubyte)b);
            bits -= 8;
        }
    }
    return result.data;
}
