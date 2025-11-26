module base64;

import std.array : appender, Appender;
import std.string : toLower;

immutable string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

string base64Encode(const(ubyte)[] data, size_t wrap = 76)
{
    auto result = appender!string();
    uint buffer = 0;
    int bits = 0;
    size_t line = 0;
    foreach(b; data) {
        buffer = (buffer << 8) | b;
        bits += 8;
        while(bits >= 6) {
            auto idx = (buffer >> (bits - 6)) & 63;
            result.put(alphabet[idx]);
            bits -= 6;
            line++;
            if(wrap > 0 && line >= wrap) {
                result.put('\n');
                line = 0;
            }
        }
    }
    if(bits > 0) {
        buffer <<= (6 - bits);
        auto idx = buffer & 63;
        result.put(alphabet[idx]);
        line++;
        if(wrap > 0 && line >= wrap) {
            result.put('\n');
            line = 0;
        }
    }
    while(line % 4 != 0) {
        result.put('=');
        line++;
        if(wrap > 0 && line >= wrap) {
            result.put('\n');
            line = 0;
        }
    }
    return result.data;
}

ubyte[] base64Decode(string data, bool ignoreGarbage = false)
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
        buffer = (buffer << 6) | cast(uint)idx;
        bits += 6;
        if(bits >= 8) {
            auto bval = (buffer >> (bits - 8)) & 0xFF;
            result.put(cast(ubyte)bval);
            bits -= 8;
        }
    }
    return result.data;
}

