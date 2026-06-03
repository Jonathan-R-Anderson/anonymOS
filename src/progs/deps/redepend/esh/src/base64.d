module base64;

import std.stdio;
import std.conv;
import std.algorithm : startsWith;
import std.string : toStringz;
import std.array : appender;
import shell.syscalls;

immutable string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Library function for interpreter.d
string base64Encode(const(ubyte)[] data, size_t wrap = 76) {
    auto result = appender!string();
    uint buffer = 0;
    int bits = 0;
    size_t col = 0;
    foreach(b; data) {
        buffer = (buffer << 8) | b;
        bits += 8;
        while(bits >= 6) {
            auto idx = (buffer >> (bits - 6)) & 63;
            result.put(alphabet[idx]);
            bits -= 6;
            col++;
            if (wrap > 0 && col >= wrap) {
                result.put("\n");
                col = 0;
            }
        }
    }
    if(bits > 0) {
        buffer <<= (6 - bits);
        auto idx = buffer & 63;
        result.put(alphabet[idx]);
        if(bits == 2) result.put("==");
        else if(bits == 4) result.put("=");
    }
    return result.data;
}

// Library function for interpreter.d
ubyte[] base64Decode(string input, bool strict = false) {
    // Simplified decode - ignores strict
    ubyte[] result;
    uint val = 0;
    int valb = -8;
    foreach(c; input) {
        if (c >= 256 || decodeParams[c] == 255) continue;
        val = (val << 6) | decodeParams[c];
        valb += 6;
        if (valb >= 0) {
            result ~= cast(ubyte)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return result; 
}


immutable ubyte[256] decodeParams = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62, 255, 255, 255, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255, 255, 255, 255, 255, 255,
    255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255,
    255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
];

void encode(int fdIn, int fdOut, size_t wrap) {
    ubyte[3] inBuf;
    ubyte[4] outBuf;
    long nread;
    int bufPos = 0;
    size_t col = 0;

    ubyte[1] byteBuf;
    while ((nread = sys_read(fdIn, byteBuf.ptr, 1)) > 0) {
        inBuf[bufPos++] = byteBuf[0];
        if (bufPos == 3) {
            outBuf[0] = alphabet[(inBuf[0] >> 2) & 0x3F];
            outBuf[1] = alphabet[((inBuf[0] & 0x3) << 4) | ((inBuf[1] >> 4) & 0xF)];
            outBuf[2] = alphabet[((inBuf[1] & 0xF) << 2) | ((inBuf[2] >> 6) & 0x3)];
            outBuf[3] = alphabet[inBuf[2] & 0x3F];
            sys_write(fdOut, outBuf.ptr, 4);
            bufPos = 0;
            col += 4;
            if (wrap > 0 && col >= wrap) {
                sys_write(fdOut, "\n".ptr, 1);
                col = 0;
            }
        }
    }

    if (bufPos > 0) {
        outBuf[0] = alphabet[(inBuf[0] >> 2) & 0x3F];
        if (bufPos == 1) {
            outBuf[1] = alphabet[((inBuf[0] & 0x3) << 4)];
            outBuf[2] = '=';
            outBuf[3] = '=';
        } else {
            outBuf[1] = alphabet[((inBuf[0] & 0x3) << 4) | ((inBuf[1] >> 4) & 0xF)];
            outBuf[2] = alphabet[((inBuf[1] & 0xF) << 2)];
            outBuf[3] = '=';
        }
        sys_write(fdOut, outBuf.ptr, 4);
        col += 4;
    }
    if (col > 0) sys_write(fdOut, "\n".ptr, 1);
}

void decode(int fdIn, int fdOut) {
    uint val = 0;
    int valb = -8;
    long nread;
    ubyte[1] byteBuf;
    
    while ((nread = sys_read(fdIn, byteBuf.ptr, 1)) > 0) {
        ubyte c = byteBuf[0];
        if (decodeParams[c] == 255) continue;
        val = (val << 6) | decodeParams[c];
        valb += 6;
        if (valb >= 0) {
            ubyte outB = cast(ubyte)((val >> valb) & 0xFF);
            sys_write(fdOut, &outB, 1);
            valb -= 8;
        }
    }
}

void base64Command(string[] tokens) {
    bool doDecode = false;
    size_t wrap = 76;
    size_t idx = 1;
    string inFile;

    while (idx < tokens.length && tokens[idx].startsWith("-")) {
        auto t = tokens[idx];
        if (t == "-d" || t == "--decode") doDecode = true;
        else if (t.startsWith("-w")) {
            if (t.length > 2) wrap = to!size_t(t[2..$]);
            else if (idx + 1 < tokens.length) wrap = to!size_t(tokens[++idx]);
        }
        else if (t == "--") { idx++; break; }
        else { break; }
        idx++;
    }

    if (idx < tokens.length) inFile = tokens[idx];

    int fdIn = 0; // stdin
    if (inFile.length > 0 && inFile != "-") {
        fdIn = cast(int)sys_open(inFile.toStringz, 0);
        if (fdIn < 0) {
            writeln("base64: cannot open ", inFile);
            return;
        }
    }

    if (doDecode) decode(fdIn, 1);
    else encode(fdIn, 1, wrap);

    if (fdIn != 0) sys_close(fdIn);
}
