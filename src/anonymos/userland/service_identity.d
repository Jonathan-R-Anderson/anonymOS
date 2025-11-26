module anonymos.userland.service_identity;

import core.stdc.stdlib : malloc, free;
import core.stdc.string : memcpy, memset;
import core.stdc.time : time, time_t;
import std.file : readText;
import std.string : splitLines, strip, startsWith, split, toUpper;
import std.exception : enforce;
import std.conv : to;
import anonymos.userland.crypto : ed25519Verify;

extern (C):

struct ServiceIdentity
{
    char*   service_id;              // e.g. "svc://authd"
    ubyte[32] pub_static_dh;         // X25519 public key
    ubyte[32] pub_sign;              // Ed25519 public key
    ubyte[32] code_hash;             // hash of the binary
    char**  roles;                   // null-terminated array of role strings
    ulong   expires;                 // unix timestamp
    ubyte[64] signature;             // signature by local root/CA
}

// Root/CA Ed25519 public key baked in (replace with real key as needed)
private __gshared immutable ubyte[32] ROOT_PUBKEY = [
    0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,
    0x90,0xA0,0xB0,0xC0,0xD0,0xE0,0xF0,0x01,
    0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,
    0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x11,0x12
];

// Helpers ---------------------------------------------------------------

private ubyte hexValue(char c)
{
    if (c >= '0' && c <= '9') return cast(ubyte)(c - '0');
    if (c >= 'a' && c <= 'f') return cast(ubyte)(10 + c - 'a');
    if (c >= 'A' && c <= 'F') return cast(ubyte)(10 + c - 'A');
    enforce(false, "Invalid hex character");
    assert(0);
}

private void parseHex(const(char)[] hex, ubyte[] outBuf)
{
    enforce(hex.length == outBuf.length * 2, "Hex length mismatch");
    foreach (i; 0 .. outBuf.length)
    {
        ubyte hi = hexValue(hex[i * 2]);
        ubyte lo = hexValue(hex[i * 2 + 1]);
        outBuf[i] = cast(ubyte)((hi << 4) | lo);
    }
}

private string sanitizeId(string id)
{
    auto buf = id.dup;
    foreach (i, ref c; buf)
    {
        if (c == '/' || c == ':') c = '_';
    }
    return buf;
}

private char* dupCString(string s)
{
    auto ptr = cast(char*)malloc(s.length + 1);
    enforce(ptr !is null, "malloc failed");
    if (s.length > 0)
    {
        memcpy(ptr, s.ptr, s.length);
    }
    ptr[s.length] = 0;
    return ptr;
}

private char** dupCStringArray(string[] vals)
{
    // null-terminated array
    auto arr = cast(char**)malloc((vals.length + 1) * (char*).sizeof);
    enforce(arr !is null, "malloc failed");
    foreach (i, v; vals)
    {
        arr[i] = dupCString(v);
    }
    arr[vals.length] = null;
    return arr;
}

// Canonical serialization of the record for signature verification.
private void canonicalize(const ServiceIdentity* id, ref ubyte[] outBuf)
{
    // service_id (null-terminated)
    auto sid = id.service_id ? id.service_id[0 .. std.string.strlen(id.service_id)] : "";
    outBuf ~= cast(const ubyte[])sid;
    outBuf ~= [0];
    outBuf ~= id.pub_static_dh[];
    outBuf ~= id.pub_sign[];
    outBuf ~= id.code_hash[];
    // expires (little endian)
    ubyte[8] exp;
    auto e = id.expires;
    foreach (i; 0 .. 8)
    {
        exp[i] = cast(ubyte)(e & 0xFF);
        e >>= 8;
    }
    outBuf ~= exp[];
    // roles: each null-terminated, then an extra null
    if (id.roles !is null)
    {
        size_t idx = 0;
        while (id.roles[idx] !is null)
        {
            auto r = id.roles[idx];
            auto len = std.string.strlen(r);
            outBuf ~= cast(const ubyte[])(r[0 .. len]);
            outBuf ~= [0];
            ++idx;
        }
    }
    outBuf ~= [0]; // terminator for roles list
}

// API -------------------------------------------------------------------

extern(C) int load_service_identity(const char* service_id, ServiceIdentity* out)
{
    if (service_id is null || out is null) return -1;
    try
    {
        string sid = service_id[0 .. std.string.strlen(service_id)];
        auto fname = "/etc/service_identities/" ~ sanitizeId(sid) ~ ".id";
        auto text = readText(fname);
        string[] roles;
        foreach (lineRaw; text.splitLines())
        {
            auto line = lineRaw.strip();
            if (line.length == 0 || line.startsWith("#")) continue;
            auto parts = line.split("=", 2);
            if (parts.length != 2) continue;
            auto key = parts[0].strip();
            auto val = parts[1].strip();
            final switch (key)
            {
                case "service_id":
                    out.service_id = dupCString(val);
                    break;
                case "pub_static_dh":
                    parseHex(val, out.pub_static_dh[]);
                    break;
                case "pub_sign":
                    parseHex(val, out.pub_sign[]);
                    break;
                case "code_hash":
                    parseHex(val, out.code_hash[]);
                    break;
                case "roles":
                    if (val.length > 0)
                        roles = val.split(",");
                    break;
                case "expires":
                    out.expires = val.to!ulong;
                    break;
                case "signature":
                    parseHex(val, out.signature[]);
                    break;
                default:
                    break;
            }
        }
        out.roles = dupCStringArray(roles);
    }
    catch (Exception)
    {
        return -1;
    }
    return 0;
}

extern(C) int verify_service_identity(const ServiceIdentity* id)
{
    if (id is null) return -1;
    // Check expiry
    time_t now = time(null);
    if (now == -1) return -2;
    if (id.expires != 0 && cast(ulong)now > id.expires) return -3;

    // Build canonical buffer
    ubyte[] buf;
    canonicalize(id, buf);
    if (!ed25519Verify(buf, id.signature, ROOT_PUBKEY))
    {
        return -4;
    }
    return 0;
}
