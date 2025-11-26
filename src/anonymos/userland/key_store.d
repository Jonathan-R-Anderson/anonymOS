module anonymos.userland.key_store;

import core.stdc.string : strlen;
import std.file : readText, exists;
import std.string : strip, replace;
import std.conv : to;
import anonymos.userland.crypto;

@nogc nothrow:

private ubyte hexValue(char c)
{
    if (c >= '0' && c <= '9') return cast(ubyte)(c - '0');
    if (c >= 'a' && c <= 'f') return cast(ubyte)(10 + c - 'a');
    if (c >= 'A' && c <= 'F') return cast(ubyte)(10 + c - 'A');
    return 0xFF;
}

private bool parseHex(const(char)[] hex, ubyte[] outBuf)
{
    if (hex.length != outBuf.length * 2) return false;
    foreach (i; 0 .. outBuf.length)
    {
        ubyte hi = hexValue(hex[i * 2]);
        ubyte lo = hexValue(hex[i * 2 + 1]);
        if (hi == 0xFF || lo == 0xFF) return false;
        outBuf[i] = cast(ubyte)((hi << 4) | lo);
    }
    return true;
}

private string sanitizeId(string id)
{
    return id.replace("/", "_").replace(":", "_");
}

/// Load Ed25519 secret key from /etc/service_keys/<id>.ed25519 (hex, 64 bytes)
bool loadEd25519Keypair(string serviceId, out Ed25519Keypair kp) @nogc nothrow
{
    auto fname = "/etc/service_keys/" ~ sanitizeId(serviceId) ~ ".ed25519";
    if (!exists(fname)) return false;
    auto text = readText(fname).strip();
    // Expect hex for 64-byte secret key (libsodium form)
    if (!parseHex(text, kp.sk[])) return false;
    if (crypto_sign_ed25519_sk_to_pk(kp.pk.ptr, kp.sk.ptr) != 0) return false;
    return true;
}

/// Load X25519 secret key from /etc/service_keys/<id>.x25519 (hex, 32 bytes)
bool loadX25519Keypair(string serviceId, out X25519Keypair kp) @nogc nothrow
{
    auto fname = "/etc/service_keys/" ~ sanitizeId(serviceId) ~ ".x25519";
    if (!exists(fname)) return false;
    auto text = readText(fname).strip();
    if (!parseHex(text, kp.sk[])) return false;
    // derive public
    crypto_scalarmult_curve25519_base(kp.pk.ptr, kp.sk.ptr);
    return true;
}

/// Load both; if X25519 missing but Ed25519 present, derive X25519.
bool loadServiceKeys(string serviceId, out Ed25519Keypair ed, out X25519Keypair x) @nogc nothrow
{
    bool haveEd = loadEd25519Keypair(serviceId, ed);
    bool haveX = loadX25519Keypair(serviceId, x);
    if (!haveX && haveEd)
    {
        if (!ed25519ToX25519(x, ed)) return false;
        haveX = true;
    }
    return haveEd && haveX;
}
