// libsecipc — Phase 0 (crypto + transport foundation) of SECURE_IPC_ROADMAP.md.
//
// The §0.1 userspace crypto library the secure-IPC endpoints link against, plus the
// §0.2 framing primitive.  Real, RFC-vector-proven implementations:
//
//   X25519 (RFC 7748) ........ ephemeral DH for forward secrecy (Phase 2 handshake)
//   HKDF-SHA-256 (RFC 5869) .. session-key derivation from the DH shared secret
//   ChaCha20 (RFC 8439 §2.4) . the stream cipher
//   Poly1305 (RFC 8439 §2.5) . the one-time authenticator
//   ChaCha20-Poly1305 (§2.8) . the AEAD record layer
//   framing (§0.2) ........... length-prefixed records over the channel
//   ctEqual / zeroize ........ constant-time compare + key zeroization
//
// Builds on the genuine SHA-256/HMAC-SHA-256 from `core/crypto.d` (§8.1).  Ed25519
// sign/verify (the §0.1 asymmetric signature) is NOT here — it needs SHA-512 +
// Edwards arithmetic; secure-IPC identity/broker signatures use the HMAC-SHA-256
// authenticator (`core/crypto.d` cryptoSign) as the stand-in, the seam Ed25519 slots
// into.  §0.3 (broker/identity/cap-manager services) is already implemented for real
// in `core/secipc.d` (Phase 1), which supersedes the "stub" requirement.
//
// Although the roadmap frames libsecipc as a *userspace* lib over the posix
// socketpair/memfd transport, it lands here as an in-kernel module (matching the
// rest of the tree) with a boot self-test; the endpoints that link it and the
// socketpair/memfd ciphertext ring are the remaining integration.
//
// Constraints mirror the rest of the kernel: -betterC, plain structs, __gshared,
// @nogc nothrow.
module core.libsecipc;

import core.io; // klog
import core.crypto : hmacSha256, ctEqual32;

extern (C) @nogc nothrow:

// === constant-time compare + zeroization (§0.1) ==============================
public bool ctEqual(const(ubyte)* a, const(ubyte)* b, ulong n) {
    ubyte d = 0;
    for (ulong i = 0; i < n; ++i) d |= cast(ubyte)(a[i] ^ b[i]);
    return d == 0;
}

// Overwrite key material.  The kernel builds at -O0 so this loop is not elided; a
// production build needs a guaranteed-non-removed memset (documented).
public void zeroize(ubyte* p, ulong n) {
    for (ulong i = 0; i < n; ++i) p[i] = 0;
}

private uint le32(const(ubyte)* p) {
    return cast(uint)p[0] | (cast(uint)p[1] << 8) |
           (cast(uint)p[2] << 16) | (cast(uint)p[3] << 24);
}
private void st32(ubyte* p, uint v) {
    p[0]=cast(ubyte)v; p[1]=cast(ubyte)(v>>8); p[2]=cast(ubyte)(v>>16); p[3]=cast(ubyte)(v>>24);
}

// === ChaCha20 (RFC 8439 §2.4) =================================================
private uint rotl32(uint x, uint n) { return (x << n) | (x >> (32 - n)); }

private void chachaQR(ref uint a, ref uint b, ref uint c, ref uint d) {
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

// One 64-byte ChaCha20 keystream block.  key[32], nonce[12], 32-bit block counter.
public void chacha20Block(const(ubyte)* key, uint counter, const(ubyte)* nonce, ubyte* out64) {
    uint[16] s;
    s[0]=0x61707865; s[1]=0x3320646e; s[2]=0x79622d32; s[3]=0x6b206574;
    foreach (i; 0 .. 8) s[4+i] = le32(key + i*4);
    s[12] = counter;
    foreach (i; 0 .. 3) s[13+i] = le32(nonce + i*4);
    uint[16] x = s;
    foreach (_; 0 .. 10) {
        chachaQR(x[0],x[4],x[8],x[12]);
        chachaQR(x[1],x[5],x[9],x[13]);
        chachaQR(x[2],x[6],x[10],x[14]);
        chachaQR(x[3],x[7],x[11],x[15]);
        chachaQR(x[0],x[5],x[10],x[15]);
        chachaQR(x[1],x[6],x[11],x[12]);
        chachaQR(x[2],x[7],x[8],x[13]);
        chachaQR(x[3],x[4],x[9],x[14]);
    }
    foreach (i; 0 .. 16) st32(out64 + i*4, x[i] + s[i]);
}

// ChaCha20 stream encrypt/decrypt (XOR keystream), starting at `counter`.
public void chacha20(const(ubyte)* key, uint counter, const(ubyte)* nonce,
                     const(ubyte)* inp, ubyte* outp, ulong len) {
    ubyte[64] ks;
    ulong off = 0;
    uint ctr = counter;
    while (off < len) {
        chacha20Block(key, ctr, nonce, ks.ptr);
        ulong n = len - off; if (n > 64) n = 64;
        for (ulong i = 0; i < n; ++i) outp[off+i] = cast(ubyte)(inp[off+i] ^ ks[i]);
        off += n; ++ctr;
    }
}

// === Poly1305 (RFC 8439 §2.5), poly1305-donna 32-bit =========================
public void poly1305(const(ubyte)* key, const(ubyte)* m, ulong len, ubyte* tag16) {
    uint t0=le32(key), t1=le32(key+4), t2=le32(key+8), t3=le32(key+12);
    uint r0 =  t0 & 0x3ffffff;
    uint r1 = ((t0>>26)|(t1<<6)) & 0x3ffff03;
    uint r2 = ((t1>>20)|(t2<<12)) & 0x3ffc0ff;
    uint r3 = ((t2>>14)|(t3<<18)) & 0x3f03fff;
    uint r4 =  (t3>>8) & 0x00fffff;
    uint s1=r1*5, s2=r2*5, s3=r3*5, s4=r4*5;
    uint h0=0,h1=0,h2=0,h3=0,h4=0;

    ulong rem = len;
    const(ubyte)* p = m;
    ubyte[16] last;
    while (rem > 0) {
        uint hibit;
        const(ubyte)* blk;
        if (rem >= 16) { blk = p; hibit = (1u<<24); }
        else {
            foreach (i; 0 .. 16) last[i] = 0;
            for (ulong i = 0; i < rem; ++i) last[i] = p[i];
            last[rem] = 1;
            blk = last.ptr; hibit = 0;
        }
        uint b0=le32(blk), b1=le32(blk+4), b2=le32(blk+8), b3=le32(blk+12);
        h0 += b0 & 0x3ffffff;
        h1 += ((b0>>26)|(b1<<6)) & 0x3ffffff;
        h2 += ((b1>>20)|(b2<<12)) & 0x3ffffff;
        h3 += ((b2>>14)|(b3<<18)) & 0x3ffffff;
        h4 += (b3>>8) | hibit;

        ulong d0 = cast(ulong)h0*r0 + cast(ulong)h1*s4 + cast(ulong)h2*s3 + cast(ulong)h3*s2 + cast(ulong)h4*s1;
        ulong d1 = cast(ulong)h0*r1 + cast(ulong)h1*r0 + cast(ulong)h2*s4 + cast(ulong)h3*s3 + cast(ulong)h4*s2;
        ulong d2 = cast(ulong)h0*r2 + cast(ulong)h1*r1 + cast(ulong)h2*r0 + cast(ulong)h3*s4 + cast(ulong)h4*s3;
        ulong d3 = cast(ulong)h0*r3 + cast(ulong)h1*r2 + cast(ulong)h2*r1 + cast(ulong)h3*r0 + cast(ulong)h4*s4;
        ulong d4 = cast(ulong)h0*r4 + cast(ulong)h1*r3 + cast(ulong)h2*r2 + cast(ulong)h3*r1 + cast(ulong)h4*r0;

        uint c;
        c = cast(uint)(d0 >> 26); h0 = cast(uint)d0 & 0x3ffffff;
        d1 += c; c = cast(uint)(d1 >> 26); h1 = cast(uint)d1 & 0x3ffffff;
        d2 += c; c = cast(uint)(d2 >> 26); h2 = cast(uint)d2 & 0x3ffffff;
        d3 += c; c = cast(uint)(d3 >> 26); h3 = cast(uint)d3 & 0x3ffffff;
        d4 += c; c = cast(uint)(d4 >> 26); h4 = cast(uint)d4 & 0x3ffffff;
        h0 += c*5; c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

        if (rem >= 16) { p += 16; rem -= 16; } else rem = 0;
    }

    // fully carry h
    uint c;
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c*5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    // compute h - p
    uint g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint g4 = h4 + c - (1u<<26);

    // select g if h >= p (g4 did not borrow)
    uint mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;

    // h = h % 2^128
    h0 = (h0 | (h1<<26)) & 0xffffffff;
    h1 = ((h1>>6) | (h2<<20)) & 0xffffffff;
    h2 = ((h2>>12) | (h3<<14)) & 0xffffffff;
    h3 = ((h3>>18) | (h4<<8)) & 0xffffffff;

    // tag = (h + s) % 2^128
    ulong f;
    f = cast(ulong)h0 + le32(key+16);            h0 = cast(uint)f;
    f = cast(ulong)h1 + le32(key+20) + (f>>32);  h1 = cast(uint)f;
    f = cast(ulong)h2 + le32(key+24) + (f>>32);  h2 = cast(uint)f;
    f = cast(ulong)h3 + le32(key+28) + (f>>32);  h3 = cast(uint)f;
    st32(tag16,    h0); st32(tag16+4,  h1);
    st32(tag16+8,  h2); st32(tag16+12, h3);
}

// === ChaCha20-Poly1305 AEAD (RFC 8439 §2.8) ==================================
enum int AEAD_MAC_MAX = 1024; // max aad+ct (proof scale; larger ⇒ chunked, later)

private void aeadMac(const(ubyte)* otk, const(ubyte)* aad, ulong aadlen,
                     const(ubyte)* ct, ulong ctlen, ubyte* tag16) {
    ubyte[AEAD_MAC_MAX + 64] mac;
    ulong p = 0;
    for (ulong i = 0; i < aadlen; ++i) mac[p++] = aad[i];
    while (p % 16 != 0) mac[p++] = 0;
    for (ulong i = 0; i < ctlen; ++i) mac[p++] = ct[i];
    while (p % 16 != 0) mac[p++] = 0;
    foreach (i; 0 .. 8) mac[p++] = cast(ubyte)(aadlen >> (i*8));
    foreach (i; 0 .. 8) mac[p++] = cast(ubyte)(ctlen  >> (i*8));
    poly1305(otk, mac.ptr, p, tag16);
}

// Seal: encrypt `plain` and produce `tag16`.  Returns false if too large.
public bool aeadSeal(const(ubyte)* key, const(ubyte)* nonce,
                     const(ubyte)* aad, ulong aadlen,
                     const(ubyte)* plain, ulong plainlen,
                     ubyte* ct, ubyte* tag16) {
    if (aadlen + plainlen > AEAD_MAC_MAX) return false;
    ubyte[64] block0;
    chacha20Block(key, 0, nonce, block0.ptr);     // one-time Poly1305 key = block0[0..32]
    chacha20(key, 1, nonce, plain, ct, plainlen);
    aeadMac(block0.ptr, aad, aadlen, ct, plainlen, tag16);
    return true;
}

// Open: verify `tag16` then decrypt into `plain`.  Returns false (no plaintext) on
// any authentication failure — fail-closed.
public bool aeadOpen(const(ubyte)* key, const(ubyte)* nonce,
                     const(ubyte)* aad, ulong aadlen,
                     const(ubyte)* ct, ulong ctlen,
                     const(ubyte)* tag16, ubyte* plain) {
    if (aadlen + ctlen > AEAD_MAC_MAX) return false;
    ubyte[64] block0;
    chacha20Block(key, 0, nonce, block0.ptr);
    ubyte[16] expect;
    aeadMac(block0.ptr, aad, aadlen, ct, ctlen, expect.ptr);
    if (!ctEqual(expect.ptr, tag16, 16)) return false;   // MAC fail ⇒ drop
    chacha20(key, 1, nonce, ct, plain, ctlen);
    return true;
}

// === HKDF-SHA-256 (RFC 5869) =================================================
public void hkdfExtract(const(ubyte)* salt, ulong saltlen,
                        const(ubyte)* ikm, ulong ikmlen, ubyte* prk32) {
    hmacSha256(salt, saltlen, ikm, ikmlen, prk32);
}

public void hkdfExpand(const(ubyte)* prk32, const(ubyte)* info, ulong infolen,
                       ubyte* okm, ulong okmlen) {
    ubyte[32] t;
    uint tlen = 0;
    ulong pos = 0;
    ubyte counter = 1;
    while (pos < okmlen) {
        // T(i) = HMAC(prk, T(i-1) || info || counter)
        ubyte[32 + 256 + 1] buf;   // T(i-1) + info(≤256) + counter
        ulong bp = 0;
        for (uint i = 0; i < tlen; ++i) buf[bp++] = t[i];
        for (ulong i = 0; i < infolen && i < 256; ++i) buf[bp++] = info[i];
        buf[bp++] = counter;
        hmacSha256(prk32, 32, buf.ptr, bp, t.ptr);
        tlen = 32;
        ulong n = okmlen - pos; if (n > 32) n = 32;
        for (ulong i = 0; i < n; ++i) okm[pos+i] = t[i];
        pos += n; ++counter;
    }
}

// === X25519 (RFC 7748) — TweetNaCl-derived field arithmetic ==================
private __gshared immutable long[16] _121665 =
    [0xDB41, 1, 0,0,0,0,0,0, 0,0,0,0,0,0,0,0];

private void fAdd(long* o, const(long)* a, const(long)* b) { foreach (i; 0..16) o[i]=a[i]+b[i]; }
private void fSub(long* o, const(long)* a, const(long)* b) { foreach (i; 0..16) o[i]=a[i]-b[i]; }

private void car25519(long* o) {
    foreach (i; 0 .. 16) {
        o[i] += (1L << 16);
        long c = o[i] >> 16;
        long add = (c - 1) + 37 * (c - 1) * (i == 15 ? 1 : 0);
        int idx = (i < 15) ? (i + 1) : 0;
        o[idx] += add;
        o[i] -= c << 16;
    }
}

private void fMul(long* o, const(long)* a, const(long)* b) {
    long[31] t;
    foreach (i; 0 .. 31) t[i] = 0;
    foreach (i; 0 .. 16) foreach (j; 0 .. 16) t[i+j] += a[i]*b[j];
    foreach (i; 0 .. 15) t[i] += 38*t[i+16];
    foreach (i; 0 .. 16) o[i] = t[i];
    car25519(o); car25519(o);
}

private void fSqr(long* o, const(long)* a) { fMul(o, a, a); }

private void sel25519(long* p, long* q, int b) {
    long c = ~(cast(long)b - 1);
    foreach (i; 0 .. 16) { long t = c & (p[i]^q[i]); p[i]^=t; q[i]^=t; }
}

private void inv25519(long* o, const(long)* i) {
    long[16] c;
    foreach (a; 0 .. 16) c[a] = i[a];
    for (int a = 253; a >= 0; --a) {
        fSqr(c.ptr, c.ptr);
        if (a != 2 && a != 4) fMul(c.ptr, c.ptr, i);
    }
    foreach (a; 0 .. 16) o[a] = c[a];
}

private void unpack25519(long* o, const(ubyte)* n) {
    foreach (i; 0 .. 16) o[i] = cast(long)n[2*i] + (cast(long)n[2*i+1] << 8);
    o[15] &= 0x7fff;
}

private void pack25519(ubyte* o, const(long)* n) {
    long[16] t, m;
    foreach (i; 0 .. 16) t[i] = n[i];
    car25519(t.ptr); car25519(t.ptr); car25519(t.ptr);
    foreach (j; 0 .. 2) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; ++i) {
            m[i] = t[i] - 0xffff - ((m[i-1] >> 16) & 1);
            m[i-1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int b = cast(int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        sel25519(t.ptr, m.ptr, 1 - b);
    }
    foreach (i; 0 .. 16) { o[2*i] = cast(ubyte)(t[i] & 0xff); o[2*i+1] = cast(ubyte)(t[i] >> 8); }
}

// q = scalar * point (both 32-byte little-endian); returns the 32-byte u-coordinate.
public void x25519(ubyte* q, const(ubyte)* scalar, const(ubyte)* point) {
    ubyte[32] z;
    long[80] x;
    long[16] a, b, c, d, e, f;
    foreach (i; 0 .. 31) z[i] = scalar[i];
    z[31] = (scalar[31] & 127) | 64;
    z[0] &= 248;
    unpack25519(x.ptr, point);
    foreach (i; 0 .. 16) { b[i] = x[i]; a[i] = c[i] = d[i] = 0; }
    a[0] = d[0] = 1;
    for (int i = 254; i >= 0; --i) {
        int r = (z[i>>3] >> (i&7)) & 1;
        sel25519(a.ptr, b.ptr, r); sel25519(c.ptr, d.ptr, r);
        fAdd(e.ptr, a.ptr, c.ptr); fSub(a.ptr, a.ptr, c.ptr);
        fAdd(c.ptr, b.ptr, d.ptr); fSub(b.ptr, b.ptr, d.ptr);
        fSqr(d.ptr, e.ptr); fSqr(f.ptr, a.ptr);
        fMul(a.ptr, c.ptr, a.ptr); fMul(c.ptr, b.ptr, e.ptr);
        fAdd(e.ptr, a.ptr, c.ptr); fSub(a.ptr, a.ptr, c.ptr);
        fSqr(b.ptr, a.ptr); fSub(c.ptr, d.ptr, f.ptr);
        fMul(a.ptr, c.ptr, _121665.ptr); fAdd(a.ptr, a.ptr, d.ptr);
        fMul(c.ptr, c.ptr, a.ptr); fMul(a.ptr, d.ptr, f.ptr);
        fMul(d.ptr, b.ptr, x.ptr); fSqr(b.ptr, e.ptr);
        sel25519(a.ptr, b.ptr, r); sel25519(c.ptr, d.ptr, r);
    }
    foreach (i; 0 .. 16) { x[i+16]=a[i]; x[i+32]=c[i]; x[i+48]=b[i]; x[i+64]=d[i]; }
    inv25519(x.ptr+32, x.ptr+32);
    fMul(x.ptr+16, x.ptr+16, x.ptr+32);
    pack25519(q, x.ptr+16);
}

// X25519 from the standard base point u=9 (public key from a private scalar).
public void x25519Base(ubyte* pub, const(ubyte)* scalar) {
    ubyte[32] nine; foreach (i; 0 .. 32) nine[i] = 0; nine[0] = 9;
    x25519(pub, scalar, nine.ptr);
}

// === §0.2 framing: length-prefixed records ===================================
enum uint FRAME_MAX = 65536;

// Encode [u32 len][payload] into `out`; returns total frame length, or 0 if it
// would overflow `outcap`.
public ulong frameEncode(const(ubyte)* payload, uint len, ubyte* outp, ulong outcap) {
    if (len > FRAME_MAX || cast(ulong)len + 4 > outcap) return 0;
    st32(outp, len);
    for (uint i = 0; i < len; ++i) outp[4+i] = payload[i];
    return cast(ulong)len + 4;
}

// Decode a frame; sets payload offset (always 4) + length.  Rejects a truncated or
// oversized record (the parser must never read past the buffer).
public bool frameDecode(const(ubyte)* buf, ulong buflen, uint* payloadLen) {
    if (buflen < 4) return false;
    uint len = le32(buf);
    if (len > FRAME_MAX) return false;
    if (cast(ulong)len + 4 > buflen) return false;   // truncated
    if (payloadLen !is null) *payloadLen = len;
    return true;
}

// === proof (RFC vectors + round-trips) =======================================
__gshared bool g_secipcCryptoSelfTested = false;

private bool tEq(const(ubyte)* a, const(ubyte)* b, ulong n) { return ctEqual(a, b, n); }

private bool selfTestChacha() {     // RFC 8439 §2.3.2 keystream block
    ubyte[32] key; foreach (i; 0 .. 32) key[i] = cast(ubyte)i;
    ubyte[12] nonce = [0,0,0,9, 0,0,0,0x4a, 0,0,0,0];
    ubyte[64] blk;
    chacha20Block(key.ptr, 1, nonce.ptr, blk.ptr);
    static immutable ubyte[64] want = [
        0x10,0xf1,0xe7,0xe4,0xd1,0x3b,0x59,0x15,0x50,0x0f,0xdd,0x1f,0xa3,0x20,0x71,0xc4,
        0xc7,0xd1,0xf4,0xc7,0x33,0xc0,0x68,0x03,0x04,0x22,0xaa,0x9a,0xc3,0xd4,0x6c,0x4e,
        0xd2,0x82,0x64,0x46,0x07,0x9f,0xaa,0x09,0x14,0xc2,0xd7,0x05,0xd9,0x8b,0x02,0xa2,
        0xb5,0x12,0x9c,0xd1,0xde,0x16,0x4e,0xb9,0xcb,0xd0,0x83,0xe8,0xa2,0x50,0x3c,0x4e,
    ];
    return tEq(blk.ptr, want.ptr, 64);
}

private bool selfTestPoly() {       // RFC 8439 §2.5.2
    static immutable ubyte[32] key = [
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b,
    ];
    static immutable ubyte[34] msg = [
        0x43,0x72,0x79,0x70,0x74,0x6f,0x67,0x72,0x61,0x70,0x68,0x69,0x63,0x20,0x46,0x6f,
        0x72,0x75,0x6d,0x20,0x52,0x65,0x73,0x65,0x61,0x72,0x63,0x68,0x20,0x47,0x72,0x6f,
        0x75,0x70,
    ];
    static immutable ubyte[16] want = [
        0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9,
    ];
    ubyte[16] tag;
    poly1305(key.ptr, msg.ptr, 34, tag.ptr);
    return tEq(tag.ptr, want.ptr, 16);
}

private bool selfTestAead() {       // RFC 8439 §2.8.2 tag + round-trip + tamper
    static immutable ubyte[32] key = [
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f,
    ];
    static immutable ubyte[12] nonce = [0x07,0,0,0, 0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47];
    static immutable ubyte[12] aad = [0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7];
    static immutable ubyte[114] pt = [
        0x4c,0x61,0x64,0x69,0x65,0x73,0x20,0x61,0x6e,0x64,0x20,0x47,0x65,0x6e,0x74,0x6c,
        0x65,0x6d,0x65,0x6e,0x20,0x6f,0x66,0x20,0x74,0x68,0x65,0x20,0x63,0x6c,0x61,0x73,
        0x73,0x20,0x6f,0x66,0x20,0x27,0x39,0x39,0x3a,0x20,0x49,0x66,0x20,0x49,0x20,0x63,
        0x6f,0x75,0x6c,0x64,0x20,0x6f,0x66,0x66,0x65,0x72,0x20,0x79,0x6f,0x75,0x20,0x6f,
        0x6e,0x6c,0x79,0x20,0x6f,0x6e,0x65,0x20,0x74,0x69,0x70,0x20,0x66,0x6f,0x72,0x20,
        0x74,0x68,0x65,0x20,0x66,0x75,0x74,0x75,0x72,0x65,0x2c,0x20,0x73,0x75,0x6e,0x73,
        0x63,0x72,0x65,0x65,0x6e,0x20,0x77,0x6f,0x75,0x6c,0x64,0x20,0x62,0x65,0x20,0x69,
        0x74,0x2e,
    ];
    static immutable ubyte[16] wantTag = [
        0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91,
    ];
    ubyte[114] ct;
    ubyte[16] tag;
    if (!aeadSeal(key.ptr, nonce.ptr, aad.ptr, 12, pt.ptr, 114, ct.ptr, tag.ptr)) return false;
    bool tagOk = tEq(tag.ptr, wantTag.ptr, 16);
    // Round-trip: open recovers the plaintext.
    ubyte[114] dec;
    bool opened = aeadOpen(key.ptr, nonce.ptr, aad.ptr, 12, ct.ptr, 114, tag.ptr, dec.ptr);
    bool ptOk = opened && tEq(dec.ptr, pt.ptr, 114);
    // Tamper: a flipped ciphertext byte fails authentication (fail-closed).
    ct[0] ^= 0x80;
    bool tamper = !aeadOpen(key.ptr, nonce.ptr, aad.ptr, 12, ct.ptr, 114, tag.ptr, dec.ptr);
    return tagOk && ptOk && tamper;
}

private bool selfTestHkdf() {       // RFC 5869 §A.1
    static immutable ubyte[22] ikm = [
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
    ];
    static immutable ubyte[13] salt = [0,1,2,3,4,5,6,7,8,9,0x0a,0x0b,0x0c];
    static immutable ubyte[10] info = [0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9];
    static immutable ubyte[32] wantPrk = [
        0x07,0x77,0x09,0x36,0x2c,0x2e,0x32,0xdf,0x0d,0xdc,0x3f,0x0d,0xc4,0x7b,0xba,0x63,
        0x90,0xb6,0xc7,0x3b,0xb5,0x0f,0x9c,0x31,0x22,0xec,0x84,0x4a,0xd7,0xc2,0xb3,0xe5,
    ];
    static immutable ubyte[42] wantOkm = [
        0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,0x90,0x43,0x4f,0x64,0xd0,0x36,0x2f,0x2a,
        0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,
        0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,0x58,0x65,
    ];
    ubyte[32] prk;
    hkdfExtract(salt.ptr, 13, ikm.ptr, 22, prk.ptr);
    bool prkOk = tEq(prk.ptr, wantPrk.ptr, 32);
    ubyte[42] okm;
    hkdfExpand(prk.ptr, info.ptr, 10, okm.ptr, 42);
    bool okmOk = tEq(okm.ptr, wantOkm.ptr, 42);
    return prkOk && okmOk;
}

private bool selfTestX25519() {     // RFC 7748 §5.2 (single scalarmult) + DH agreement
    static immutable ubyte[32] scalar = [
        0xa5,0x46,0xe3,0x6b,0xf0,0x52,0x7c,0x9d,0x3b,0x16,0x15,0x4b,0x82,0x46,0x5e,0xdd,
        0x62,0x14,0x4c,0x0a,0xc1,0xfc,0x5a,0x18,0x50,0x6a,0x22,0x44,0xba,0x44,0x9a,0xc4,
    ];
    static immutable ubyte[32] u = [
        0xe6,0xdb,0x68,0x67,0x58,0x30,0x30,0xdb,0x35,0x94,0xc1,0xa4,0x24,0xb1,0x5f,0x7c,
        0x72,0x66,0x24,0xec,0x26,0xb3,0x35,0x3b,0x10,0xa9,0x03,0xa6,0xd0,0xab,0x1c,0x4c,
    ];
    static immutable ubyte[32] want = [
        0xc3,0xda,0x55,0x37,0x9d,0xe9,0xc6,0x90,0x8e,0x94,0xea,0x4d,0xf2,0x8d,0x08,0x4f,
        0x32,0xec,0xcf,0x03,0x49,0x1c,0x71,0xf7,0x54,0xb4,0x07,0x55,0x77,0xa2,0x85,0x52,
    ];
    ubyte[32] out_;
    x25519(out_.ptr, scalar.ptr, u.ptr);
    bool kat = tEq(out_.ptr, want.ptr, 32);
    // Diffie-Hellman agreement: pubA=base*a, pubB=base*b ⇒ a*pubB == b*pubA.
    ubyte[32] a; foreach (i; 0 .. 32) a[i] = cast(ubyte)(0x11 + i);
    ubyte[32] b; foreach (i; 0 .. 32) b[i] = cast(ubyte)(0x55 + i);
    ubyte[32] pubA, pubB, ssAB, ssBA;
    x25519Base(pubA.ptr, a.ptr);
    x25519Base(pubB.ptr, b.ptr);
    x25519(ssAB.ptr, a.ptr, pubB.ptr);
    x25519(ssBA.ptr, b.ptr, pubA.ptr);
    bool agree = tEq(ssAB.ptr, ssBA.ptr, 32);
    return kat && agree;
}

private bool selfTestFraming() {    // §0.2
    ubyte[8] payload = [1,2,3,4,5,6,7,8];
    ubyte[32] buf;
    ulong fl = frameEncode(payload.ptr, 8, buf.ptr, 32);
    uint plen;
    bool ok = (fl == 12 && frameDecode(buf.ptr, fl, &plen) && plen == 8 &&
               tEq(buf.ptr + 4, payload.ptr, 8));
    bool truncated = !frameDecode(buf.ptr, 10, &plen);   // claims 8 but only 6 payload bytes
    bool tooShort = !frameDecode(buf.ptr, 2, &plen);
    return ok && truncated && tooShort;
}

public void libsecipcSelfTest() {
    if (g_secipcCryptoSelfTested) return;
    g_secipcCryptoSelfTested = true;
    bool cc = selfTestChacha();
    bool po = selfTestPoly();
    bool ae = selfTestAead();
    bool hk = selfTestHkdf();
    bool xx = selfTestX25519();
    bool fr = selfTestFraming();
    if (cc && po && ae && hk && xx && fr) {
        klog("[libsecipc] selftest PASS\n");
    } else {
        klog("[libsecipc] selftest FAIL:");
        if (!cc) klog(" chacha20");
        if (!po) klog(" poly1305");
        if (!ae) klog(" aead");
        if (!hk) klog(" hkdf");
        if (!xx) klog(" x25519");
        if (!fr) klog(" framing");
        klog("\n");
    }
}
