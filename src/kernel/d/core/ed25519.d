// ed25519.d — Ed25519 signature VERIFICATION (SYSTEM_UPDATE D3).
//
// D3: "HMAC (DM12) is symmetric — verifier holds the signing secret; unusable for OS releases."
// That is the whole problem with 4.4's update signing as shipped: anyone holding
// scripts/mk-hosupd.sh can forge a bundle the kernel accepts, because the kernel's verification
// key IS the signing key.  For a locally built image that is fine.  For a release anyone
// downloads, it means the update system authenticates nothing.
//
// VERIFY ONLY, deliberately.  The kernel never needs to sign an update — it needs to refuse one
// that was not signed by the release key.  Leaving signing out removes the private-key handling
// path from the kernel entirely, so there is no secret in the image to extract.
//
// PROVENANCE: this is a port of TweetNaCl's ed25519 (Bernstein, Janssen, Lange, Schwabe — public
// domain), chosen over writing field arithmetic from scratch precisely because a subtly wrong
// curve implementation is WORSE than the symmetric HMAC it replaces: it would accept forgeries
// while looking like real asymmetric crypto.  TweetNaCl is small enough to read end to end and is
// the most widely reviewed compact implementation available.
//
// Representation: gf = long[16], radix 2^16 with lazy carries — TweetNaCl's choice.  It avoids
// needing 128-bit integers, which -betterC/ldc2 does not portably provide, at some speed cost.
// Speed is irrelevant here: this runs once per update, not per packet.
//
// NOT constant-time in the hardened sense.  That is acceptable for THIS use and nothing else:
// signature verification operates entirely on public data (public key, signature, message), so
// there is no secret whose timing could leak.  Do not reuse this module for anything involving a
// private key.
module core.ed25519;

@nogc: nothrow:

extern (C) void sha512_hash(const(ubyte)* data, size_t len, ubyte* output) @nogc nothrow;

private alias gf = long[16];

private static immutable long[16] GF0 = 0;
private static immutable long[16] GF1 = [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
// d = -121665/121666
private static immutable long[16] D = [
    0x78a3,0x1359,0x4dca,0x75eb,0xd8ab,0x4141,0x0a4d,0x0070,
    0xe898,0x7779,0x4079,0x8cc7,0xfe73,0x2b6f,0x6cee,0x5203];
// 2*d
private static immutable long[16] D2 = [
    0xf159,0x26b2,0x9b94,0xebd6,0xb156,0x8283,0x149a,0x00e0,
    0xd130,0xeef3,0x80f2,0x198e,0xfce7,0x56df,0xd9dc,0x2406];
private static immutable long[16] X = [
    0xd51a,0x8f25,0x2d60,0xc956,0xa7b2,0x9525,0xc760,0x692c,
    0xdc5c,0xfdd6,0xe231,0xc0a4,0x53fe,0xcd6e,0x36d3,0x2169];
private static immutable long[16] Y = [
    0x6658,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,
    0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666];
// sqrt(-1)
private static immutable long[16] I = [
    0xa0b0,0x4a0e,0x1b27,0xc4ee,0xe478,0xad2f,0x1806,0x2f43,
    0xd7a7,0x3dfb,0x0099,0x2b4d,0xdf0b,0x4fc1,0x2480,0x2b83];

// L = 2^252 + 27742317777372353535851937790883648493, little-endian bytes, as TweetNaCl's `L`.
private static immutable long[32] ORDER_L = [
    0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10];

private void set25519(ref gf r, ref const(gf) a) { foreach (i; 0 .. 16) r[i] = a[i]; }

private void car25519(ref gf o) {
    foreach (i; 0 .. 16) {
        o[i] += (1L << 16);
        long c = o[i] >> 16;
        o[(i + 1) * ((i < 15) ? 1 : 0)] += c - 1 + 37 * (c - 1) * ((i == 15) ? 1 : 0);
        o[i] -= c << 16;
    }
}

private void sel25519(ref gf p, ref gf q, int b) {
    const long c = ~(cast(long)b - 1);
    foreach (i; 0 .. 16) {
        const long t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

private void pack25519(ubyte* o, ref const(gf) n) {
    gf m, t;
    foreach (i; 0 .. 16) t[i] = n[i];
    car25519(t); car25519(t); car25519(t);
    foreach (_; 0 .. 2) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; ++i) {
            m[i] = t[i] - 0xffff - ((m[i-1] >> 16) & 1);
            m[i-1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        const int b = cast(int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    foreach (i; 0 .. 16) {
        o[2*i]     = cast(ubyte)(t[i] & 0xff);
        o[2*i + 1] = cast(ubyte)(t[i] >> 8);
    }
}

private int neq25519(ref const(gf) a, ref const(gf) b) {
    ubyte[32] c, d;
    pack25519(c.ptr, a); pack25519(d.ptr, b);
    return cryptoVerify32(c.ptr, d.ptr);
}

private ubyte par25519(ref const(gf) a) {
    ubyte[32] d;
    pack25519(d.ptr, a);
    return d[0] & 1;
}

private void unpack25519(ref gf o, const(ubyte)* n) {
    foreach (i; 0 .. 16) o[i] = cast(long)n[2*i] + ((cast(long)n[2*i + 1]) << 8);
    o[15] &= 0x7fff;
}

private void A(ref gf o, ref const(gf) a, ref const(gf) b) { foreach (i; 0 .. 16) o[i] = a[i] + b[i]; }
private void Z(ref gf o, ref const(gf) a, ref const(gf) b) { foreach (i; 0 .. 16) o[i] = a[i] - b[i]; }

private void M(ref gf o, ref const(gf) a, ref const(gf) b) {
    long[31] t = 0;
    foreach (i; 0 .. 16) foreach (j; 0 .. 16) t[i + j] += a[i] * b[j];
    foreach (i; 0 .. 15) t[i] += 38 * t[i + 16];
    foreach (i; 0 .. 16) o[i] = t[i];
    car25519(o); car25519(o);
}

private void S(ref gf o, ref const(gf) a) { M(o, a, a); }

private void inv25519(ref gf o, ref const(gf) i) {
    gf c;
    foreach (k; 0 .. 16) c[k] = i[k];
    for (int a = 253; a >= 0; --a) {
        S(c, c);
        if (a != 2 && a != 4) M(c, c, i);
    }
    foreach (k; 0 .. 16) o[k] = c[k];
}

private void pow2523(ref gf o, ref const(gf) i) {
    gf c;
    foreach (k; 0 .. 16) c[k] = i[k];
    for (int a = 250; a >= 0; --a) {
        S(c, c);
        if (a != 1) M(c, c, i);
    }
    foreach (k; 0 .. 16) o[k] = c[k];
}

// Extended-coordinate point addition (p += q).
private void addPt(ref gf[4] p, ref gf[4] q) {
    gf a, b, c, d, t, e, f, g, h;
    Z(a, p[1], p[0]);
    Z(t, q[1], q[0]);
    M(a, a, t);
    A(b, p[0], p[1]);
    A(t, q[0], q[1]);
    M(b, b, t);
    M(c, p[3], q[3]);
    M(c, c, D2);
    M(d, p[2], q[2]);
    A(d, d, d);
    Z(e, b, a);
    Z(f, d, c);
    A(g, d, c);
    A(h, b, a);
    M(p[0], e, f);
    M(p[1], h, g);
    M(p[2], g, f);
    M(p[3], e, h);
}

private void cswapPt(ref gf[4] p, ref gf[4] q, ubyte b) {
    foreach (i; 0 .. 4) sel25519(p[i], q[i], b);
}

private void packPt(ubyte* r, ref gf[4] p) {
    gf tx, ty, zi;
    inv25519(zi, p[2]);
    M(tx, p[0], zi);
    M(ty, p[1], zi);
    pack25519(r, ty);
    r[31] ^= cast(ubyte)(par25519(tx) << 7);
}

private void scalarmult(ref gf[4] p, ref gf[4] q, const(ubyte)* s) {
    set25519(p[0], GF0); set25519(p[1], GF1);
    set25519(p[2], GF1); set25519(p[3], GF0);
    for (int i = 255; i >= 0; --i) {
        const ubyte b = cast(ubyte)((s[i / 8] >> (i & 7)) & 1);
        cswapPt(p, q, b);
        addPt(q, p);
        addPt(p, p);
        cswapPt(p, q, b);
    }
}

private void scalarbase(ref gf[4] p, const(ubyte)* s) {
    gf[4] q;
    set25519(q[0], X); set25519(q[1], Y); set25519(q[2], GF1);
    M(q[3], X, Y);
    scalarmult(p, q, s);
}

// Decompress a public key into -A (TweetNaCl's unpackneg).  Returns false if the encoding is not
// a valid curve point -- a malformed key must be REFUSED, not coerced into something usable.
private bool unpackneg(ref gf[4] r, const(ubyte)* p) {
    gf t, chk, num, den, den2, den4, den6;
    set25519(r[2], GF1);
    unpack25519(r[1], p);
    S(num, r[1]);
    M(den, num, D);
    Z(num, num, r[2]);
    A(den, r[2], den);

    S(den2, den);
    S(den4, den2);
    M(den6, den4, den2);
    M(t, den6, num);
    M(t, t, den);

    pow2523(t, t);
    M(t, t, num);
    M(t, t, den);
    M(t, t, den);
    M(r[0], t, den);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) M(r[0], r[0], I);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) return false;

    if (par25519(r[0]) == ((p[31] >> 7) & 1)) Z(r[0], GF0, r[0]);

    M(r[3], r[0], r[1]);
    return true;
}

// Constant-time-ish 32-byte compare: 0 = equal.
private int cryptoVerify32(const(ubyte)* x, const(ubyte)* y) {
    uint d = 0;
    foreach (i; 0 .. 32) d |= x[i] ^ y[i];
    return (1 & ((d - 1) >> 8)) - 1;
}

// Reduce a 64-byte little-endian scalar mod L, in place (TweetNaCl's reduce/modL).
private void modL(ubyte* r, long* x) {
    for (int i = 63; i >= 32; --i) {
        long carry = 0;
        int j = i - 32;
        const int jend = i - 12;
        for (; j < jend; ++j) {
            x[j] += carry - 16 * x[i] * ORDER_L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[j] += carry;
        x[i] = 0;
    }
    long carry = 0;
    foreach (j; 0 .. 32) {
        x[j] += carry - (x[31] >> 4) * ORDER_L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    foreach (j; 0 .. 32) x[j] -= carry * ORDER_L[j];
    foreach (i; 0 .. 32) {
        x[i + 1] += x[i] >> 8;
        r[i] = cast(ubyte)(x[i] & 255);
    }
}

private void reduce(ubyte* r) {
    long[64] x;
    foreach (i; 0 .. 64) x[i] = cast(long)r[i];
    foreach (i; 0 .. 64) r[i] = 0;
    modL(r, x.ptr);
}

__gshared ulong g_edVerifyTotal = 0;
__gshared ulong g_edRejectTotal = 0;

// Verify a detached Ed25519 signature: 64-byte sig over `msg`, under 32-byte `pk`.
//
// The message is hashed into a fixed buffer, so `len` is bounded -- a kernel verifier must not
// depend on an allocation it cannot make.  ED_MSG_MAX is generous for an update header; the
// whole-image bundle signs a 64-byte header, not the payload.
enum size_t ED_MSG_MAX = 512;

public bool ed25519Verify(const(ubyte)* sig, const(ubyte)* msg, size_t len, const(ubyte)* pk) {
    ++g_edVerifyTotal;
    if (sig is null || pk is null || (len > 0 && msg is null) || len > ED_MSG_MAX) {
        ++g_edRejectTotal; return false;
    }

    gf[4] q;
    if (!unpackneg(q, pk)) { ++g_edRejectTotal; return false; }

    // h = SHA-512(R || A || M), reduced mod L.
    // __gshared, not a stack array: this is 576 bytes on top of the several KB the gf temporaries
    // already use, and a kernel stack is not the place to discover that limit.  Verification is
    // not reentrant here (one update at a time), so a shared scratch buffer is safe.
    static __gshared ubyte[64 + ED_MSG_MAX] sm;
    foreach (i; 0 .. 32) sm[i]      = sig[i];        // R
    foreach (i; 0 .. 32) sm[32 + i] = pk[i];         // A
    foreach (i; 0 .. len) sm[64 + i] = msg[i];
    ubyte[64] h;
    sha512_hash(sm.ptr, 64 + len, h.ptr);
    reduce(h.ptr);

    // Check [S]B == R + [h]A, i.e. [S]B - [h]A - R == 0 with q = -A.
    gf[4] p;
    scalarmult(p, q, h.ptr);
    gf[4] g;
    scalarbase(g, sig + 32);                          // [S]B
    addPt(p, g);

    ubyte[32] t;
    packPt(t.ptr, p);
    const bool ok = (cryptoVerify32(sig, t.ptr) == 0);
    if (!ok) ++g_edRejectTotal;
    return ok;
}

// ── Proof: RFC 8032 test vectors ─────────────────────────────────────────────────────────────
//
// A hand-ported curve implementation that is SUBTLY wrong is worse than the symmetric HMAC it
// replaces -- it would accept forgeries while looking like real asymmetric crypto.  So this does
// not self-test its own arithmetic against itself; it checks the official RFC 8032 §7.1 vectors,
// which are external ground truth this code cannot have accidentally agreed with.
//
// Both directions matter: the vectors must VERIFY, and a single flipped bit in the signature must
// be REFUSED.  A verifier that returns true unconditionally passes the first check alone.
import core.io : klog, klog_dec;

__gshared bool g_edSelfTested = false;

private void hexTo(const(char)* hex, ubyte* out_, size_t n) {
    static int nyb(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    }
    foreach (i; 0 .. n) out_[i] = cast(ubyte)((nyb(hex[2*i]) << 4) | nyb(hex[2*i + 1]));
}

public void ed25519SelfTest() {
    if (g_edSelfTested) return;
    g_edSelfTested = true;

    ubyte[32] pk1, pk2;
    ubyte[64] s1, s2;

    // RFC 8032 §7.1 TEST 1 — empty message.
    hexTo("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\0".ptr, pk1.ptr, 32);
    hexTo("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b\0".ptr, s1.ptr, 64);
    const bool t1 = ed25519Verify(s1.ptr, null, 0, pk1.ptr);

    // RFC 8032 §7.1 TEST 2 — one-byte message 0x72.
    hexTo("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c\0".ptr, pk2.ptr, 32);
    hexTo("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00\0".ptr, s2.ptr, 64);
    ubyte[1] m2 = [0x72];
    const bool t2 = ed25519Verify(s2.ptr, m2.ptr, 1, pk2.ptr);

    // A forged signature: one bit flipped in an otherwise valid one.
    s2[0] ^= 0x01;
    const bool tForged = ed25519Verify(s2.ptr, m2.ptr, 1, pk2.ptr);
    s2[0] ^= 0x01;

    // A wrong message under a valid signature.
    ubyte[1] mBad = [0x73];
    const bool tWrongMsg = ed25519Verify(s2.ptr, mBad.ptr, 1, pk2.ptr);

    // A malformed public key must be refused by unpackneg, not coerced.
    ubyte[32] pkBad = 0xFF;
    const bool tBadKey = ed25519Verify(s2.ptr, m2.ptr, 1, pkBad.ptr);

    const bool pass = t1 && t2 && !tForged && !tWrongMsg && !tBadKey;
    klog("[4.10] Ed25519 (RFC 8032 vectors): t1=");     klog_dec(t1 ? 1 : 0);
    klog(" t2=");            klog_dec(t2 ? 1 : 0);
    klog(" forged-refused=");  klog_dec(tForged ? 0 : 1);
    klog(" wrongmsg-refused="); klog_dec(tWrongMsg ? 0 : 1);
    klog(" badkey-refused=");  klog_dec(tBadKey ? 0 : 1);
    klog(pass ? " -- D3 PASS\n" : " -- D3 FAIL\n");
}
