// Kernel crypto primitives + measured/verified boot — IMMUTABLE_ROOTLESS §8.1/§8.2.
//
// §8.1 gives the kernel a *real* cryptographic hash (SHA-256, proven against the
// NIST vectors) and a keyed authenticator (HMAC-SHA-256, proven against RFC 4231) —
// the primitive the earlier phases promised would replace their stand-ins (§4.2
// content hashing, §6.2 update signatures).  §8.2 builds a measured/verified-boot
// register and a signed module manifest on top: each module is hashed, the
// measurement register is PCR-extended, and a boot is accepted only if every
// measured hash appears in a manifest whose signature verifies with the trusted key.
//
// Asymmetry note: the §8.1 outcome names ed25519.  A full ed25519 verify (field
// arithmetic mod 2^255-19 + SHA-512 + point ops) is not implemented here; the
// signature/verify primitive is HMAC-SHA-256 under a kernel-held trusted key — a
// genuine cryptographic authenticator (an attacker without the key cannot forge a
// signature, which is the verified-boot property), and a drop-in seam for a later
// asymmetric verify.  This is the one remaining stand-in; the *hash* is now real.
//
// Constraints mirror the rest of the kernel: -betterC, plain structs, __gshared
// fixed tables, @nogc nothrow.
module core.crypto;

import core.io; // klog

extern (C) @nogc nothrow:

// === SHA-256 (FIPS 180-4) =====================================================
struct Sha256 {
    uint[8]   h;
    ulong     total;   // total bytes absorbed
    ubyte[64] buf;
    uint      used;    // bytes pending in buf
}

private immutable uint[64] SHA256_K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
];

private uint rotr(uint x, uint n) { return (x >> n) | (x << (32 - n)); }

public void sha256Init(ref Sha256 s) {
    s.h[0]=0x6a09e667; s.h[1]=0xbb67ae85; s.h[2]=0x3c6ef372; s.h[3]=0xa54ff53a;
    s.h[4]=0x510e527f; s.h[5]=0x9b05688c; s.h[6]=0x1f83d9ab; s.h[7]=0x5be0cd19;
    s.total = 0; s.used = 0;
}

private void sha256Block(ref Sha256 s, const(ubyte)* p) {
    uint[64] w;
    foreach (i; 0 .. 16)
        w[i] = (cast(uint)p[i*4] << 24) | (cast(uint)p[i*4+1] << 16) |
               (cast(uint)p[i*4+2] << 8) | cast(uint)p[i*4+3];
    foreach (i; 16 .. 64) {
        uint s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
        uint s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint a=s.h[0], b=s.h[1], c=s.h[2], d=s.h[3], e=s.h[4], f=s.h[5], g=s.h[6], hh=s.h[7];
    foreach (i; 0 .. 64) {
        uint S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
        uint ch = (e & f) ^ (~e & g);
        uint t1 = hh + S1 + ch + SHA256_K[i] + w[i];
        uint S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint t2 = S0 + maj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    s.h[0]+=a; s.h[1]+=b; s.h[2]+=c; s.h[3]+=d; s.h[4]+=e; s.h[5]+=f; s.h[6]+=g; s.h[7]+=hh;
}

public void sha256Update(ref Sha256 s, const(ubyte)* data, ulong len) {
    s.total += len;
    for (ulong i = 0; i < len; ++i) {
        s.buf[s.used++] = data[i];
        if (s.used == 64) { sha256Block(s, s.buf.ptr); s.used = 0; }
    }
}

public void sha256Final(ref Sha256 s, ubyte* out32) {
    ulong bits = s.total * 8;          // original message length, in bits
    ubyte pad = 0x80;
    sha256Update(s, &pad, 1);
    ubyte zero = 0;
    while (s.used != 56) sha256Update(s, &zero, 1);
    ubyte[8] lenbuf;
    foreach (i; 0 .. 8) lenbuf[i] = cast(ubyte)(bits >> (56 - i*8));
    sha256Update(s, lenbuf.ptr, 8);
    foreach (i; 0 .. 8) {
        out32[i*4]   = cast(ubyte)(s.h[i] >> 24);
        out32[i*4+1] = cast(ubyte)(s.h[i] >> 16);
        out32[i*4+2] = cast(ubyte)(s.h[i] >> 8);
        out32[i*4+3] = cast(ubyte)(s.h[i]);
    }
}

public void sha256(const(ubyte)* data, ulong len, ubyte* out32) {
    Sha256 s; sha256Init(s); sha256Update(s, data, len); sha256Final(s, out32);
}

// === HMAC-SHA-256 (RFC 2104) ==================================================
public void hmacSha256(const(ubyte)* key, ulong keylen,
                       const(ubyte)* msg, ulong msglen, ubyte* out32) {
    ubyte[64] k0;
    foreach (i; 0 .. 64) k0[i] = 0;
    if (keylen > 64) sha256(key, keylen, k0.ptr);          // long key ⇒ hash it
    else for (ulong i = 0; i < keylen; ++i) k0[i] = key[i];
    ubyte[64] ipad, opad;
    foreach (i; 0 .. 64) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }
    ubyte[32] inner;
    Sha256 s; sha256Init(s);
    sha256Update(s, ipad.ptr, 64);
    sha256Update(s, msg, msglen);
    sha256Final(s, inner.ptr);
    Sha256 s2; sha256Init(s2);
    sha256Update(s2, opad.ptr, 64);
    sha256Update(s2, inner.ptr, 32);
    sha256Final(s2, out32);
}

// Constant-time 32-byte compare (no early-out timing leak).
public bool ctEqual32(const(ubyte)* a, const(ubyte)* b) {
    ubyte d = 0;
    foreach (i; 0 .. 32) d |= cast(ubyte)(a[i] ^ b[i]);
    return d == 0;
}

// The kernel-held trusted verification key (stands in for the §8.2 ed25519 public
// key baked into the verified-boot chain).
__gshared ubyte[32] g_trustedKey = [
    0xA1,0x7E,0xB0,0x0F,0x51,0x61,0xCa,0xFE,0xDE,0xAD,0xBE,0xEF,0x01,0x23,0x45,0x67,
    0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,0x0F,0x1E,0x2D,0x3C,
];

// Sign/verify a message with the trusted key (HMAC-SHA-256 authenticator).
public void cryptoSign(const(ubyte)* msg, ulong len, ubyte* sig32) {
    hmacSha256(g_trustedKey.ptr, 32, msg, len, sig32);
}

public bool cryptoVerify(const(ubyte)* msg, ulong len, const(ubyte)* sig32) {
    ubyte[32] expect;
    hmacSha256(g_trustedKey.ptr, 32, msg, len, expect.ptr);
    return ctEqual32(expect.ptr, sig32);
}

// === §8.2 measured / verified boot ============================================
// A PCR-like measurement register, extended once per measured module, plus a signed
// manifest of expected module hashes.  A boot is "verified" iff every module's
// measured SHA-256 is present in a manifest whose signature verifies.
enum int MANIFEST_MAX = 16;

struct ManifestEntry {
    bool      inUse;
    uint      nameHash;
    ubyte[32] hash;     // expected SHA-256 of the module
}

struct Manifest {
    ManifestEntry[MANIFEST_MAX] e;
    uint      count;
    ubyte[32] sig;      // cryptoSign over the entry hashes
}

__gshared ubyte[32] g_measurePCR;      // boot measurement register
__gshared ulong     g_measureExtends = 0;
__gshared ulong     g_verifyOk       = 0;
__gshared ulong     g_verifyFail     = 0;
__gshared bool      g_cryptoSelfTested = false;

// Reset the measurement register (PCR) to zero.
public void measureReset() { foreach (i; 0 .. 32) g_measurePCR[i] = 0; }

// PCR-extend: register := SHA-256(register || moduleHash).
public void measureExtend(const(ubyte)* hash32) {
    ubyte[64] cat;
    foreach (i; 0 .. 32) cat[i] = g_measurePCR[i];
    foreach (i; 0 .. 32) cat[32 + i] = hash32[i];
    sha256(cat.ptr, 64, g_measurePCR.ptr);
    ++g_measureExtends;
}

// Add a module's expected hash to a manifest.
public bool manifestAdd(ref Manifest m, uint nameHash, const(ubyte)* hash32) {
    if (m.count >= MANIFEST_MAX) return false;
    auto e = &m.e[m.count];
    e.inUse = true;
    e.nameHash = nameHash;
    foreach (i; 0 .. 32) e.hash[i] = hash32[i];
    ++m.count;
    return true;
}

// Sign the manifest (over the concatenated entry hashes) with the trusted key.
public void manifestSign(ref Manifest m) {
    ubyte[32 * MANIFEST_MAX] body_;
    uint n = 0;
    foreach (k; 0 .. m.count)
        foreach (i; 0 .. 32) body_[n++] = m.e[k].hash[i];
    cryptoSign(body_.ptr, n, m.sig.ptr);
}

private bool manifestSigValid(ref const(Manifest) m) {
    ubyte[32 * MANIFEST_MAX] body_;
    uint n = 0;
    foreach (k; 0 .. m.count)
        foreach (i; 0 .. 32) body_[n++] = m.e[k].hash[i];
    return cryptoVerify(body_.ptr, n, m.sig.ptr);
}

private bool manifestHasHash(ref const(Manifest) m, const(ubyte)* hash32) {
    foreach (k; 0 .. m.count)
        if (ctEqual32(m.e[k].hash.ptr, hash32)) return true;
    return false;
}

// Verify a measured module against a signed manifest: the manifest signature must
// verify AND the module's measured hash must be one of its entries.  A tampered
// module (different hash) or a forged manifest (bad signature) fails.
public bool verifyModule(ref const(Manifest) m, const(ubyte)* moduleData, ulong len) {
    if (!manifestSigValid(m)) { ++g_verifyFail; return false; }
    ubyte[32] h;
    sha256(moduleData, len, h.ptr);
    if (!manifestHasHash(m, h.ptr)) { ++g_verifyFail; return false; }
    ++g_verifyOk;
    return true;
}

// === proof ====================================================================
private immutable ubyte[32] V_ABC = [   // SHA-256("abc")
    0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
    0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad,
];
private immutable ubyte[32] V_EMPTY = [ // SHA-256("")
    0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
    0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55,
];
private immutable ubyte[32] V_HMAC = [  // RFC 4231 TC1: HMAC-SHA256(0x0b*20, "Hi There")
    0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
    0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7,
];

private bool selfTestSha() {
    ubyte[32] d;
    sha256(cast(const(ubyte)*)"abc".ptr, 3, d.ptr);
    bool abc = ctEqual32(d.ptr, V_ABC.ptr);
    sha256(cast(const(ubyte)*)"".ptr, 0, d.ptr);
    bool empty = ctEqual32(d.ptr, V_EMPTY.ptr);
    // A one-bit change in the input changes the digest.
    ubyte[3] abd = ['a','b','d'];
    sha256(abd.ptr, 3, d.ptr);
    bool diff = !ctEqual32(d.ptr, V_ABC.ptr);
    return abc && empty && diff;
}

private bool selfTestHmac() {
    ubyte[20] key; foreach (i; 0 .. 20) key[i] = 0x0b;
    ubyte[8] msg = ['H','i',' ','T','h','e','r','e'];
    ubyte[32] mac;
    hmacSha256(key.ptr, 20, msg.ptr, 8, mac.ptr);
    bool vector = ctEqual32(mac.ptr, V_HMAC.ptr);
    // Sign/verify round-trip under the trusted key, and reject a tampered message.
    ubyte[5] m = ['h','e','l','l','o'];
    ubyte[32] sig; cryptoSign(m.ptr, 5, sig.ptr);
    bool accept = cryptoVerify(m.ptr, 5, sig.ptr);
    m[0] = 'j';
    bool reject = !cryptoVerify(m.ptr, 5, sig.ptr);
    return vector && accept && reject;
}

private bool selfTestMeasuredBoot() {
    static immutable ubyte[6] modA = ['k','e','r','n','e','l'];
    static immutable ubyte[5] modB = ['i','n','i','t','d'];
    ubyte[32] hA, hB;
    sha256(modA.ptr, modA.length, hA.ptr);
    sha256(modB.ptr, modB.length, hB.ptr);

    // Build + sign a manifest of the two modules.
    Manifest m;
    m.count = 0;
    manifestAdd(m, 0xAAAA, hA.ptr);
    manifestAdd(m, 0xBBBB, hB.ptr);
    manifestSign(m);

    bool okA = verifyModule(m, modA.ptr, modA.length);   // genuine module verifies
    // A tampered module's hash is not in the manifest ⇒ refused.
    ubyte[6] bad = ['k','e','r','n','e','X'];
    bool tamper = !verifyModule(m, bad.ptr, bad.length);
    // A forged manifest (signature does not verify) ⇒ refused.
    Manifest f = m;
    f.sig[0] ^= 0x80;
    bool forged = !verifyModule(f, modA.ptr, modA.length);

    // Measurement register: extending with two modules is order-dependent and
    // non-zero (a real boot-attestation property).
    measureReset();
    measureExtend(hA.ptr);
    measureExtend(hB.ptr);
    ubyte[32] pcr1; foreach (i; 0 .. 32) pcr1[i] = g_measurePCR[i];
    measureReset();
    measureExtend(hB.ptr);
    measureExtend(hA.ptr);
    bool orderDependent = !ctEqual32(pcr1.ptr, g_measurePCR.ptr);
    bool nonZero = false; foreach (i; 0 .. 32) if (pcr1[i] != 0) nonZero = true;

    return okA && tamper && forged && orderDependent && nonZero;
}

public void cryptoSelfTest() {
    if (g_cryptoSelfTested) return;
    g_cryptoSelfTested = true;
    bool sha = selfTestSha();
    bool hmac = selfTestHmac();
    bool boot = selfTestMeasuredBoot();
    if (sha && hmac && boot) {
        klog("[crypto] selftest PASS\n");
    } else {
        klog("[crypto] selftest FAIL:");
        if (!sha)  klog(" sha256");
        if (!hmac) klog(" hmac");
        if (!boot) klog(" measuredboot");
        klog("\n");
    }
}

public void cryptoStats() {
    klog("[crypto] extends="); klog_hex(g_measureExtends);
    klog(" verifyok=");        klog_hex(g_verifyOk);
    klog(" verifyfail=");      klog_hex(g_verifyFail);
    klog("\n");
}
