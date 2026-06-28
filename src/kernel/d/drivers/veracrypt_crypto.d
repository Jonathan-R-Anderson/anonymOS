// ─────────────────────────────────────────────────────────────────────────────
// Real AES-256 + SHA-512 for the kernel (roadmap/INSTALLER.md §E2b)
//
// Replaces the do-nothing crypto stubs (core/stubs.d) with correct, pure-D
// primitives so veracrypt_impl.d can build real VeraCrypt volume headers at install
// time.  The kernel's header WRITE path needs only AES-256 single-block ENCRYPT
// (for XTS + the XTS tweak) and SHA-512 (for PBKDF2-HMAC); decrypt/open lives on the
// host reference (deps/veracrypt/vcheader.c).  Validated in-kernel by vcCryptoKat()
// against FIPS-197 (AES-256) and the NIST SHA-512("abc") vector, and end-to-end by
// the §E2b header cross-check (kernel writes a header → host vc_open_header opens it).
//
// extern(C) names match the declarations in veracrypt_impl.d.
// ─────────────────────────────────────────────────────────────────────────────
module drivers.veracrypt_crypto;

import core.io : klog;

@nogc nothrow:

// ── AES-256 ──────────────────────────────────────────────────────────────────
private immutable ubyte[256] SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];
private immutable ubyte[7] RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40];

private ubyte xtime(ubyte x) { return cast(ubyte)((x << 1) ^ (((x >> 7) & 1) * 0x1b)); }

// Expand a 32-byte AES-256 key into 15 round keys (240 bytes).
private void aes256_expand(const(ubyte)* key, ubyte* rk) {
    foreach (i; 0 .. 32) rk[i] = key[i];
    uint bytes = 32;
    ubyte rconIdx = 0;
    ubyte[4] t;
    while (bytes < 240) {
        foreach (i; 0 .. 4) t[i] = rk[bytes - 4 + i];
        if (bytes % 32 == 0) {
            // RotWord
            ubyte tmp = t[0]; t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = tmp;
            // SubWord
            foreach (i; 0 .. 4) t[i] = SBOX[t[i]];
            t[0] ^= RCON[rconIdx++];
        } else if (bytes % 32 == 16) {
            // AES-256: extra SubWord at the midpoint
            foreach (i; 0 .. 4) t[i] = SBOX[t[i]];
        }
        foreach (i; 0 .. 4) { rk[bytes] = cast(ubyte)(rk[bytes - 32] ^ t[i]); bytes++; }
    }
}

// Encrypt one 16-byte block in place under `key` (32 bytes).  AES-256, 14 rounds.
extern(C) void aes_encrypt(ubyte* data, const(ubyte)* key) {
    ubyte[240] rk = void;
    aes256_expand(key, rk.ptr);
    ubyte[16] s = void;
    foreach (i; 0 .. 16) s[i] = cast(ubyte)(data[i] ^ rk[i]);

    foreach (round; 1 .. 14) {
        foreach (i; 0 .. 16) s[i] = SBOX[s[i]];                 // SubBytes
        shiftRows(s.ptr);                                       // ShiftRows
        mixColumns(s.ptr);                                      // MixColumns
        foreach (i; 0 .. 16) s[i] ^= rk[round * 16 + i];        // AddRoundKey
    }
    foreach (i; 0 .. 16) s[i] = SBOX[s[i]];                     // final SubBytes
    shiftRows(s.ptr);                                           // final ShiftRows
    foreach (i; 0 .. 16) data[i] = cast(ubyte)(s[i] ^ rk[14 * 16 + i]);
}

private void shiftRows(ubyte* s) {
    ubyte t;
    t = s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;                 // row1 <<1
    t = s[2]; s[2]=s[10]; s[10]=t; t = s[6]; s[6]=s[14]; s[14]=t;       // row2 <<2
    t = s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;              // row3 <<3
}

private void mixColumns(ubyte* s) {
    foreach (c; 0 .. 4) {
        ubyte* col = s + c * 4;
        ubyte b0 = col[0], b1 = col[1], b2 = col[2], b3 = col[3];
        col[0] = cast(ubyte)(xtime(b0) ^ (xtime(b1) ^ b1) ^ b2 ^ b3);
        col[1] = cast(ubyte)(b0 ^ xtime(b1) ^ (xtime(b2) ^ b2) ^ b3);
        col[2] = cast(ubyte)(b0 ^ b1 ^ xtime(b2) ^ (xtime(b3) ^ b3));
        col[3] = cast(ubyte)((xtime(b0) ^ b0) ^ b1 ^ b2 ^ xtime(b3));
    }
}

// ── SHA-512 ──────────────────────────────────────────────────────────────────
private immutable ulong[80] K512 = [
    0x428a2f98d728ae22UL,0x7137449123ef65cdUL,0xb5c0fbcfec4d3b2fUL,0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL,0x59f111f1b605d019UL,0x923f82a4af194f9bUL,0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL,0x12835b0145706fbeUL,0x243185be4ee4b28cUL,0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL,0x80deb1fe3b1696b1UL,0x9bdc06a725c71235UL,0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL,0xefbe4786384f25e3UL,0x0fc19dc68b8cd5b5UL,0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL,0x4a7484aa6ea6e483UL,0x5cb0a9dcbd41fbd4UL,0x76f988da831153b5UL,
    0x983e5152ee66dfabUL,0xa831c66d2db43210UL,0xb00327c898fb213fUL,0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL,0xd5a79147930aa725UL,0x06ca6351e003826fUL,0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL,0x2e1b21385c26c926UL,0x4d2c6dfc5ac42aedUL,0x53380d139d95b3dfUL,
    0x650a73548baf63deUL,0x766a0abb3c77b2a8UL,0x81c2c92e47edaee6UL,0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL,0xa81a664bbc423001UL,0xc24b8b70d0f89791UL,0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL,0xd69906245565a910UL,0xf40e35855771202aUL,0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL,0x1e376c085141ab53UL,0x2748774cdf8eeb99UL,0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL,0x4ed8aa4ae3418acbUL,0x5b9cca4f7763e373UL,0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL,0x78a5636f43172f60UL,0x84c87814a1f0ab72UL,0x8cc702081a6439ecUL,
    0x90befffa23631e28UL,0xa4506cebde82bde9UL,0xbef9a3f7b2c67915UL,0xc67178f2e372532bUL,
    0xca273eceea26619cUL,0xd186b8c721c0c207UL,0xeada7dd6cde0eb1eUL,0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL,0x0a637dc5a2c898a6UL,0x113f9804bef90daeUL,0x1b710b35131c471bUL,
    0x28db77f523047d84UL,0x32caab7b40c72493UL,0x3c9ebe0a15c9bebcUL,0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL,0x597f299cfc657e2aUL,0x5fcb6fab3ad6faecUL,0x6c44198c4a475817UL,
];

private ulong ror64(ulong x, uint n) { return (x >> n) | (x << (64 - n)); }

private void sha512_block(ref ulong[8] h, const(ubyte)* p) {
    ulong[80] w = void;
    foreach (i; 0 .. 16) {
        ulong v = 0;
        foreach (j; 0 .. 8) v = (v << 8) | p[i * 8 + j];
        w[i] = v;
    }
    foreach (i; 16 .. 80) {
        ulong s0 = ror64(w[i-15], 1) ^ ror64(w[i-15], 8) ^ (w[i-15] >> 7);
        ulong s1 = ror64(w[i-2], 19) ^ ror64(w[i-2], 61) ^ (w[i-2] >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    ulong a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    foreach (i; 0 .. 80) {
        ulong S1 = ror64(e,14) ^ ror64(e,18) ^ ror64(e,41);
        ulong ch = (e & f) ^ (~e & g);
        ulong t1 = hh + S1 + ch + K512[i] + w[i];
        ulong S0 = ror64(a,28) ^ ror64(a,34) ^ ror64(a,39);
        ulong maj = (a & b) ^ (a & c) ^ (b & c);
        ulong t2 = S0 + maj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

// One-shot SHA-512.  `output` is 64 bytes.
extern(C) void sha512_hash(const(ubyte)* data, size_t len, ubyte* output) {
    ulong[8] h = [
        0x6a09e667f3bcc908UL,0xbb67ae8584caa73bUL,0x3c6ef372fe94f82bUL,0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL,0x9b05688c2b3e6c1fUL,0x1f83d9abfb41bd6bUL,0x5be0cd19137e2179UL,
    ];
    size_t full = len / 128;
    foreach (b; 0 .. full) sha512_block(h, data + b * 128);

    // Final block(s): copy the tail, append 0x80, pad, then the 128-bit bit-length.
    ubyte[256] buf = void;
    foreach (i; 0 .. 256) buf[i] = 0;
    size_t rem = len - full * 128;
    foreach (i; 0 .. rem) buf[i] = data[full * 128 + i];
    buf[rem] = 0x80;
    size_t blocks = (rem >= 112) ? 2 : 1;     // need a second block if no room for the length
    size_t total = blocks * 128;
    ulong bitsLow = cast(ulong)len << 3;
    ulong bitsHigh = cast(ulong)len >> 61;
    foreach (i; 0 .. 8) buf[total - 16 + i] = cast(ubyte)(bitsHigh >> (56 - 8 * i));
    foreach (i; 0 .. 8) buf[total - 8  + i] = cast(ubyte)(bitsLow  >> (56 - 8 * i));
    foreach (b; 0 .. blocks) sha512_block(h, buf.ptr + b * 128);

    foreach (i; 0 .. 8)
        foreach (j; 0 .. 8)
            output[i * 8 + j] = cast(ubyte)(h[i] >> (56 - 8 * j));
}

// ── Boot KAT: prove the primitives are correct against published vectors ──────
public void vcCryptoKat() {
    bool ok = true;

    // AES-256 (FIPS-197): key 000102..1f, pt 00112233..ff → ct 8ea2b7ca...4b496089
    ubyte[32] key = [
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f];
    ubyte[16] blk = [
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff];
    immutable ubyte[16] aesWant = [
        0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89];
    aes_encrypt(blk.ptr, key.ptr);
    foreach (i; 0 .. 16) if (blk[i] != aesWant[i]) ok = false;

    // SHA-512("abc")
    immutable ubyte[64] shaWant = [
        0xdd,0xaf,0x35,0xa1,0x93,0x61,0x7a,0xba,0xcc,0x41,0x73,0x49,0xae,0x20,0x41,0x31,
        0x12,0xe6,0xfa,0x4e,0x89,0xa9,0x7e,0xa2,0x0a,0x9e,0xee,0xe6,0x4b,0x55,0xd3,0x9a,
        0x21,0x92,0x99,0x2a,0x27,0x4f,0xc1,0xa8,0x36,0xba,0x3c,0x23,0xa3,0xfe,0xeb,0xbd,
        0x45,0x4d,0x44,0x23,0x64,0x3c,0xe8,0x0e,0x2a,0x9a,0xc9,0x4f,0xa5,0x4c,0xa4,0x9f];
    ubyte[3] abc = ['a','b','c'];
    ubyte[64] dig = void;
    sha512_hash(abc.ptr, 3, dig.ptr);
    foreach (i; 0 .. 64) if (dig[i] != shaWant[i]) ok = false;

    if (ok) klog("[vc-crypto] KAT PASS (AES-256 FIPS-197 + SHA-512 NIST)\n");
    else    klog("[vc-crypto] KAT FAIL\n");
}
