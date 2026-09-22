module core.random;

import core.io : klog, klog_hex;

@nogc nothrow:

private __gshared ulong[64] entropyPool;
private __gshared ulong entropyIndex = 0;
private __gshared ulong rngState0 = 0x243F6A8885A308D3UL;
private __gshared ulong rngState1 = 0x13198A2E03707344UL;
private __gshared ulong rngState2 = 0xA4093822299F31D0UL;
private __gshared ulong rngState3 = 0x082EFA98EC4E6C89UL;
private __gshared bool rngReady = false;

public ulong rdtsc()
{
    ulong tsc;

    asm @nogc nothrow
    {
        rdtsc;
        shl RDX, 32;
        or RAX, RDX;
        mov tsc, RAX;
    }

    return tsc;
}

private ulong rotl64(ulong x, uint k)
{
    return (x << k) | (x >> (64 - k));
}

private ulong splitmix64(ref ulong x)
{
    x += 0x9E3779B97F4A7C15UL;

    ulong z = x;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
    return z ^ (z >> 31);
}

public void random_add_entropy(ulong value)
{
    ulong t = rdtsc();
    ulong mixed = value ^ t ^ entropyIndex;

    mixed ^= mixed >> 33;
    mixed *= 0xff51afd7ed558ccdUL;
    mixed ^= mixed >> 33;
    mixed *= 0xc4ceb9fe1a85ec53UL;
    mixed ^= mixed >> 33;

    entropyPool[entropyIndex & 63] ^= mixed;
    entropyPool[(entropyIndex + 17) & 63] += rotl64(mixed, 23);
    entropyPool[(entropyIndex + 41) & 63] ^= rotl64(mixed, 47);

    rngState0 ^= mixed;
    rngState1 += rotl64(mixed, 13);
    rngState2 ^= rotl64(mixed, 29);
    rngState3 += 0x9E3779B97F4A7C15UL ^ mixed;

    entropyIndex++;
}

private ulong mix_pool()
{
    ulong x = rdtsc() ^ entropyIndex;

    foreach (i; 0 .. 64)
    {
        x ^= entropyPool[i];
        x = rotl64(x, 27);
        x *= 0x9E3779B97F4A7C15UL;
        x ^= x >> 31;
    }

    random_add_entropy(x);
    return x;
}

// Xoshiro256** style generator, reseeded/mixed from entropyPool.
public ulong random_get64()
{
    if (!rngReady)
        random_init();

    ulong result = rotl64(rngState1 * 5, 7) * 9;
    ulong t = rngState1 << 17;

    rngState2 ^= rngState0;
    rngState3 ^= rngState1;
    rngState1 ^= rngState2;
    rngState0 ^= rngState3;
    rngState2 ^= t;
    rngState3 = rotl64(rngState3, 45);

    result ^= mix_pool();

    return result;
}

public void random_get_bytes(void* outBuf, ulong len)
{
    auto buf = cast(ubyte*)outBuf;
    ulong produced = 0;

    while (produced < len)
    {
        ulong r = random_get64();

        foreach (i; 0 .. 8)
        {
            if (produced >= len)
                break;

            buf[produced++] = cast(ubyte)((r >> (i * 8)) & 0xff);
        }
    }
}

public void random_init()
{
    ulong seed = rdtsc();

    // Mix boot-time timing jitter.
    foreach (i; 0 .. 1024)
    {
        seed ^= rdtsc();
        seed = splitmix64(seed);
        random_add_entropy(seed ^ cast(ulong)i);
    }

    // Initialize generator state from mixed seed.
    rngState0 = splitmix64(seed);
    rngState1 = splitmix64(seed);
    rngState2 = splitmix64(seed);
    rngState3 = splitmix64(seed);

    // Mix entropy pool into generator state.
    foreach (i; 0 .. 64)
    {
        rngState0 ^= entropyPool[i];
        rngState1 += rotl64(entropyPool[i], 11);
        rngState2 ^= rotl64(entropyPool[i], 29);
        rngState3 += rotl64(entropyPool[i], 47);
    }

    rngReady = true;

    klog("[random] initialized\n");
}
// ── Bulk CSPRNG for the installer's random fill (INSTALLER §E4a/F2) ─────────────────────────────
//
// random_get_bytes() above stirs the entropy pool for EVERY 8 bytes it emits (mix_pool: a
// 64-iteration hash loop plus rdtsc per word).  That is the right shape for keys and salts, and
// the wrong shape for filling a 3 GB outer volume: it ran at ~8 MB/s with the kernel lock held,
// which is most of why an encrypted install froze the desktop.  A ChaCha20 keystream keyed from
// the pool is a proper CSPRNG (RFC 8439 core, 20 rounds), costs ~a dozen ARX ops per byte, and --
// the point for the second-core worker -- keeps ALL its state in the caller's context, so two CPUs
// can each own one without a lock or any shared RNG state.
public struct ChaChaCtx {
    uint[16] st;        // constants | key (8) | counter (1) | nonce (3)
    ulong    produced;  // bytes emitted since keying; rekey after CHACHA_REKEY_BYTES
}
enum ulong CHACHA_REKEY_BYTES = 64UL << 20;   // fresh key from the pool every 64 MiB

private uint rotl32(uint x, uint r) { return (x << r) | (x >> (32 - r)); }

// Key from the pool: 8 key words + 3 nonce words drawn from random_get64().  MUST be called on the
// BSP under the kernel lock (random_get64 touches the global pool); afterwards the context is
// self-contained and may be driven from any CPU.
public void chacha_seed(ref ChaChaCtx c) {
    c.st[0] = 0x61707865; c.st[1] = 0x3320646e; c.st[2] = 0x79622d32; c.st[3] = 0x6b206574;
    foreach (i; 0 .. 4) { const ulong r = random_get64(); c.st[4 + 2*i] = cast(uint)r; c.st[5 + 2*i] = cast(uint)(r >> 32); }
    c.st[12] = 0;                                              // block counter
    { const ulong r = random_get64(); c.st[13] = cast(uint)r; c.st[14] = cast(uint)(r >> 32); }
    c.st[15] = cast(uint)random_get64();
    c.produced = 0;
}
public bool chacha_needs_reseed(ref const ChaChaCtx c) { return c.produced >= CHACHA_REKEY_BYTES; }

private void chacha_block(ref const uint[16] input, ref uint[16] output) {
    uint[16] x = input;
    static void qr(ref uint a, ref uint b, ref uint c, ref uint d) @nogc nothrow {
        a += b; d ^= a; d = rotl32(d, 16);
        c += d; b ^= c; b = rotl32(b, 12);
        a += b; d ^= a; d = rotl32(d, 8);
        c += d; b ^= c; b = rotl32(b, 7);
    }
    foreach (_; 0 .. 10) {
        qr(x[0], x[4], x[8],  x[12]); qr(x[1], x[5], x[9],  x[13]);
        qr(x[2], x[6], x[10], x[14]); qr(x[3], x[7], x[11], x[15]);
        qr(x[0], x[5], x[10], x[15]); qr(x[1], x[6], x[11], x[12]);
        qr(x[2], x[7], x[8],  x[13]); qr(x[3], x[4], x[9],  x[14]);
    }
    foreach (i; 0 .. 16) output[i] = x[i] + input[i];
}

// Fill `len` bytes of keystream.  No pool access, no globals: safe on the AP.
public void chacha_fill(ref ChaChaCtx c, ubyte* outBuf, ulong len) {
    uint[16] blk = void;
    ulong done = 0;
    while (done < len) {
        chacha_block(c.st, blk);
        if (++c.st[12] == 0) ++c.st[13];                       // 64-bit counter across words 12/13
        const ulong n = (len - done) < 64 ? (len - done) : 64;
        auto src = cast(const(ubyte)*)blk.ptr;
        foreach (i; 0 .. cast(size_t)n) outBuf[done + i] = src[i];
        done += n;
    }
    c.produced += len;
}

// Fast-key-erasure ratchet: derive the next key + nonce from the generator's own keystream and
// reset the counter.  Lets a context that lives on another CPU (no access to the pool) rekey
// itself every CHACHA_REKEY_BYTES without any shared state.
public void chacha_ratchet(ref ChaChaCtx c) {
    ubyte[44] fresh = void;
    chacha_fill(c, fresh.ptr, 44);
    foreach (i; 0 .. 11) {
        c.st[4 + i] = cast(uint)fresh[4*i] | (cast(uint)fresh[4*i+1] << 8) |
                      (cast(uint)fresh[4*i+2] << 16) | (cast(uint)fresh[4*i+3] << 24);
    }
    c.st[12] = 0;
    c.produced = 0;
    foreach (i; 0 .. 44) fresh[i] = 0;
}
