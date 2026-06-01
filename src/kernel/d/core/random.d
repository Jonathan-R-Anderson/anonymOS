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