module kernel.ipc.secure_ipc;

import core.stdc.stdint : uint64_t;
import core.stdc.string : memcpy;

enum ulong PRIME = 0xffffffffffc5UL; // not cryptographically strong
enum ulong BASE = 5;

struct DhKeyPair {
    ulong priv;
    ulong pub;
}

ulong modexp(ulong base, ulong exp, ulong mod)
{
    ulong result = 1;
    base %= mod;
    while(exp > 0)
    {
        if(exp & 1) result = (result * base) % mod;
        exp >>= 1;
        base = (base * base) % mod;
    }
    return result;
}

DhKeyPair dh_generate(ulong priv)
{
    DhKeyPair kp;
    kp.priv = priv;
    kp.pub = modexp(BASE, priv, PRIME);
    return kp;
}

ulong dh_compute_shared(ulong peer_pub, ulong my_priv)
{
    return modexp(peer_pub, my_priv, PRIME);
}

ulong simple_checksum(const(void)* data, size_t len)
{
    auto p = cast(const ubyte*)data;
    ulong sum = 0;
    for(size_t i=0;i<len;i++)
        sum = (sum * 131) + p[i];
    return sum;
}

struct SecureSession
{
    ulong key;
    ulong token; // used in signatures
}

void session_init(ref SecureSession s, ulong key, ulong token)
{
    s.key = key;
    s.token = token;
}

void encrypt(ref SecureSession s, ubyte[] data)
{
    foreach(i, ref b; data)
        b ^= cast(ubyte)(s.key >> ((i % 8) * 8));
}

alias decrypt = encrypt; // XOR symmetric

ulong sign_message(ref SecureSession s, const(ubyte)[] msg)
{
    return simple_checksum(msg.ptr, msg.length) ^ s.token;
}

bool verify_message(ref SecureSession s, const(ubyte)[] msg, ulong signature)
{
    return sign_message(s, msg) == signature;
}

struct RendezvousInfo
{
    ulong hash; // hash of rendezvous string
}

ulong hash_string(const(char)* s)
{
    ulong h = 5381;
    size_t i=0;
    while(s[i])
    {
        h = ((h << 5) + h) + cast(ubyte)s[i];
        i++;
    }
    return h;
}

void prepare_rendezvous(ref RendezvousInfo info, const(char)* name)
{
    info.hash = hash_string(name);
}

bool verify_rendezvous(ref RendezvousInfo a, ref RendezvousInfo b)
{
    return a.hash == b.hash;
}
