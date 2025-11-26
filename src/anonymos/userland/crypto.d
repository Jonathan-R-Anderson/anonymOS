module anonymos.userland.crypto;

import core.stdc.string : memset;
import core.stdc.stdint : uint8_t, uint32_t;

// Thin, no-stub bindings to libsodium. All routines expect sodium_init() to
// succeed; call cryptoInit() once before use.
extern(C):
int sodium_init();

int crypto_sign_ed25519_keypair(ubyte* pk, ubyte* sk);
int crypto_sign_ed25519_sk_to_pk(ubyte* pk, const ubyte* sk);
int crypto_sign_ed25519_detached(ubyte* sig, ulong* siglen,
                                 const ubyte* m, ulong mlen,
                                 const ubyte* sk);
int crypto_sign_ed25519_verify_detached(const ubyte* sig,
                                        const ubyte* m, ulong mlen,
                                        const ubyte* pk);
int crypto_scalarmult_curve25519_base(ubyte* q, const ubyte* n);
int crypto_scalarmult_curve25519(ubyte* q, const ubyte* n, const ubyte* p);
int crypto_sign_ed25519_pk_to_curve25519(ubyte* curve25519_pk,
                                         const ubyte* ed25519_pk);
int crypto_sign_ed25519_sk_to_curve25519(ubyte* curve25519_sk,
                                         const ubyte* ed25519_sk);
void randombytes_buf(void* const buf, const size_t size);

int crypto_hash_sha256(ubyte* out, const ubyte* in, ulong inlen);

struct crypto_auth_hmacsha256_state
{
    align(8) ubyte[208] opaque;
}
int crypto_auth_hmacsha256_init(crypto_auth_hmacsha256_state* state,
                                const ubyte* key, size_t keylen);
int crypto_auth_hmacsha256_update(crypto_auth_hmacsha256_state* state,
                                  const ubyte* in, size_t inlen);
int crypto_auth_hmacsha256_final(crypto_auth_hmacsha256_state* state,
                                 ubyte* out);

enum crypto_aead_chacha20poly1305_ietf_KEYBYTES = 32;
enum crypto_aead_chacha20poly1305_ietf_NPUBBYTES = 12;
enum crypto_aead_chacha20poly1305_ietf_ABYTES = 16;
int crypto_aead_chacha20poly1305_ietf_encrypt(ubyte* c, ulong* clen_p,
                                              const ubyte* m, ulong mlen,
                                              const ubyte* ad, ulong adlen,
                                              const ubyte* nsec,
                                              const ubyte* npub,
                                              const ubyte* k);
int crypto_aead_chacha20poly1305_ietf_decrypt(ubyte* m, ulong* mlen_p,
                                              ubyte* nsec,
                                              const ubyte* c, ulong clen,
                                              const ubyte* ad, ulong adlen,
                                              const ubyte* npub,
                                              const ubyte* k);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

@nogc nothrow:

bool cryptoInit()
{
    return sodium_init() >= 0;
}

struct Ed25519Keypair { ubyte[32] pk; ubyte[64] sk; }
struct X25519Keypair  { ubyte[32] pk; ubyte[32] sk; }

Ed25519Keypair ed25519Generate() @nogc nothrow
{
    Ed25519Keypair kp;
    crypto_sign_ed25519_keypair(kp.pk.ptr, kp.sk.ptr);
    return kp;
}

X25519Keypair x25519Generate() @nogc nothrow
{
    X25519Keypair kp;
    randombytes_buf(kp.sk.ptr, kp.sk.length);
    crypto_scalarmult_curve25519_base(kp.pk.ptr, kp.sk.ptr);
    return kp;
}

bool ed25519ToX25519(out X25519Keypair outkp, ref const Ed25519Keypair inpk) @nogc nothrow
{
    // libsodium requires the full Ed25519 secret to derive the Curve25519 secret
    if (crypto_sign_ed25519_sk_to_curve25519(outkp.sk.ptr, inpk.sk.ptr) != 0)
        return false;
    if (crypto_sign_ed25519_pk_to_curve25519(outkp.pk.ptr, inpk.pk.ptr) != 0)
        return false;
    return true;
}

bool ed25519Sign(const ubyte[] msg, ref const Ed25519Keypair kp, out ubyte[64] sig) @nogc nothrow
{
    ulong siglen = 0;
    const int rc = crypto_sign_ed25519_detached(sig.ptr, &siglen, msg.ptr, msg.length, kp.sk.ptr);
    return rc == 0 && siglen == 64;
}

bool ed25519Verify(const ubyte[] msg, const ubyte[64] sig, const ubyte[32] pk) @nogc nothrow
{
    return crypto_sign_ed25519_verify_detached(sig.ptr, msg.ptr, msg.length, pk.ptr) == 0;
}

/// X25519 DH
bool x25519Shared(const ubyte[32] sk, const ubyte[32] pk, out ubyte[32] shared) @nogc nothrow
{
    return crypto_scalarmult_curve25519(shared.ptr, sk.ptr, pk.ptr) == 0;
}

// HKDF-SHA256 (extract+expand) yielding up to two 32-byte outputs.
private void hmacSha256(const ubyte[] key, const ubyte[] data, out ubyte[32] outTag) @nogc nothrow
{
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key.ptr, key.length);
    crypto_auth_hmacsha256_update(&st, data.ptr, data.length);
    crypto_auth_hmacsha256_final(&st, outTag.ptr);
}

void hkdfSha256(const ubyte[] salt, const ubyte[] ikm,
                out ubyte[32] okm1, out ubyte[32] okm2) @nogc nothrow
{
    ubyte prk[32];
    hmacSha256(salt, ikm, prk);

    // T1 = HMAC(prk, 0x01)
    ubyte t1_input[1] = [1];
    hmacSha256(prk[], t1_input[], okm1);

    // T2 = HMAC(prk, T1 || 0x02)
    ubyte[33] t2buf;
    // copy T1
    foreach (i; 0 .. 32) t2buf[i] = okm1[i];
    t2buf[32] = 2;
    hmacSha256(prk[], t2buf[], okm2);

    // Wipe prk
    memset(prk.ptr, 0, prk.length);
}

// AEAD with ChaCha20-Poly1305 (IETF)
bool aeadEncrypt(const ubyte[32] key, const ubyte[12] nonce,
                 const ubyte[] plaintext, const ubyte[] ad,
                 ref ubyte[] outCipher) @nogc nothrow
{
    // outCipher must be sized by caller: plaintext.length + 16
    if (outCipher.length < plaintext.length + crypto_aead_chacha20poly1305_ietf_ABYTES)
        return false;
    ulong clen = 0;
    const int rc = crypto_aead_chacha20poly1305_ietf_encrypt(outCipher.ptr, &clen,
                                                             plaintext.ptr, plaintext.length,
                                                             ad.ptr, ad.length,
                                                             null,
                                                             nonce.ptr, key.ptr);
    return rc == 0 && clen == outCipher.length;
}

bool aeadDecrypt(const ubyte[32] key, const ubyte[12] nonce,
                 const ubyte[] ciphertext, const ubyte[] ad,
                 ref ubyte[] outPlain) @nogc nothrow
{
    if (ciphertext.length < crypto_aead_chacha20poly1305_ietf_ABYTES)
        return false;
    if (outPlain.length + crypto_aead_chacha20poly1305_ietf_ABYTES != ciphertext.length)
        return false;
    ulong mlen = 0;
    const int rc = crypto_aead_chacha20poly1305_ietf_decrypt(outPlain.ptr, &mlen,
                                                             null,
                                                             ciphertext.ptr, ciphertext.length,
                                                             ad.ptr, ad.length,
                                                             nonce.ptr, key.ptr);
    return rc == 0 && mlen == outPlain.length;
}

// ---------------------------------------------------------------------------
// Simple X25519-based IPC key exchange (two-message, symmetric)
// Client: call ipcKxClientStart() -> send pub_eC
// Server: ipcKxServerReply(pub_eC) -> returns pub_eS, txKey, rxKey for server
// Client: ipcKxClientFinish(pub_eS) -> returns txKey, rxKey for client
// Both sides derive matching tx/rx keys (per-role) via HKDF-SHA256.
// ---------------------------------------------------------------------------

struct IpcKxClientState
{
    X25519Keypair e;
    ubyte[32] shared;
    bool ready;
}

X25519Keypair ipcKxClientStart(out IpcKxClientState state) @nogc nothrow
{
    state.ready = false;
    state.e = x25519Generate();
    return state.e;
}

bool ipcKxServerReply(const ubyte[32] clientPub,
                      out X25519Keypair serverKeys,
                      out ubyte[32] txKey,
                      out ubyte[32] rxKey) @nogc nothrow
{
    serverKeys = x25519Generate();
    ubyte shared[32];
    if (!x25519Shared(serverKeys.sk, clientPub, shared))
        return false;
    // HKDF with role separation: info = "ipc-kx" || role byte
    ubyte[9] salt = [ 'i','p','c','-','k','x',0,0,0 ];
    salt[6] = 's';
    salt[7] = 'r';
    salt[8] = 'v';
    hkdfSha256(salt[], shared[], txKey, rxKey); // server txKey, rxKey
    return true;
}

bool ipcKxClientFinish(ref IpcKxClientState state,
                       const ubyte[32] serverPub,
                       out ubyte[32] txKey,
                       out ubyte[32] rxKey) @nogc nothrow
{
    if (!x25519Shared(state.e.sk, serverPub, state.shared))
        return false;
    ubyte[9] salt = [ 'i','p','c','-','k','x',0,0,0 ];
    salt[6] = 'c';
    salt[7] = 'l';
    salt[8] = 'i';
    hkdfSha256(salt[], state.shared[], txKey, rxKey); // client txKey, rxKey
    state.ready = true;
    return true;
}
