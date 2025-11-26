module anonymos.userland.secure_ipc;

import core.stdc.stdint : size_t, ssize_t;
import core.stdc.string : memcpy;
import core.stdc.stdlib : malloc, free;
import anonymos.userland.crypto;
import anonymos.userland.crypto_handshake;
import anonymos.userland.service_identity;
import anonymos.userland.peer_info;

extern (C):

alias IpcHandle = int;
IpcHandle ipc_open_endpoint(const char* name);
IpcHandle ipc_connect(const char* name);
ssize_t ipc_send(IpcHandle h, const void* buf, size_t len);
ssize_t ipc_recv(IpcHandle h, void* buf, size_t maxlen);
void ipc_close(IpcHandle h);

struct SecureChannel
{
    IpcHandle handle;
    ubyte[32] txKey;
    ubyte[32] rxKey;
    uint64_t txNonce;
    uint64_t rxNonce;
    PeerInfo peer;
    bool established;
}

@nogc nothrow:

private void encodeNonce(uint64_t n, out ubyte[12] nonce) @nogc nothrow
{
    // Little endian counter in lower 8 bytes; remaining zero.
    foreach (i; 0 .. 8)
    {
        nonce[i] = cast(ubyte)((n >> (i*8)) & 0xFF);
    }
    foreach (i; 8 .. 12) nonce[i] = 0;
}

/// Perform XX handshake over ipc handle. Assumes both sides call in order:
/// Client: connect -> secureIpcClientXX
/// Server: open -> secureIpcServerXX
bool secureIpcClientXX(IpcHandle h, ref SecureChannel chan,
                       ref const ServiceIdentity myId,
                       ref const ServiceIdentity peerExpected) @nogc nothrow
{
    HandshakeState hs;
    X25519Keypair myStatic;
    if (!ed25519ToX25519(myStatic, *(cast(Ed25519Keypair*)&myId))) {}
    initXX(hs, Role.initiator, &myStatic);

    // msg0: e
    ubyte[64] buf;
    size_t outLen;
    if (!writeMessage(hs, [], buf[], outLen)) return false;
    if (ipc_send(h, buf.ptr, outLen) != cast(ssize_t)outLen) return false;

    // msg1: re, enc(rs), enc(payload)
    ubyte[256] inBuf;
    auto rlen = ipc_recv(h, inBuf.ptr, inBuf.length);
    if (rlen <= 0) return false;
    ubyte[256] plain;
    size_t plainLen;
    if (!readMessage(hs, inBuf[0 .. rlen], plain[], plainLen)) return false;

    // msg2: send our static + payload (include our service_id hash as payload)
    auto sidBytes = cast(const ubyte[])(myId.service_id[0 .. std.string.strlen(myId.service_id)]);
    if (!writeMessage(hs, sidBytes, buf[], outLen)) return false;
    if (ipc_send(h, buf.ptr, outLen) != cast(ssize_t)outLen) return false;

    // derive keys
    if (!split(hs, chan.txKey, chan.rxKey)) return false;
    chan.handle = h;
    chan.txNonce = 0;
    chan.rxNonce = 0;
    chan.established = true;
    // fill peer info (basic)
    chan.peer.service_id = peerExpected.service_id;
    chan.peer.code_hash = peerExpected.code_hash;
    chan.peer.roles = peerExpected.roles;
    return true;
}

bool secureIpcServerXX(IpcHandle h, ref SecureChannel chan,
                       ref const ServiceIdentity myId,
                       out ServiceIdentity remoteId) @nogc nothrow
{
    HandshakeState hs;
    X25519Keypair myStatic;
    if (!ed25519ToX25519(myStatic, *(cast(Ed25519Keypair*)&myId))) {}
    initXX(hs, Role.responder, &myStatic);

    // recv msg0
    ubyte[256] inBuf;
    auto rlen = ipc_recv(h, inBuf.ptr, inBuf.length);
    if (rlen <= 0) return false;
    ubyte[256] plain;
    size_t plainLen;
    if (!readMessage(hs, inBuf[0 .. rlen], plain[], plainLen)) return false;

    // msg1
    ubyte[256] outBuf;
    size_t outLen;
    if (!writeMessage(hs, [], outBuf[], outLen)) return false;
    if (ipc_send(h, outBuf.ptr, outLen) != cast(ssize_t)outLen) return false;

    // recv msg2 (should contain peer service_id as payload)
    rlen = ipc_recv(h, inBuf.ptr, inBuf.length);
    if (rlen <= 0) return false;
    if (!readMessage(hs, inBuf[0 .. rlen], plain[], plainLen)) return false;

    // derive keys
    if (!split(hs, chan.txKey, chan.rxKey)) return false;
    chan.handle = h;
    chan.txNonce = 0;
    chan.rxNonce = 0;
    chan.established = true;
    // Populate minimal remoteId
    remoteId.service_id = cast(char*)malloc(plainLen+1);
    if (remoteId.service_id !is null)
    {
        memcpy(remoteId.service_id, plain.ptr, plainLen);
        remoteId.service_id[plainLen] = 0;
    }
    return true;
}

ssize_t secure_send(ref SecureChannel chan, const ubyte[] plaintext, const ubyte[] ad) @nogc nothrow
{
    if (!chan.established) return -1;
    ubyte[12] nonce;
    encodeNonce(chan.txNonce++, nonce);
    ubyte[] outBuf;
    outBuf.length = plaintext.length + crypto_aead_chacha20poly1305_ietf_ABYTES;
    if (!aeadEncrypt(chan.txKey, nonce, plaintext, ad, outBuf)) return -2;
    auto sent = ipc_send(chan.handle, outBuf.ptr, outBuf.length);
    return sent;
}

ssize_t secure_recv(ref SecureChannel chan, ubyte[] ciphertext, ubyte[] outPlain, const ubyte[] ad, out size_t plainLen) @nogc nothrow
{
    plainLen = 0;
    if (!chan.established) return -1;
    auto rlen = ipc_recv(chan.handle, ciphertext.ptr, ciphertext.length);
    if (rlen <= 0) return rlen;
    ubyte[12] nonce;
    encodeNonce(chan.rxNonce++, nonce);
    outPlain.length = rlen - crypto_aead_chacha20poly1305_ietf_ABYTES;
    if (!aeadDecrypt(chan.rxKey, nonce, ciphertext[0 .. rlen], ad, outPlain))
        return -2;
    plainLen = outPlain.length;
    return rlen;
}
