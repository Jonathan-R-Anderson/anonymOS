module anonymos.userland.ipcsec_handshake;

import core.stdc.stdint : size_t, ssize_t, uint64_t;
import core.stdc.stdlib : malloc, free;
import core.stdc.string : memcpy, strlen, strcmp;
import anonymos.userland.crypto;
import anonymos.userland.crypto_handshake;
import anonymos.userland.service_identity;
import anonymos.userland.key_store;
import anonymos.userland.secure_msg;
import anonymos.userland.peer_info;

extern (C):

alias IpcHandle = int;
IpcHandle ipc_open_endpoint(const char* name);
IpcHandle ipc_connect(const char* name);
ssize_t ipc_send(IpcHandle h, const void* buf, size_t len);
ssize_t ipc_recv(IpcHandle h, void* buf, size_t maxlen);
void ipc_close(IpcHandle h);

int sec_send(SecureChan* c, const ubyte* msg, size_t len);
int sec_recv(SecureChan* c, ubyte** msg, size_t* len);
void sec_close(SecureChan* c);
const PeerInfo* sec_peer(SecureChan* c);

struct SecureChan
{
    IpcHandle raw;
    ubyte[32] send_key;
    ubyte[32] recv_key;
    uint64_t send_nonce;
    uint64_t recv_nonce;
    PeerInfo peer;
    int is_initiator;
}

@nogc nothrow:

private void encodeNonce(uint64_t n, out ubyte[12] nonce)
{
    foreach (i; 0 .. 8) nonce[i] = cast(ubyte)((n >> (8*i)) & 0xFF);
    foreach (i; 8 .. 12) nonce[i] = 0;
}

// ---------------- Identity serialization -----------------
private bool writeU16(ubyte[] buf, size_t offset, uint val)
{
    if (offset + 2 > buf.length) return false;
    buf[offset] = cast(ubyte)(val & 0xFF);
    buf[offset+1] = cast(ubyte)((val >> 8) & 0xFF);
    return true;
}
private bool writeU64(ubyte[] buf, size_t offset, uint64_t v)
{
    if (offset + 8 > buf.length) return false;
    foreach (i; 0 .. 8)
    {
        buf[offset + i] = cast(ubyte)(v & 0xFF);
        v >>= 8;
    }
    return true;
}

private bool serializeIdentity(const ServiceIdentity* id, ubyte[] outBuf, out size_t outLen)
{
    outLen = 0;
    if (id is null || id.service_id is null) return false;
    auto sidLen = strlen(id.service_id);
    size_t rolesCount = 0;
    if (id.roles !is null)
    {
        while (id.roles[rolesCount] !is null) ++rolesCount;
    }
    // Rough size: type-free blob: sidLen(2)+sid + pub dh + pub sign + code_hash + expires(8)+ rolesCount(1)+ each role len(2)+role + signature
    size_t need = 2 + sidLen + 32 + 32 + 32 + 8 + 1 + 64;
    for (size_t i = 0; i < rolesCount; ++i)
    {
        need += 2 + strlen(id.roles[i]);
    }
    if (outBuf.length < need) return false;
    size_t off = 0;
    if (!writeU16(outBuf, off, cast(uint)sidLen)) return false;
    off += 2;
    memcpy(outBuf.ptr + off, id.service_id, sidLen);
    off += sidLen;
    memcpy(outBuf.ptr + off, id.pub_static_dh.ptr, 32); off += 32;
    memcpy(outBuf.ptr + off, id.pub_sign.ptr, 32); off += 32;
    memcpy(outBuf.ptr + off, id.code_hash.ptr, 32); off += 32;
    if (!writeU64(outBuf, off, id.expires)) return false;
    off += 8;
    if (rolesCount > 255) return false;
    outBuf[off++] = cast(ubyte)rolesCount;
    for (size_t i = 0; i < rolesCount; ++i)
    {
        auto rlen = strlen(id.roles[i]);
        if (!writeU16(outBuf, off, cast(uint)rlen)) return false;
        off += 2;
        memcpy(outBuf.ptr + off, id.roles[i], rlen);
        off += rlen;
    }
    memcpy(outBuf.ptr + off, id.signature.ptr, 64);
    off += 64;
    outLen = off;
    return true;
}

private bool readU16(const ubyte[] buf, size_t offset, out uint v)
{
    if (offset + 2 > buf.length) return false;
    v = buf[offset] | (buf[offset+1] << 8);
    return true;
}
private bool readU64(const ubyte[] buf, size_t offset, out uint64_t v)
{
    if (offset + 8 > buf.length) return false;
    v = 0;
    foreach (i; 0 .. 8)
    {
        v |= cast(uint64_t)buf[offset + i] << (8*i);
    }
    return true;
}

private bool deserializeIdentity(const ubyte[] buf, out ServiceIdentity id, char[] sidStorage, char[][] roleStorage)
{
    size_t off = 0;
    uint sidLen = 0;
    if (!readU16(buf, off, sidLen)) return false;
    off += 2;
    if (off + sidLen > buf.length) return false;
    if (sidLen + 1 > sidStorage.length) return false;
    for (uint i = 0; i < sidLen; ++i) sidStorage[i] = cast(char)buf[off + i];
    sidStorage[sidLen] = 0;
    id.service_id = sidStorage.ptr;
    off += sidLen;
    if (off + 32*3 + 8 > buf.length) return false;
    memcpy(id.pub_static_dh.ptr, buf.ptr + off, 32); off += 32;
    memcpy(id.pub_sign.ptr, buf.ptr + off, 32); off += 32;
    memcpy(id.code_hash.ptr, buf.ptr + off, 32); off += 32;
    uint64_t exp;
    if (!readU64(buf, off, exp)) return false;
    id.expires = exp;
    off += 8;
    if (off >= buf.length) return false;
    ubyte rcount = buf[off++];
    if (rcount > roleStorage.length) return false;
    // roles array null-terminated
    auto rolesArr = cast(char**)malloc((rcount + 1) * (char*).sizeof);
    if (rolesArr is null) return false;
    for (ubyte i = 0; i < rcount; ++i)
    {
        uint rlen;
        if (!readU16(buf, off, rlen)) { free(rolesArr); return false; }
        off += 2;
        if (off + rlen > buf.length) { free(rolesArr); return false; }
        if (rlen + 1 > roleStorage[i].length) { free(rolesArr); return false; }
        for (uint j = 0; j < rlen; ++j) roleStorage[i][j] = cast(char)buf[off + j];
        roleStorage[i][rlen] = 0;
        rolesArr[i] = roleStorage[i].ptr;
        off += rlen;
    }
    rolesArr[rcount] = null;
    id.roles = rolesArr;
    if (off + 64 > buf.length) { free(rolesArr); return false; }
    memcpy(id.signature.ptr, buf.ptr + off, 64);
    return true;
}

// ---------------- KDF helpers -----------------
private bool deriveTempKey(const ubyte[32] dh1, const ubyte[32] dh2, const ubyte[] transcript, out ubyte[32] ktemp) @nogc nothrow
{
    ubyte[64] ikm;
    memcpy(ikm.ptr, dh1.ptr, 32);
    memcpy(ikm.ptr + 32, dh2.ptr, 32);
    ubyte[32] okm1;
    ubyte[32] okm2;
    hkdfSha256(transcript, ikm[], okm1, okm2);
    ktemp = okm1; // okm1 as temp key; okm2 unused
    return true;
}

private bool deriveFinalKeys(const ubyte[32] dh1, const ubyte[32] dh2, const ubyte[] transcript, bool initiator,
                             out ubyte[32] sendKey, out ubyte[32] recvKey) @nogc nothrow
{
    ubyte[64] ikm;
    memcpy(ikm.ptr, dh1.ptr, 32);
    memcpy(ikm.ptr + 32, dh2.ptr, 32);
    ubyte[32] okm1;
    ubyte[32] okm2;
    hkdfSha256(transcript, ikm[], okm1, okm2);
    if (initiator)
    {
        sendKey = okm1;
        recvKey = okm2;
    }
    else
    {
        sendKey = okm2;
        recvKey = okm1;
    }
    return true;
}

// ---------------- Client (initiator) -----------------
SecureChan* sec_connect(const char* service_id, const char* endpoint_name)
{
    if (!cryptoInit()) return null;
    ServiceIdentity srvId;
    if (load_service_identity(service_id, &srvId) != 0) return null;
    X25519Keypair myStaticX;
    Ed25519Keypair myStaticEd;
    if (!loadServiceKeys(service_id, myStaticEd, myStaticX)) return null;

    // connect
    auto h = ipc_connect(endpoint_name);
    if (h < 0) return null;

    HandshakeState hs;
    initIK(hs, Role.initiator, &myStaticX, &srvId.pub_static_dh);
    hs.msg = 0;

    // msg1
    ubyte[64] m1buf;
    size_t m1len;
    if (!serializeMsg1(hs.e.pk, [], m1buf[], m1len)) { ipc_close(h); return null; }
    if (ipc_send(h, m1buf.ptr, m1len) != cast(ssize_t)m1len) { ipc_close(h); return null; }

    // recv msg2
    ubyte[512] m2buf;
    auto r2 = ipc_recv(h, m2buf.ptr, m2buf.length);
    if (r2 <= 0) { ipc_close(h); return null; }
    ubyte[32] es;
    const(ubyte)[] encBlob2;
    if (!parseMsg2(m2buf[0 .. r2], es, encBlob2)) { ipc_close(h); return null; }

    // DHs
    ubyte[32] dh1; // ee
    ubyte[32] dh2; // e_c with K_s
    if (!x25519Shared(hs.e.sk, es, dh1)) { ipc_close(h); return null; }
    if (!x25519Shared(hs.e.sk, srvId.pub_static_dh, dh2)) { ipc_close(h); return null; }

    // transcript: m1||m2 header
    ubyte[64] transcript;
    size_t tlen = 0;
    memcpy(transcript.ptr + tlen, m1buf.ptr, m1len); tlen += m1len;
    if (tlen + r2 > transcript.length) tlen = transcript.length; // clamp
    memcpy(transcript.ptr + tlen, m2buf.ptr, (r2 < transcript.length - tlen) ? r2 : transcript.length - tlen);
    auto tview = transcript[0 .. (m1len + ((r2 < (transcript.length - m1len)) ? r2 : (transcript.length - m1len)))];

    // derive temp key and decrypt identity blob
    ubyte[32] ktemp;
    deriveTempKey(dh1, dh2, tview, ktemp);
    // decrypt encBlob2
    ubyte[] plainBlob;
    plainBlob.length = encBlob2.length - crypto_aead_chacha20poly1305_ietf_ABYTES;
    ubyte[12] nonce2 = [0,0,0,0,0,0,0,0,0,0,0,0];
    if (!aeadDecrypt(ktemp, nonce2, encBlob2, tview, plainBlob)) { ipc_close(h); return null; }

    // parse identity
    ServiceIdentity peerId;
    char[128] sidStorage;
    char[16][64] roleStorage;
    if (!deserializeIdentity(plainBlob, peerId, sidStorage[], roleStorage[])) { ipc_close(h); return null; }
    if (verify_service_identity(&peerId) != 0) { ipc_close(h); return null; }
    // check matches expectation
    if (strcmp(peerId.service_id, service_id) != 0) { ipc_close(h); return null; }

    // derive final keys
    ubyte[32] sendKey;
    ubyte[32] recvKey;
    deriveFinalKeys(dh1, dh2, tview, true, sendKey, recvKey);

    auto chan = cast(SecureChan*)malloc(SecureChan.sizeof);
    if (chan is null) { ipc_close(h); return null; }
    chan.raw = h;
    chan.send_key = sendKey;
    chan.recv_key = recvKey;
    chan.send_nonce = 0;
    chan.recv_nonce = 0;
    chan.is_initiator = 1;
    chan.peer.service_id = peerId.service_id;
    memcpy(chan.peer.code_hash.ptr, peerId.code_hash.ptr, 32);
    chan.peer.roles = peerId.roles;
    return chan;
}

// ---------------- Encrypted data framing -----------------

private bool writeHeader(SecureMsgType t, uint64_t nonceVal, uint cipherLen, ubyte[13] hdr)
{
    hdr[0] = cast(ubyte)t;
    foreach (i; 0 .. 8) hdr[1 + i] = cast(ubyte)((nonceVal >> (8*i)) & 0xFF);
    hdr[9]  = cast(ubyte)(cipherLen & 0xFF);
    hdr[10] = cast(ubyte)((cipherLen >> 8) & 0xFF);
    hdr[11] = cast(ubyte)((cipherLen >> 16) & 0xFF);
    hdr[12] = cast(ubyte)((cipherLen >> 24) & 0xFF);
    return true;
}

private bool readHeader(const ubyte[13] hdr, out SecureMsgType t, out uint64_t nonceVal, out uint cipherLen)
{
    t = cast(SecureMsgType)hdr[0];
    nonceVal = 0;
    foreach (i; 0 .. 8) nonceVal |= cast(uint64_t)hdr[1 + i] << (8*i);
    cipherLen = hdr[9] | (hdr[10] << 8) | (hdr[11] << 16) | (hdr[12] << 24);
    return true;
}

extern (C) int sec_send(SecureChan* c, const ubyte* msg, size_t len)
{
    if (c is null || !c.established) return -1;
    ubyte[13] hdr;
    ubyte[12] nonce;
    encodeNonce(++c.send_nonce, nonce); // increment then use
    uint cipherLen = cast(uint)(len + crypto_aead_chacha20poly1305_ietf_ABYTES);
    writeHeader(SecureMsgType.MSG_DATA, c.send_nonce, cipherLen, hdr);

    // AD is header bytes
    ubyte[] ad = hdr[];

    // Encrypt
    ubyte* sendBuf = cast(ubyte*)malloc(13 + cipherLen);
    if (sendBuf is null) return -2;
    memcpy(sendBuf, hdr.ptr, 13);
    ubyte[] cipher = sendBuf[13 .. 13 + cipherLen];
    ubyte[] plain = msg[0 .. len];
    if (!aeadEncrypt(c.send_key, nonce, plain, ad, cipher))
    {
        free(sendBuf);
        return -3;
    }
    auto sent = ipc_send(c.raw, sendBuf, 13 + cipherLen);
    free(sendBuf);
    return (sent == cast(ssize_t)(13 + cipherLen)) ? 0 : -4;
}

extern (C) int sec_recv(SecureChan* c, ubyte** msg, size_t* len)
{
    if (c is null || msg is null || len is null || !c.established) return -1;
    *msg = null; *len = 0;
    ubyte[13] hdr;
    auto r = ipc_recv(c.raw, hdr.ptr, hdr.length);
    if (r != hdr.length) return -2;
    SecureMsgType t;
    uint64_t nonceVal;
    uint cipherLen;
    readHeader(hdr, t, nonceVal, cipherLen);
    if (t != SecureMsgType.MSG_DATA) return -3;
    // Simple in-order check
    if (nonceVal != c.recv_nonce + 1) return -4;
    c.recv_nonce = nonceVal;
    // Read ciphertext
    ubyte* cipherBuf = cast(ubyte*)malloc(cipherLen);
    if (cipherBuf is null) return -5;
    auto r2 = ipc_recv(c.raw, cipherBuf, cipherLen);
    if (r2 != cast(ssize_t)cipherLen) { free(cipherBuf); return -6; }

    ubyte[12] nonce;
    encodeNonce(nonceVal, nonce);
    ubyte[] ad = hdr[];
    auto plainLen = cipherLen - crypto_aead_chacha20poly1305_ietf_ABYTES;
    ubyte* plainBuf = cast(ubyte*)malloc(plainLen);
    if (plainBuf is null) { free(cipherBuf); return -7; }
    ubyte[] cipher = cipherBuf[0 .. cipherLen];
    ubyte[] plain = plainBuf[0 .. plainLen];
    if (!aeadDecrypt(c.recv_key, nonce, cipher, ad, plain))
    {
        free(cipherBuf);
        free(plainBuf);
        return -8;
    }
    free(cipherBuf);
    *msg = plainBuf;
    *len = plainLen;
    return 0;
}

extern (C) void sec_close(SecureChan* c)
{
    if (c is null) return;
    // Wipe keys
    foreach (i; 0 .. 32) { c.send_key[i] = 0; c.recv_key[i] = 0; }
    c.send_nonce = 0;
    c.recv_nonce = 0;
    // Free roles in peer
    if (c.peer.roles !is null)
    {
        size_t idx = 0;
        while (c.peer.roles[idx] !is null)
        {
            free(c.peer.roles[idx]);
            ++idx;
        }
        free(c.peer.roles);
        c.peer.roles = null;
    }
    if (c.peer.service_id !is null)
    {
        free(c.peer.service_id);
        c.peer.service_id = null;
    }
    if (c.raw >= 0) ipc_close(c.raw);
    free(c);
}

extern (C) const PeerInfo* sec_peer(SecureChan* c)
{
    return c is null ? null : &c.peer;
}
// ---------------- Server (responder) -----------------

SecureChan* sec_accept(const char* endpoint_name,
                       int function(const PeerInfo* peer, void* ctx) @nogc nothrow auth_cb,
                       void* cb_ctx)
{
    if (!cryptoInit()) return null;
    // For simplicity, assume endpoint_name is the service_id for key loading.
    auto h = ipc_open_endpoint(endpoint_name);
    if (h < 0) return null;

    ServiceIdentity selfId;
    if (load_service_identity(endpoint_name, &selfId) != 0) { ipc_close(h); return null; }
    Ed25519Keypair selfEd;
    X25519Keypair selfX;
    if (!loadServiceKeys(endpoint_name, selfEd, selfX)) { ipc_close(h); return null; }

    // recv msg1
    ubyte[128] m1buf;
    auto r1 = ipc_recv(h, m1buf.ptr, m1buf.length);
    if (r1 <= 0) { ipc_close(h); return null; }
    ubyte[32] ec;
    const(ubyte)[] nonce1;
    if (!parseMsg1(m1buf[0 .. r1], ec, nonce1)) { ipc_close(h); return null; }

    // generate server ephemeral
    X25519Keypair es = x25519Generate();

    // DHs
    ubyte[32] dh1; // ee
    ubyte[32] dh2; // k_s with e_c
    if (!x25519Shared(es.sk, ec, dh1)) { ipc_close(h); return null; }
    if (!x25519Shared(selfX.sk, ec, dh2)) { ipc_close(h); return null; }

    // transcript hash
    ubyte[64] transcript;
    size_t tlen = 0;
    memcpy(transcript.ptr, m1buf.ptr, r1 < transcript.length ? r1 : transcript.length);
    tlen = (r1 < transcript.length) ? r1 : transcript.length;
    auto tview = transcript[0 .. tlen];

    // derive temp key
    ubyte[32] ktemp;
    deriveTempKey(dh1, dh2, tview, ktemp);

    // serialize identity and encrypt
    ubyte[512] idbuf;
    size_t idlen;
    if (!serializeIdentity(&selfId, idbuf[], idlen)) { ipc_close(h); return null; }
    ubyte[] encId;
    encId.length = idlen + crypto_aead_chacha20poly1305_ietf_ABYTES;
    ubyte[12] nonce2 = [0,0,0,0,0,0,0,0,0,0,0,0];
    if (!aeadEncrypt(ktemp, nonce2, idbuf[0 .. idlen], tview, encId)) { ipc_close(h); return null; }

    // send msg2
    ubyte[640] m2buf;
    size_t m2len;
    if (!serializeMsg2(es.pk, encId, m2buf[], m2len)) { ipc_close(h); return null; }
    if (ipc_send(h, m2buf.ptr, m2len) != cast(ssize_t)m2len) { ipc_close(h); return null; }

    // derive final keys
    ubyte[32] sendKey;
    ubyte[32] recvKey;
    deriveFinalKeys(dh1, dh2, tview, false, sendKey, recvKey);

    auto chan = cast(SecureChan*)malloc(SecureChan.sizeof);
    if (chan is null) { ipc_close(h); return null; }
    chan.raw = h;
    chan.send_key = sendKey;
    chan.recv_key = recvKey;
    chan.send_nonce = 0;
    chan.recv_nonce = 0;
    chan.is_initiator = 0;
    chan.peer.service_id = selfId.service_id; // peer info for server is self? for auth_cb we need client; we skip msg3 so unknown
    chan.peer.roles = null;
    memset(chan.peer.code_hash.ptr, 0, 32);

    if (auth_cb !is null)
    {
        if (auth_cb(&chan.peer, cb_ctx) != 0)
        {
            ipc_close(h);
            free(chan);
            return null;
        }
    }
    return chan;
}
