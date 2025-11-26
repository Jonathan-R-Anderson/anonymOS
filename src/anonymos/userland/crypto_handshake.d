module anonymos.userland.crypto_handshake;

import anonymos.userland.crypto;
import core.stdc.string : memset;

@nogc nothrow:

enum Pattern { IK, XX }
enum Role { initiator, responder }

struct HandshakeState
{
    Pattern pattern;
    Role role;
    ubyte[32] ck;   // chaining key
    ubyte[32] h;    // transcript hash
    X25519Keypair s; // local static
    X25519Keypair e; // local ephemeral (current)
    ubyte[32] rs;    // remote static (if known)
    ubyte[32] re;    // remote ephemeral
    bool hasRemoteStatic;
    uint msg;        // handshake message index
}

private enum string PROTO_IK = "Noise_IK";
private enum string PROTO_XX = "Noise_XX";
private enum size_t MAX_HASH_BUF = 1024;

private bool sha256(out ubyte[32] outHash, const ubyte[] data) @nogc nothrow
{
    if (data.ptr is null && data.length != 0) return false;
    crypto_hash_sha256(outHash.ptr, data.ptr, data.length);
    return true;
}

private bool mixHash(ref HandshakeState st, const ubyte[] data) @nogc nothrow
{
    // h = SHA256(h || data)
    if (data.length + st.h.length > MAX_HASH_BUF) return false;
    ubyte[MAX_HASH_BUF] buf;
    size_t idx = 0;
    // copy h
    foreach (b; st.h) { buf[idx++] = b; }
    foreach (b; data) { buf[idx++] = b; }
    ubyte[32] outHash;
    if (!sha256(outHash, buf[0 .. idx])) return false;
    st.h = outHash;
    return true;
}

private bool mixKey(ref HandshakeState st, const ubyte[32] dh) @nogc nothrow
{
    ubyte[32] okm1;
    ubyte[32] okm2;
    hkdfSha256(st.ck[], dh[], okm1, okm2);
    st.ck = okm1;
    st.h = okm2; // fold derived value into hash base for associated data
    return true;
}

private bool dh(out ubyte[32] outShared, const ubyte[32] sk, const ubyte[32] pk) @nogc nothrow
{
    return x25519Shared(sk, pk, outShared);
}

/// Initialize XX pattern. Caller supplies local static; initiator sets role to initiator.
bool initXX(ref HandshakeState st, Role role, const X25519Keypair* staticKey) @nogc nothrow
{
    st = HandshakeState.init;
    st.pattern = Pattern.XX;
    st.role = role;
    if (staticKey !is null)
        st.s = *staticKey;
    ubyte[32] protoHash;
    sha256(protoHash, cast(const ubyte[])PROTO_XX);
    st.ck = protoHash;
    st.h = protoHash;
    st.msg = 0;
    return true;
}

/// Initialize IK pattern (initiator knows responder static).
bool initIK(ref HandshakeState st, Role role,
            const X25519Keypair* staticKey,
            const ubyte[32]* responderStaticPk) @nogc nothrow
{
    st = HandshakeState.init;
    st.pattern = Pattern.IK;
    st.role = role;
    if (staticKey !is null)
        st.s = *staticKey;
    if (responderStaticPk !is null)
    {
        st.rs = *responderStaticPk;
        st.hasRemoteStatic = true;
    }
    ubyte[32] protoHash;
    sha256(protoHash, cast(const ubyte[])PROTO_IK);
    st.ck = protoHash;
    st.h = protoHash;
    st.msg = 0;
    return true;
}

/// Noise XX / IK write_message.
/// outBuf must be large enough for the message; outLen returns bytes written.
bool writeMessage(ref HandshakeState st, const ubyte[] payload, ubyte[] outBuf, out size_t outLen) @nogc nothrow
{
    outLen = 0;
    // Message numbering from initiator perspective: 0,2 for initiator; 1 for responder.
    // Pattern handling:
    if (st.pattern == Pattern.XX)
    {
        if (st.role == Role.initiator)
        {
            if (st.msg == 0)
            {
                st.e = x25519Generate();
                if (outBuf.length < 32) return false;
                outBuf[0 .. 32] = st.e.pk[];
                outLen = 32;
                if (!mixHash(st, st.e.pk[])) return false;
                st.msg = 1;
                return true;
            }
            else if (st.msg == 2)
            {
                // Send encrypted static and payload using current chaining key
                ubyte[32] tempK;
                ubyte[32] shared;
                if (!dh(shared, st.s.sk, st.re)) return false;
                mixKey(st, shared);
                tempK = st.h; // temp key derived in mixKey

                if (!mixHash(st, st.s.pk[])) return false;

                // enc static
                ubyte[12] nonce = [0,0,0,0,0,0,0,0,0,0,0,0];
                // message layout: enc_static || enc_payload
                size_t need = 32 + crypto_aead_chacha20poly1305_ietf_ABYTES + payload.length + crypto_aead_chacha20poly1305_ietf_ABYTES;
                if (outBuf.length < need) return false;
                ubyte[] encStatic = outBuf[0 .. 32 + crypto_aead_chacha20poly1305_ietf_ABYTES];
                ubyte[] encPayload = outBuf[encStatic.length .. need];
                if (!aeadEncrypt(tempK, nonce, st.s.pk[], st.h[], encStatic)) return false;
                mixHash(st, encStatic[]);

                // derive new temp key for payload
                nonce[0] = 1;
                if (!aeadEncrypt(tempK, nonce, payload, st.h[], encPayload)) return false;
                mixHash(st, encPayload[]);

                outLen = need;
                st.msg = 3;
                return true;
            }
        }
        else // responder
        {
            if (st.msg == 1)
            {
                st.e = x25519Generate();
                // DH ee
                ubyte[32] shared;
                ubyte[32] tempK;
                if (!dh(shared, st.e.sk, st.re)) return false;
                mixKey(st, shared);
                tempK = st.h;

                size_t needed = 32; // e_r
                needed += 32 + crypto_aead_chacha20poly1305_ietf_ABYTES; // enc rs
                needed += payload.length + crypto_aead_chacha20poly1305_ietf_ABYTES; // enc payload
                if (outBuf.length < needed) return false;
                size_t offset = 0;
                outBuf[offset .. offset+32] = st.e.pk[];
                offset += 32;
                mixHash(st, st.e.pk[]);

                // DH se (responder static, initiator ephemeral)
                if (!dh(shared, st.s.sk, st.re)) return false;
                mixKey(st, shared);
                tempK = st.h;

                // enc rs
                ubyte[12] nonce = [0,0,0,0,0,0,0,0,0,0,0,0];
                ubyte[] encRs = outBuf[offset .. offset + 32 + crypto_aead_chacha20poly1305_ietf_ABYTES];
                if (!aeadEncrypt(tempK, nonce, st.s.pk[], st.h[], encRs)) return false;
                mixHash(st, encRs[]);
                offset += encRs.length;

                // enc payload
                nonce[0] = 1;
                ubyte[] encPayload = outBuf[offset .. offset + payload.length + crypto_aead_chacha20poly1305_ietf_ABYTES];
                if (!aeadEncrypt(tempK, nonce, payload, st.h[], encPayload)) return false;
                mixHash(st, encPayload[]);
                offset += encPayload.length;

                outLen = offset;
                st.msg = 2;
                return true;
            }
        }
    }
    else if (st.pattern == Pattern.IK)
    {
        if (st.role == Role.initiator && st.msg == 0)
        {
            st.e = x25519Generate();
            size_t needed = 32; // e
            needed += payload.length + crypto_aead_chacha20poly1305_ietf_ABYTES;
            if (outBuf.length < needed) return false;
            outBuf[0 .. 32] = st.e.pk[];
            mixHash(st, st.e.pk[]);

            // DH es (initiator ephemeral, responder static)
            ubyte[32] shared;
            if (!dh(shared, st.e.sk, st.rs)) return false;
            mixKey(st, shared);
            ubyte[32] tempK = st.h;

            ubyte[12] nonce = [0,0,0,0,0,0,0,0,0,0,0,0];
            ubyte[] encPayload = outBuf[32 .. needed];
            if (!aeadEncrypt(tempK, nonce, payload, st.h[], encPayload)) return false;
            mixHash(st, encPayload[]);
            outLen = needed;
            st.msg = 1;
            return true;
        }
        else if (st.role == Role.responder && st.msg == 1)
        {
            st.e = x25519Generate();
            ubyte[32] shared;
            // ee
            if (!dh(shared, st.e.sk, st.re)) return false;
            mixKey(st, shared);
            ubyte[32] tempK = st.h;

            size_t needed = 32; // e_r
            needed += payload.length + crypto_aead_chacha20poly1305_ietf_ABYTES;
            if (outBuf.length < needed) return false;
            outBuf[0 .. 32] = st.e.pk[];
            mixHash(st, st.e.pk[]);

            // se (responder static, initiator ephemeral)
            if (!dh(shared, st.s.sk, st.re)) return false;
            mixKey(st, shared);
            tempK = st.h;

            ubyte[12] nonce = [0,0,0,0,0,0,0,0,0,0,0,0];
            ubyte[] encPayload = outBuf[32 .. needed];
            if (!aeadEncrypt(tempK, nonce, payload, st.h[], encPayload)) return false;
            mixHash(st, encPayload[]);

            outLen = needed;
            st.msg = 2;
            return true;
        }
    }

    return false;
}

/// read_message: parses input, updates state, and writes plaintext into outPlain (must be sized).
bool readMessage(ref HandshakeState st, const ubyte[] inMsg, ubyte[] outPlain, out size_t outPlainLen) @nogc nothrow
{
    outPlainLen = 0;
    size_t offset = 0;
    if (st.pattern == Pattern.XX)
    {
        if (st.role == Role.responder && st.msg == 0)
        {
            if (inMsg.length < 32) return false;
            st.re = inMsg[0 .. 32];
            offset = 32;
            if (!mixHash(st, st.re[])) return false;
            st.msg = 1;
            return true;
        }
        else if (st.role == Role.initiator && st.msg == 1)
        {
            // expect: re || enc_rs || enc_payload
            if (inMsg.length < 32) return false;
            st.re = inMsg[0 .. 32];
            offset = 32;
            mixHash(st, st.re[]);

            // ee
            ubyte[32] shared;
            if (!dh(shared, st.e.sk, st.re)) return false;
            mixKey(st, shared);
            ubyte[32] tempK = st.h;

            // se (initiator static with re)
            if (!dh(shared, st.s.sk, st.re)) return false;
            mixKey(st, shared);
            tempK = st.h;

            if (inMsg.length < offset + 32 + crypto_aead_chacha20poly1305_ietf_ABYTES) return false;
            ubyte[12] nonce = [0,0,0,0,0,0,0,0,0,0,0,0];
            ubyte[] encRs = inMsg[offset .. offset + 32 + crypto_aead_chacha20poly1305_ietf_ABYTES];
            ubyte[32] rsOut;
            ubyte[] rsPlain = rsOut[];
            if (!aeadDecrypt(tempK, nonce, encRs, st.h[], rsPlain)) return false;
            st.rs = rsOut;
            st.hasRemoteStatic = true;
            mixHash(st, encRs[]);
            offset += encRs.length;

            // decrypt payload
            nonce[0] = 1;
            size_t ctLeft = inMsg.length - offset;
            if (ctLeft > outPlain.length) return false;
            ubyte[] encPayload = inMsg[offset .. inMsg.length];
            ubyte[] plainSlice = outPlain[0 .. (ctLeft - crypto_aead_chacha20poly1305_ietf_ABYTES)];
            if (!aeadDecrypt(tempK, nonce, encPayload, st.h[], plainSlice)) return false;
            mixHash(st, encPayload[]);
            outPlainLen = plainSlice.length;
            st.msg = 2;
            return true;
        }
        else if (st.role == Role.responder && st.msg == 2)
        {
            // expect enc_static || enc_payload
            if (inMsg.length < (32 + crypto_aead_chacha20poly1305_ietf_ABYTES)) return false;
            ubyte[12] nonce = [0,0,0,0,0,0,0,0,0,0,0,0];
            ubyte[] encS = inMsg[0 .. 32 + crypto_aead_chacha20poly1305_ietf_ABYTES];
            ubyte[32] sPlain;
            ubyte[] sPlainSlice = sPlain[];
            ubyte[32] shared;
            // derive key from existing ck via mixKey on dh(s_r.sk, re)
            if (!dh(shared, st.s.sk, st.re)) return false;
            mixKey(st, shared);
            ubyte[32] tempK = st.h;
            if (!aeadDecrypt(tempK, nonce, encS, st.h[], sPlainSlice)) return false;
            st.rs = sPlain;
            st.hasRemoteStatic = true;
            mixHash(st, encS[]);
            size_t offset2 = encS.length;

            nonce[0] = 1;
            size_t ctLeft = inMsg.length - offset2;
            if (ctLeft > outPlain.length) return false;
            if (ctLeft > 0)
            {
                ubyte[] encPayload = inMsg[offset2 .. inMsg.length];
                ubyte[] plainSlice = outPlain[0 .. (ctLeft - crypto_aead_chacha20poly1305_ietf_ABYTES)];
                if (!aeadDecrypt(tempK, nonce, encPayload, st.h[], plainSlice)) return false;
                mixHash(st, encPayload[]);
                outPlainLen = plainSlice.length;
            }
            st.msg = 3;
            return true;
        }
    }
    else if (st.pattern == Pattern.IK)
    {
        if (st.role == Role.responder && st.msg == 0)
        {
            if (inMsg.length < 32) return false;
            st.re = inMsg[0 .. 32];
            mixHash(st, st.re[]);
            size_t ctLeft = inMsg.length - 32;
            if (ctLeft > outPlain.length) return false;
            // DH es
            ubyte[32] shared;
            if (!dh(shared, st.s.sk, st.re)) return false;
            mixKey(st, shared);
            ubyte[32] tempK = st.h;
            ubyte[12] nonce = [0,0,0,0,0,0,0,0,0,0,0,0];
            if (ctLeft > 0)
            {
                ubyte[] encPayload = inMsg[32 .. inMsg.length];
                ubyte[] plainSlice = outPlain[0 .. (ctLeft - crypto_aead_chacha20poly1305_ietf_ABYTES)];
                if (!aeadDecrypt(tempK, nonce, encPayload, st.h[], plainSlice)) return false;
                mixHash(st, encPayload[]);
                outPlainLen = plainSlice.length;
            }
            st.msg = 1;
            return true;
        }
        else if (st.role == Role.initiator && st.msg == 2)
        {
            if (inMsg.length < 32) return false;
            st.re = inMsg[0 .. 32];
            mixHash(st, st.re[]);
            // ee
            ubyte[32] shared;
            if (!dh(shared, st.e.sk, st.re)) return false;
            mixKey(st, shared);
            // se
            if (!dh(shared, st.s.sk, st.re)) return false;
            mixKey(st, shared);
            ubyte[32] tempK = st.h;
            ubyte[12] nonce = [0,0,0,0,0,0,0,0,0,0,0,0];
            size_t ctLeft = inMsg.length - 32;
            if (ctLeft > outPlain.length) return false;
            if (ctLeft > 0)
            {
                ubyte[] encPayload = inMsg[32 .. inMsg.length];
                ubyte[] plainSlice = outPlain[0 .. (ctLeft - crypto_aead_chacha20poly1305_ietf_ABYTES)];
                if (!aeadDecrypt(tempK, nonce, encPayload, st.h[], plainSlice)) return false;
                mixHash(st, encPayload[]);
                outPlainLen = plainSlice.length;
            }
            st.msg = 3;
            return true;
        }
    }
    return false;
}

/// After handshake completes (msg==3), derive traffic keys.
bool split(ref HandshakeState st, out ubyte[32] txKey, out ubyte[32] rxKey) @nogc nothrow
{
    if (st.msg < 3) return false;
    hkdfSha256(st.ck[], st.h[], txKey, rxKey);
    return true;
}
