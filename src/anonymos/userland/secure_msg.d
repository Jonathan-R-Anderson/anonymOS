module anonymos.userland.secure_msg;

import core.stdc.string : memcpy;

@nogc nothrow:

// Wire framing
enum SecureMsgType : ubyte
{
    MSG_HANDSHAKE_1 = 1,
    MSG_HANDSHAKE_2 = 2,
    MSG_HANDSHAKE_3 = 3,
    MSG_DATA        = 4
}

/// Generic serializer: writes type || payload into outBuf. outBuf must be sized.
bool serializeMsg(SecureMsgType t, const ubyte[] payload, ubyte[] outBuf, out size_t outLen) @nogc nothrow
{
    if (outBuf.length < 1 + payload.length) return false;
    outBuf[0] = cast(ubyte)t;
    if (payload.length > 0)
    {
        memcpy(outBuf.ptr + 1, payload.ptr, payload.length);
    }
    outLen = 1 + payload.length;
    return true;
}

/// Parse generic message header; returns type and payload slice (view into input).
bool parseMsg(const ubyte[] inBuf, out SecureMsgType t, out const(ubyte)[] payload) @nogc nothrow
{
    if (inBuf.length < 1) return false;
    t = cast(SecureMsgType)inBuf[0];
    payload = inBuf[1 .. $];
    return true;
}

// ---------------------------------------------------------------------------
// IK-style handshake message helpers
// ---------------------------------------------------------------------------

/// msg1: type | e_c (32) | optional nonce
bool serializeMsg1(const ubyte[32] ec, const ubyte[] nonceOpt, ubyte[] outBuf, out size_t outLen) @nogc nothrow
{
    const size_t need = 1 + 32 + nonceOpt.length;
    if (outBuf.length < need) return false;
    outBuf[0] = SecureMsgType.MSG_HANDSHAKE_1;
    memcpy(outBuf.ptr + 1, ec.ptr, 32);
    if (nonceOpt.length > 0)
    {
        memcpy(outBuf.ptr + 1 + 32, nonceOpt.ptr, nonceOpt.length);
    }
    outLen = need;
    return true;
}

bool parseMsg1(const ubyte[] inBuf, out ubyte[32] ec, out const(ubyte)[] nonceOpt) @nogc nothrow
{
    if (inBuf.length < 1 + 32) return false;
    if (cast(SecureMsgType)inBuf[0] != SecureMsgType.MSG_HANDSHAKE_1) return false;
    memcpy(ec.ptr, inBuf.ptr + 1, 32);
    nonceOpt = inBuf[1 + 32 .. $];
    return true;
}

/// msg2: type | e_s (32) | enc_blob (rest)
bool serializeMsg2(const ubyte[32] es, const ubyte[] encBlob, ubyte[] outBuf, out size_t outLen) @nogc nothrow
{
    const size_t need = 1 + 32 + encBlob.length;
    if (outBuf.length < need) return false;
    outBuf[0] = SecureMsgType.MSG_HANDSHAKE_2;
    memcpy(outBuf.ptr + 1, es.ptr, 32);
    if (encBlob.length > 0)
    {
        memcpy(outBuf.ptr + 1 + 32, encBlob.ptr, encBlob.length);
    }
    outLen = need;
    return true;
}

bool parseMsg2(const ubyte[] inBuf, out ubyte[32] es, out const(ubyte)[] encBlob) @nogc nothrow
{
    if (inBuf.length < 1 + 32) return false;
    if (cast(SecureMsgType)inBuf[0] != SecureMsgType.MSG_HANDSHAKE_2) return false;
    memcpy(es.ptr, inBuf.ptr + 1, 32);
    encBlob = inBuf[1 + 32 .. $];
    return true;
}

/// msg3: type | enc_blob
bool serializeMsg3(const ubyte[] encBlob, ubyte[] outBuf, out size_t outLen) @nogc nothrow
{
    const size_t need = 1 + encBlob.length;
    if (outBuf.length < need) return false;
    outBuf[0] = SecureMsgType.MSG_HANDSHAKE_3;
    if (encBlob.length > 0)
    {
        memcpy(outBuf.ptr + 1, encBlob.ptr, encBlob.length);
    }
    outLen = need;
    return true;
}

bool parseMsg3(const ubyte[] inBuf, out const(ubyte)[] encBlob) @nogc nothrow
{
    if (inBuf.length < 1) return false;
    if (cast(SecureMsgType)inBuf[0] != SecureMsgType.MSG_HANDSHAKE_3) return false;
    encBlob = inBuf[1 .. $];
    return true;
}
