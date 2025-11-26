module anonymos.userland.group_controller;

import core.stdc.stdlib : malloc, free;
import core.stdc.string : memcpy;
import core.stdc.stdint : size_t, uint64_t;
import anonymos.userland.crypto : randombytes_buf, aeadEncrypt, aeadDecrypt, crypto_aead_chacha20poly1305_ietf_ABYTES;
import anonymos.userland.ipcsec_handshake : SecureChan, sec_send, sec_recv;

extern (C):

struct GroupKey
{
    ubyte[32] group_key;
    uint64_t epoch;
}

struct GroupController
{
    SecureChan** members;
    size_t member_count;
    GroupKey current;
}

@nogc nothrow:

// Allocate a controller with a fresh group key/epoch and the provided member list.
GroupController* group_create(SecureChan** chans, size_t count)
{
    if (chans is null || count == 0) return null;
    auto gc = cast(GroupController*)malloc(GroupController.sizeof);
    if (gc is null) return null;
    gc.members = chans;
    gc.member_count = count;
    randombytes_buf(gc.current.group_key.ptr, gc.current.group_key.length);
    gc.current.epoch = 1;
    // distribute initial key
    foreach (i; 0 .. count)
    {
        auto c = gc.members[i];
        if (c is null) continue;
        ubyte[40] payload;
        // key (32) + epoch (8)
        memcpy(payload.ptr, gc.current.group_key.ptr, 32);
        foreach (j; 0 .. 8) payload[32 + j] = cast(ubyte)((gc.current.epoch >> (8*j)) & 0xFF);
        sec_send(c, payload.ptr, 40);
    }
    return gc;
}

// Broadcast a message using the current group key; per-member nonce derived from their recv_nonce/send_nonce counters.
int group_broadcast(GroupController* gc, const ubyte* msg, size_t len)
{
    if (gc is null || msg is null) return -1;
    int rc = 0;
    foreach (i; 0 .. gc.member_count)
    {
        auto c = gc.members[i];
        if (c is null) { rc = -1; continue; }
        // Use group_key as key, member send_nonce as nonce
        ubyte[12] nonce;
        foreach (j; 0 .. 8) nonce[j] = cast(ubyte)(((++c.send_nonce) >> (8*j)) & 0xFF);
        foreach (j; 8 .. 12) nonce[j] = 0;
        auto ctLen = len + crypto_aead_chacha20poly1305_ietf_ABYTES;
        auto buf = cast(ubyte*)malloc(ctLen);
        if (buf is null) { rc = -2; continue; }
        ubyte[] ct = buf[0 .. ctLen];
        ubyte[] pt = msg[0 .. len];
        if (!aeadEncrypt(gc.current.group_key, nonce, pt, [], ct))
        {
            free(buf);
            rc = -3;
            continue;
        }
        // send raw ciphertext; receiver must know to decrypt with group_key
        auto sendRc = sec_send(c, ct.ptr, ct.length);
        free(buf);
        if (sendRc != 0) rc = -4;
    }
    return rc;
}

// Rotate the group key and redistribute.
int group_rotate(GroupController* gc)
{
    if (gc is null) return -1;
    gc.current.epoch += 1;
    randombytes_buf(gc.current.group_key.ptr, gc.current.group_key.length);
    foreach (i; 0 .. gc.member_count)
    {
        auto c = gc.members[i];
        if (c is null) continue;
        ubyte[40] payload;
        memcpy(payload.ptr, gc.current.group_key.ptr, 32);
        foreach (j; 0 .. 8) payload[32 + j] = cast(ubyte)((gc.current.epoch >> (8*j)) & 0xFF);
        sec_send(c, payload.ptr, 40);
    }
    return 0;
}
