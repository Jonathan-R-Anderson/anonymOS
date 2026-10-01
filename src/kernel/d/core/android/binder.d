/**
 * android/binder.d -- the binder IPC driver, phase A1 (docs/hw-bringup/ANDROID.md).
 *
 * binder is the keystone of Android: servicemanager and every system service talk over it, and
 * nothing in Android (and so nothing in Waydroid) starts without it.  This is the FIRST phase of the
 * native Android bring-up -- the device and its command/return protocol framing, with the parts that
 * need a mapped receive buffer (A2) and full object/handle translation and the thread pool (A3)
 * scoped as later phases.  It is deliberately a pure kernel-buffer engine: posix.d copies the user
 * buffers in and out under SMAP and calls binderWriteRead with kernel pointers, so the protocol can
 * be exercised by an in-kernel self-test with no user context.
 *
 * What A1 implements, against the real Linux binder UAPI:
 *   - BINDER_VERSION            -> protocol version 8 (the 64-bit value libbinder checks)
 *   - BINDER_SET_MAX_THREADS    -> recorded
 *   - BINDER_SET_CONTEXT_MGR    -> registers this proc as the context manager (handle 0)
 *   - BINDER_WRITE_READ         -> parses the BC_* write stream and produces the BR_* read stream:
 *        looper commands, ref commands and BC_FREE_BUFFER are acknowledged; BC_TRANSACTION to
 *        handle 0 is routed to the context manager's mailbox as BR_TRANSACTION and the sender gets
 *        BR_TRANSACTION_COMPLETE; BC_REPLY gets BR_TRANSACTION_COMPLETE.
 *
 * What A1 does NOT do (see the roadmap): follow the transaction DATA pointer (it needs the mmap'd
 * buffer, A2), translate flat binder objects/handles/fds, ref-count, or notify on death.  The
 * transaction HEADER (target, code, flags, cookie) round-trips; the payload is delivered as empty.
 */
module core.android.binder;

@nogc nothrow:

// ---- UAPI constants (x86-64) -----------------------------------------------------------------
enum uint BINDER_WRITE_READ      = 0xC030_6201;
enum uint BINDER_SET_MAX_THREADS = 0x4004_6205;
enum uint BINDER_SET_CONTEXT_MGR = 0x4004_6207;
enum uint BINDER_VERSION         = 0xC004_6209;
enum uint BINDER_THREAD_EXIT     = 0x4004_6208;
enum int  BINDER_CURRENT_PROTOCOL_VERSION = 8;

// BC_* : commands written by userspace (low 16 bits of the _IOC code; the driver reads the full u32).
enum uint BC_TRANSACTION    = 0xC030_6300;  // _IOW('c',0, binder_transaction_data)
enum uint BC_REPLY          = 0xC030_6301;  // _IOW('c',1, binder_transaction_data)
enum uint BC_FREE_BUFFER    = 0x4008_6303;  // _IOW('c',3, binder_uintptr_t)
enum uint BC_INCREFS        = 0x4004_6304;
enum uint BC_ACQUIRE        = 0x4004_6305;
enum uint BC_RELEASE        = 0x4004_6306;
enum uint BC_DECREFS        = 0x4004_6307;
enum uint BC_REGISTER_LOOPER= 0x0000_630B;  // _IO('c',11)
enum uint BC_ENTER_LOOPER   = 0x0000_630C;  // _IO('c',12)
enum uint BC_EXIT_LOOPER    = 0x0000_630D;  // _IO('c',13)

// BR_* : returns delivered to userspace.
enum uint BR_TRANSACTION          = 0x8030_7202;  // _IOR('r',2, binder_transaction_data)
enum uint BR_REPLY                = 0x8030_7203;  // _IOR('r',3, binder_transaction_data)
enum uint BR_TRANSACTION_COMPLETE = 0x0000_7206;  // _IO('r',6)
enum uint BR_NOOP                 = 0x0000_720C;  // _IO('r',12)
enum uint BR_FAILED_REPLY         = 0x0000_7211;

// binder_transaction_data: 64 bytes on 64-bit (see the file header).
struct BinderTxData {
align(1):
    ulong target;       // handle (u32, zero-extended) or a binder ptr
    ulong cookie;
    uint  code;
    uint  flags;
    int   sender_pid;
    uint  sender_euid;
    ulong data_size;
    ulong offsets_size;
    ulong data_buffer;  // user ptr (phase A1 does not follow it)
    ulong data_offsets; // user ptr
}
static assert(BinderTxData.sizeof == 64);

// ---- per-open state --------------------------------------------------------------------------
private enum int MAX_PROCS   = 64;
private enum int MAILBOX_CAP = 32;

private struct Mail {
    uint code;          // BR_TRANSACTION or BR_REPLY
    BinderTxData tx;
}

private struct BinderProc {
    bool used;
    uint maxThreads;
    bool looper;
    int  mailHead, mailLen;
    Mail[MAILBOX_CAP] mail;
}

private __gshared BinderProc[MAX_PROCS] g_procs;
private __gshared int g_contextMgr = -1;   // the proc index registered as handle 0, or -1

// ---- lifecycle -------------------------------------------------------------------------------

/// Allocate a binder proc for a new /dev/binder fd; -1 when the table is full.
public int binderAlloc() {
    foreach (i; 0 .. MAX_PROCS) {
        if (!g_procs[i].used) {
            g_procs[i] = BinderProc.init;
            g_procs[i].used = true;
            return i;
        }
    }
    return -1;
}

/// Release a binder proc on close.
public void binderFree(int id) {
    if (id < 0 || id >= MAX_PROCS || !g_procs[id].used) return;
    if (g_contextMgr == id) g_contextMgr = -1;
    g_procs[id] = BinderProc.init;
}

public int binderVersion() { return BINDER_CURRENT_PROTOCOL_VERSION; }

public void binderSetMaxThreads(int id, uint n) {
    if (id >= 0 && id < MAX_PROCS && g_procs[id].used) g_procs[id].maxThreads = n;
}

/// Register `id` as the context manager (handle 0).  EBUSY if one is already set, EINVAL on a bad id.
public long binderSetContextMgr(int id) {
    if (id < 0 || id >= MAX_PROCS || !g_procs[id].used) return -22; // EINVAL
    if (g_contextMgr >= 0 && g_contextMgr != id) return -16;        // EBUSY
    g_contextMgr = id;
    return 0;
}

private bool mailPush(int id, uint code, const ref BinderTxData tx) {
    auto p = &g_procs[id];
    if (p.mailLen >= MAILBOX_CAP) return false;
    const int slot = (p.mailHead + p.mailLen) % MAILBOX_CAP;
    p.mail[slot].code = code;
    p.mail[slot].tx = tx;
    ++p.mailLen;
    return true;
}

private bool mailPop(int id, ref Mail out_) {
    auto p = &g_procs[id];
    if (p.mailLen == 0) return false;
    out_ = p.mail[p.mailHead];
    p.mailHead = (p.mailHead + 1) % MAILBOX_CAP;
    --p.mailLen;
    return true;
}

// ---- the write/read engine -------------------------------------------------------------------

private void putU32(ubyte* b, ulong cap, ref ulong off, uint v) {
    if (off + 4 > cap) return;
    b[off] = cast(ubyte)v; b[off+1] = cast(ubyte)(v>>8);
    b[off+2] = cast(ubyte)(v>>16); b[off+3] = cast(ubyte)(v>>24);
    off += 4;
}
private void putTx(ubyte* b, ulong cap, ref ulong off, const ref BinderTxData tx) {
    if (off + BinderTxData.sizeof > cap) return;
    auto s = cast(const(ubyte)*)&tx;
    foreach (i; 0 .. BinderTxData.sizeof) b[off + i] = s[i];
    off += BinderTxData.sizeof;
}
private uint rdU32(const(ubyte)* b, ulong off) {
    return b[off] | (b[off+1]<<8) | (b[off+2]<<16) | (cast(uint)b[off+3]<<24);
}

/**
 * BINDER_WRITE_READ, on kernel buffers.  Parses `wbuf[0..wsize]` as a BC_* command stream and
 * writes a BR_* return stream into `rbuf[0..rsize]`.  Sets *wconsumed = bytes of write consumed and
 * *rconsumed = bytes of read produced.  Returns 0, or -errno.
 */
public long binderWriteRead(int id, const(ubyte)* wbuf, ulong wsize, ulong* wconsumed,
                            ubyte* rbuf, ulong rsize, ulong* rconsumed) {
    if (id < 0 || id >= MAX_PROCS || !g_procs[id].used) return -22; // EINVAL
    ulong rpos = 0;
    ulong wpos = 0;

    // Process the write command stream.
    while (wpos + 4 <= wsize) {
        const uint cmd = rdU32(wbuf, wpos);
        wpos += 4;
        switch (cmd) {
            case BC_ENTER_LOOPER: case BC_REGISTER_LOOPER:
                g_procs[id].looper = true;
                break;
            case BC_EXIT_LOOPER:
                g_procs[id].looper = false;
                break;
            case BC_INCREFS: case BC_ACQUIRE: case BC_RELEASE: case BC_DECREFS:
                wpos += 4;   // a u32 ref target; acknowledged, no BR in A1
                break;
            case BC_FREE_BUFFER:
                wpos += 8;   // a binder_uintptr_t; the buffer is freed (no-op until A2)
                break;
            case BC_TRANSACTION: {
                if (wpos + BinderTxData.sizeof > wsize) { wpos = wsize; break; }
                BinderTxData tx;
                auto d = cast(ubyte*)&tx;
                foreach (i; 0 .. BinderTxData.sizeof) d[i] = wbuf[wpos + i];
                wpos += BinderTxData.sizeof;
                // A1 does not carry the payload (A2's mapped buffer does); deliver the header only.
                tx.data_size = 0; tx.offsets_size = 0; tx.data_buffer = 0; tx.data_offsets = 0;
                // Route by target handle.  Only the context manager (handle 0) is known in A1.
                const bool toMgr = (tx.target == 0);
                if (toMgr && g_contextMgr >= 0) {
                    mailPush(g_contextMgr, BR_TRANSACTION, tx);
                    putU32(rbuf, rsize, rpos, BR_TRANSACTION_COMPLETE);
                } else {
                    putU32(rbuf, rsize, rpos, BR_FAILED_REPLY);
                }
                break;
            }
            case BC_REPLY: {
                if (wpos + BinderTxData.sizeof > wsize) { wpos = wsize; break; }
                wpos += BinderTxData.sizeof;
                putU32(rbuf, rsize, rpos, BR_TRANSACTION_COMPLETE);
                break;
            }
            default:
                // Unknown command: stop parsing rather than misread the stream (A1 is a subset).
                wpos = wsize;
                break;
        }
    }
    if (wconsumed !is null) *wconsumed = wpos;

    // Drain this proc's mailbox into the read stream: a BR_NOOP lead-in (as real binder emits), then
    // each pending transaction/reply as its code + binder_transaction_data.
    if (rsize >= 4) putU32(rbuf, rsize, rpos, BR_NOOP);
    Mail m;
    while (rpos + 4 + BinderTxData.sizeof <= rsize && mailPop(id, m)) {
        putU32(rbuf, rsize, rpos, m.code);
        putTx(rbuf, rsize, rpos, m.tx);
    }
    if (rconsumed !is null) *rconsumed = rpos;
    return 0;
}

// ---- boot self-test --------------------------------------------------------------------------

import core.io : klog;

/// A1 proof: open a binder proc, check the version, set max threads, become the context manager,
/// then WRITE_READ a BC_ENTER_LOOPER + BC_TRANSACTION to handle 0 and confirm the return stream
/// carries BR_TRANSACTION_COMPLETE and that the transaction routed back as BR_TRANSACTION.
public void binderSelfTest() {
    bool ok = true;
    const int a = binderAlloc();
    ok = ok && (a >= 0);
    ok = ok && (binderVersion() == 8);
    binderSetMaxThreads(a, 15);
    ok = ok && (g_procs[a].maxThreads == 15);
    ok = ok && (binderSetContextMgr(a) == 0);
    ok = ok && (binderSetContextMgr(a) == 0);   // same proc, idempotent

    // write: BC_ENTER_LOOPER, BC_TRANSACTION{target=0, code=0x2a}
    ubyte[4 + 4 + BinderTxData.sizeof] wbuf = 0;
    ulong w = 0;
    putU32(wbuf.ptr, wbuf.length, w, BC_ENTER_LOOPER);
    putU32(wbuf.ptr, wbuf.length, w, BC_TRANSACTION);
    BinderTxData tx; tx.target = 0; tx.code = 0x2a; tx.flags = 0;
    putTx(wbuf.ptr, wbuf.length, w, tx);

    ubyte[256] rbuf = 0;
    ulong wc = 0, rc = 0;
    const long r = binderWriteRead(a, wbuf.ptr, w, &wc, rbuf.ptr, rbuf.length, &rc);
    ok = ok && (r == 0) && (wc == w);

    // The sender's read stream must contain BR_TRANSACTION_COMPLETE; and because the sender IS the
    // context manager, the transaction it sent to handle 0 must come back as BR_TRANSACTION(code 0x2a).
    bool sawComplete = false, sawTxn = false;
    ulong p = 0;
    while (p + 4 <= rc) {
        const uint code = rdU32(rbuf.ptr, p); p += 4;
        if (code == BR_TRANSACTION_COMPLETE) { sawComplete = true; continue; }
        if (code == BR_TRANSACTION || code == BR_REPLY) {
            if (p + BinderTxData.sizeof <= rc) {
                const uint rxcode = rdU32(rbuf.ptr, p + 16);  // code is at offset 16 in BinderTxData
                if (code == BR_TRANSACTION && rxcode == 0x2a) sawTxn = true;
                p += BinderTxData.sizeof;
            } else break;
        }
        // BR_NOOP and others carry no payload.
    }
    ok = ok && sawComplete && sawTxn;

    binderFree(a);
    ok = ok && (g_contextMgr == -1);

    if (ok) klog("[binder] selftest PASS (version 8, context-mgr, WRITE_READ transaction round-trip)\n");
    else    klog("[binder] selftest FAIL\n");
}
