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

import core.exports : phys_to_virt;
import memory.mm : alloc_phys_pages, free_phys_pages;

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
    // A2: the mmap'd receive buffer.  regionPhys is contiguous kernel-owned physical memory mapped
    // into the proc at regionUserBase (recorded after the mmap maps it); the kernel writes
    // transaction data here via phys_to_virt and hands the proc a pointer at regionUserBase+off.
    ulong regionPhys;
    ulong regionUserBase;
    uint  regionSize;
    uint  bumpUsed;     // simple bump allocator; reset when the last buffer is freed (A3: real freelist)
    int   allocCount;
}

// BINDER_VM_MAX caps a proc's receive region.  libbinder uses ~1 MiB by default and at most 4 MiB.
private enum uint BINDER_VM_MAX = 4 * 1024 * 1024;

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
    if (g_procs[id].regionPhys != 0)
        free_phys_pages(g_procs[id].regionPhys, g_procs[id].regionSize / 4096);
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

// ---- A2: the receive region and its allocator -----------------------------------------------

/// mmap of /dev/binder: allocate the proc's receive region (once) of `size` bytes, contiguous and
/// zeroed, and return its physical base for the mmap dispatcher to map.  0 on failure.
public ulong binderMmapAlloc(int id, uint size) {
    if (id < 0 || id >= MAX_PROCS || !g_procs[id].used) return 0;
    auto p = &g_procs[id];
    if (p.regionPhys != 0) return p.regionPhys;     // libbinder maps once
    if (size == 0) return 0;
    if (size > BINDER_VM_MAX) size = BINDER_VM_MAX;
    const uint pages = (size + 4095) / 4096;
    const ulong phys = alloc_phys_pages(pages);
    if (phys == 0) return 0;
    auto z = cast(ubyte*)phys_to_virt(phys);
    foreach (i; 0 .. pages * 4096) z[i] = 0;
    p.regionPhys = phys;
    p.regionSize = pages * 4096;
    p.bumpUsed = 0;
    p.allocCount = 0;
    return phys;
}

/// Record where the region was mapped, and how many bytes were actually mapped (the dispatcher
/// knows both only after mapping).  Allocation is clamped to the mapped length so a handed-out
/// pointer is always backed -- the physical region may be larger than the mapping.  Pointers given
/// to the proc are regionUserBase + off.
public void binderNoteMmap(int id, ulong uvaddr, ulong mappedLen) {
    if (id < 0 || id >= MAX_PROCS || !g_procs[id].used) return;
    g_procs[id].regionUserBase = uvaddr;
    if (mappedLen < g_procs[id].regionSize) g_procs[id].regionSize = cast(uint)mappedLen;
}

public uint binderRegionSize(int id) {
    return (id >= 0 && id < MAX_PROCS && g_procs[id].used) ? g_procs[id].regionSize : 0;
}

// Allocate `n` bytes from the proc's region (8-byte aligned); -1 when there is no region or no room.
private long bufAlloc(int id, uint n) {
    auto p = &g_procs[id];
    if (p.regionPhys == 0) return -1;
    const uint need = (n + 7) & ~7u;
    if (p.bumpUsed + need > p.regionSize) return -1;
    const uint off = p.bumpUsed;
    p.bumpUsed += need;
    ++p.allocCount;
    return cast(long)off;
}

/// BC_FREE_BUFFER: the proc is done with a received buffer (a user pointer into its region).  A2
/// uses a bump allocator, so the space is reclaimed only once every buffer is freed (A3: freelist).
public void binderFreeBuffer(int id, ulong userptr) {
    if (id < 0 || id >= MAX_PROCS || !g_procs[id].used) return;
    auto p = &g_procs[id];
    if (p.regionUserBase == 0 || userptr < p.regionUserBase ||
        userptr >= p.regionUserBase + p.regionSize) return;
    if (p.allocCount > 0) --p.allocCount;
    if (p.allocCount == 0) p.bumpUsed = 0;
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

// BinderCopyIn reads `n` bytes from a SENDER user address `uaddr` into `dst` (kernel), returning the
// bytes copied.  posix.d supplies one that copies under SMAP from the sender's current address
// space; the self-test supplies one that treats `uaddr` as a kernel pointer.  binder.d never
// dereferences user memory itself.
alias BinderCopyIn = ulong function(ulong uaddr, ubyte* dst, ulong n) @nogc nothrow;

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
                            ubyte* rbuf, ulong rsize, ulong* rconsumed, BinderCopyIn copyin) {
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
            case BC_FREE_BUFFER: {
                if (wpos + 8 > wsize) { wpos = wsize; break; }
                ulong bufptr = 0;
                foreach (i; 0 .. 8) bufptr |= cast(ulong)wbuf[wpos + i] << (8 * i);
                wpos += 8;
                binderFreeBuffer(id, bufptr);   // A2: reclaim the received buffer
                break;
            }
            case BC_TRANSACTION: {
                if (wpos + BinderTxData.sizeof > wsize) { wpos = wsize; break; }
                BinderTxData tx;
                auto d = cast(ubyte*)&tx;
                foreach (i; 0 .. BinderTxData.sizeof) d[i] = wbuf[wpos + i];
                wpos += BinderTxData.sizeof;
                // Route by target handle.  Only the context manager (handle 0) is known until A3
                // adds a handle table.
                const int tgt = (tx.target == 0) ? g_contextMgr : -1;
                const ulong srcBuf = tx.data_buffer;
                const uint  dsz = (tx.data_size > BINDER_VM_MAX) ? 0 : cast(uint)tx.data_size;
                // A2 carries the DATA; object OFFSETS need handle/fd translation, which is A3, so
                // they are not forwarded yet.
                tx.offsets_size = 0; tx.data_offsets = 0;
                bool ok = (tgt >= 0 && g_procs[tgt].used && g_procs[tgt].regionPhys != 0);
                long off = -1;
                if (ok) { off = bufAlloc(tgt, dsz); ok = (off >= 0); }
                if (ok && dsz > 0 && copyin !is null) {
                    // Pull the data out of the SENDER's address space into the TARGET's region.
                    auto rp = cast(ubyte*)phys_to_virt(g_procs[tgt].regionPhys) + cast(uint)off;
                    copyin(srcBuf, rp, dsz);
                }
                if (ok) {
                    tx.data_size   = dsz;
                    tx.data_buffer = g_procs[tgt].regionUserBase + cast(ulong)off;
                    mailPush(tgt, BR_TRANSACTION, tx);
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

// A test copy-in: the self-test has no user context, so a "user address" is a kernel pointer.
private ulong testCopyIn(ulong uaddr, ubyte* dst, ulong n) @nogc nothrow {
    auto src = cast(const(ubyte)*)uaddr;
    foreach (i; 0 .. n) dst[i] = src[i];
    return n;
}

/// A1+A2 proof: open a proc, check the version, set max threads, become the context manager, give
/// it a receive region (standing in for mmap), then WRITE_READ a BC_ENTER_LOOPER + BC_TRANSACTION
/// to handle 0 carrying a data payload.  Confirm the return stream has BR_TRANSACTION_COMPLETE and
/// a BR_TRANSACTION whose buffer lies in the region and holds the bytes sent, then BC_FREE_BUFFER it.
public void binderSelfTest() {
    bool ok = true;
    const int a = binderAlloc();
    ok = ok && (a >= 0);
    ok = ok && (binderVersion() == 8);
    binderSetMaxThreads(a, 15);
    ok = ok && (g_procs[a].maxThreads == 15);
    ok = ok && (binderSetContextMgr(a) == 0);
    ok = ok && (binderSetContextMgr(a) == 0);   // same proc, idempotent

    // A2: give the proc a receive region (stands in for the user mmap).  Its "user base" is the
    // kernel alias, so the test can read the delivered pointer directly.
    const ulong phys = binderMmapAlloc(a, 64 * 1024);
    ok = ok && (phys != 0) && (binderRegionSize(a) == 64 * 1024);
    binderNoteMmap(a, phys_to_virt(phys), 64 * 1024);

    // A payload the transaction carries.
    ubyte[16] payload;
    foreach (i; 0 .. payload.length) payload[i] = cast(ubyte)(0xB0 + i);

    // write: BC_ENTER_LOOPER, BC_TRANSACTION{target=0, code=0x2a, data=payload}
    ubyte[4 + 4 + BinderTxData.sizeof] wbuf = 0;
    ulong w = 0;
    putU32(wbuf.ptr, wbuf.length, w, BC_ENTER_LOOPER);
    putU32(wbuf.ptr, wbuf.length, w, BC_TRANSACTION);
    BinderTxData tx; tx.target = 0; tx.code = 0x2a; tx.flags = 0;
    tx.data_size = payload.length; tx.data_buffer = cast(ulong)payload.ptr;
    putTx(wbuf.ptr, wbuf.length, w, tx);

    ubyte[256] rbuf = 0;
    ulong wc = 0, rc = 0;
    const long r = binderWriteRead(a, wbuf.ptr, w, &wc, rbuf.ptr, rbuf.length, &rc, &testCopyIn);
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
                BinderTxData rx;
                auto d = cast(ubyte*)&rx;
                foreach (i; 0 .. BinderTxData.sizeof) d[i] = rbuf[p + i];
                if (code == BR_TRANSACTION && rx.code == 0x2a && rx.data_size == payload.length) {
                    // The delivered buffer must lie in the region and hold the bytes we sent.
                    const ulong base = phys_to_virt(phys);
                    if (rx.data_buffer >= base && rx.data_buffer + rx.data_size <= base + binderRegionSize(a)) {
                        auto got = cast(const(ubyte)*)rx.data_buffer;
                        bool bytesOk = true;
                        foreach (i; 0 .. payload.length) if (got[i] != payload[i]) bytesOk = false;
                        if (bytesOk) { sawTxn = true; binderFreeBuffer(a, rx.data_buffer); }
                    }
                }
                p += BinderTxData.sizeof;
            } else break;
        }
        // BR_NOOP and others carry no payload.
    }
    ok = ok && sawComplete && sawTxn;
    ok = ok && (g_procs[a].allocCount == 0) && (g_procs[a].bumpUsed == 0);   // freed + reclaimed

    binderFree(a);
    ok = ok && (g_contextMgr == -1);

    if (ok) klog("[binder] selftest PASS (A1+A2: version 8, context-mgr, mmap region, transaction data round-trip, free)\n");
    else    klog("[binder] selftest FAIL\n");
}
