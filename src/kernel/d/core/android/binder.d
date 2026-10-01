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
enum uint BC_INCREFS_DONE   = 0x4010_6308;  // _IOW('c', 8, binder_ptr_cookie) -- 16 bytes
enum uint BC_ACQUIRE_DONE   = 0x4010_6309;  // _IOW('c', 9, binder_ptr_cookie)
enum uint BC_REGISTER_LOOPER= 0x0000_630B;  // _IO('c',11)
enum uint BC_ENTER_LOOPER   = 0x0000_630C;  // _IO('c',12)
enum uint BC_EXIT_LOOPER    = 0x0000_630D;  // _IO('c',13)
// A3: death notifications (binder_handle_cookie is __packed: u32 handle + u64 cookie = 12 bytes).
enum uint BC_REQUEST_DEATH_NOTIFICATION = 0x400C_630E;  // _IOW('c',14, binder_handle_cookie)
enum uint BC_CLEAR_DEATH_NOTIFICATION   = 0x400C_630F;  // _IOW('c',15, binder_handle_cookie)
enum uint BC_DEAD_BINDER_DONE           = 0x4008_6310;  // _IOW('c',16, binder_uintptr_t)

// BR_* : returns delivered to userspace.
enum uint BR_TRANSACTION          = 0x8030_7202;  // _IOR('r',2, binder_transaction_data)
enum uint BR_REPLY                = 0x8030_7203;  // _IOR('r',3, binder_transaction_data)
enum uint BR_DEAD_REPLY           = 0x0000_7205;  // _IO('r',5) -- target gone mid-transaction
enum uint BR_TRANSACTION_COMPLETE = 0x0000_7206;  // _IO('r',6)
enum uint BR_NOOP                 = 0x0000_720C;  // _IO('r',12)
enum uint BR_DEAD_BINDER          = 0x8008_720F;  // _IOR('r',15, binder_uintptr_t) -- carries a cookie
enum uint BR_CLEAR_DEATH_NOTIFICATION_DONE = 0x8008_7210; // _IOR('r',16, binder_uintptr_t)
enum uint BR_FAILED_REPLY         = 0x0000_7211;

// Transaction flags (binder_transaction_data.flags).
enum uint TF_ONE_WAY = 0x01;   // asynchronous: no reply, no transaction stack entry

// Flat-object types, B_PACK_CHARS('x','y','*', B_TYPE_LARGE=0x85), as binder.h packs them.
private enum uint B_TYPE_LARGE = 0x85;
enum uint BINDER_TYPE_BINDER      = (cast(uint)'s'<<24)|(cast(uint)'b'<<16)|(cast(uint)'*'<<8)|B_TYPE_LARGE;
enum uint BINDER_TYPE_WEAK_BINDER = (cast(uint)'w'<<24)|(cast(uint)'b'<<16)|(cast(uint)'*'<<8)|B_TYPE_LARGE;
enum uint BINDER_TYPE_HANDLE      = (cast(uint)'s'<<24)|(cast(uint)'h'<<16)|(cast(uint)'*'<<8)|B_TYPE_LARGE;
enum uint BINDER_TYPE_WEAK_HANDLE = (cast(uint)'w'<<24)|(cast(uint)'h'<<16)|(cast(uint)'*'<<8)|B_TYPE_LARGE;
enum uint BINDER_TYPE_FD          = (cast(uint)'f'<<24)|(cast(uint)'d'<<16)|(cast(uint)'*'<<8)|B_TYPE_LARGE;

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

// flat_binder_object: 24 bytes on 64-bit.  The `payload` union is a binder ptr (TYPE_BINDER) or a
// handle in its low 32 bits (TYPE_HANDLE); `cookie` carries the owner's BBinder cookie for a BINDER.
// The transaction's offsets array lists the byte offset of each of these within the data buffer; the
// driver walks them and rewrites BINDER<->HANDLE so a reference means the right thing in each proc.
struct FlatBinderObject {
align(1):
    uint  type;
    uint  flags;
    ulong payload;   // binder ptr, or handle (low 32 bits)
    ulong cookie;
}
static assert(FlatBinderObject.sizeof == 24);

// ---- per-open state --------------------------------------------------------------------------
private enum int MAX_PROCS   = 64;
private enum int MAILBOX_CAP = 32;
private enum int MAX_HANDLES = 256;   // per-proc handle table (handle 0 reserved for the context mgr)
private enum int MAX_TXSTACK = 16;    // depth of nested synchronous transactions awaiting a reply

private struct Mail {
    uint code;          // BR_TRANSACTION / BR_REPLY (tx used), or BR_DEAD_BINDER (tx.cookie used)
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
    // A3: this proc's handle table (handle -> node index; -1 = free) and its stack of incoming
    // synchronous transactions, each recording the sender to route the eventual BC_REPLY back to.
    int[MAX_HANDLES] handleNode = -1;
    int  txStackN;
    int[MAX_TXSTACK] txStackSender;
    // A3b: the fd-table id of the task that opened this /dev/binder, so a TYPE_FD object can be
    // installed into the right process's fd table.  -1 until posix.d records it (binderSetProcTab).
    int  ownerTab = -1;
}

// BINDER_VM_MAX caps a proc's receive region.  libbinder uses ~1 MiB by default and at most 4 MiB.
private enum uint BINDER_VM_MAX = 4 * 1024 * 1024;

private __gshared BinderProc[MAX_PROCS] g_procs;
private __gshared int g_contextMgr = -1;   // the proc index registered as handle 0, or -1

// ---- A3: the binder node table ---------------------------------------------------------------
// A node is a binder object living in its owner proc.  Other procs reach it through a handle in
// their own table.  Clients may subscribe to the node's death; when the owner goes away the kernel
// delivers BR_DEAD_BINDER{cookie} to each subscriber.
private enum int MAX_NODES = 256;
private enum int MAX_DEATH = 8;      // death subscribers per node

private struct Node {
    bool  used;
    int   owner;        // proc index that owns the binder object
    ulong ptr;          // the owner's local binder pointer (its BBinder weak ref)
    ulong cookie;       // the owner's cookie (its BBinder)
    int   strongRefs;
    int   subN;
    int[MAX_DEATH]   subProc;    // subscriber proc indices
    ulong[MAX_DEATH] subCookie;  // the cookie each subscriber wants echoed back on death
}

private __gshared Node[MAX_NODES] g_nodes;
private __gshared int g_ctxMgrNode = -1;   // the node every proc reaches as handle 0, or -1

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

/// Release a binder proc on close (or on a crash).  A3: every node this proc owned now has a dead
/// owner, so fire a death notification to each subscriber before dropping those nodes.
public void binderFree(int id) {
    if (id < 0 || id >= MAX_PROCS || !g_procs[id].used) return;
    foreach (n; 0 .. MAX_NODES) {
        if (!g_nodes[n].used || g_nodes[n].owner != id) continue;
        foreach (s; 0 .. g_nodes[n].subN) {
            const int sp = g_nodes[n].subProc[s];
            if (sp >= 0 && sp < MAX_PROCS && g_procs[sp].used && sp != id) {
                BinderTxData dm; dm.cookie = g_nodes[n].subCookie[s];
                mailPush(sp, BR_DEAD_BINDER, dm);
            }
        }
        g_nodes[n] = Node.init;   // the owner is gone; outstanding handles to it are now dead
    }
    if (g_contextMgr == id) { g_contextMgr = -1; g_ctxMgrNode = -1; }
    if (g_procs[id].regionPhys != 0)
        free_phys_pages(g_procs[id].regionPhys, g_procs[id].regionSize / 4096);
    g_procs[id] = BinderProc.init;
}

public int binderVersion() { return BINDER_CURRENT_PROTOCOL_VERSION; }

// A3b: record the owning task's fd-table id, so a TYPE_FD object sent by this proc is dup'd out of
// (and into) the right process's fd table.  posix.d calls this when /dev/binder is opened.
public void binderSetProcTab(int id, int tab) {
    if (id >= 0 && id < MAX_PROCS && g_procs[id].used) g_procs[id].ownerTab = tab;
}

// A3b: the cross-process fd installer.  binder.d holds no fd machinery of its own, so posix.d
// supplies this: dup `fromFd` out of table `fromTab` into table `toTab`, returning the new fd there
// (or -1).  Set once via binderSetFdDup; null until then (and in the kernel-only self-test, which
// swaps in a stub).
alias BinderFdDup = long function(int fromTab, uint fromFd, int toTab) @nogc nothrow;
private __gshared BinderFdDup g_binderFdDup;
public void binderSetFdDup(BinderFdDup f) { g_binderFdDup = f; }

public void binderSetMaxThreads(int id, uint n) {
    if (id >= 0 && id < MAX_PROCS && g_procs[id].used) g_procs[id].maxThreads = n;
}

/// Register `id` as the context manager (handle 0).  EBUSY if one is already set, EINVAL on a bad id.
/// A3: the context manager gets a node, so every proc reaches it as handle 0 and can subscribe to
/// its death like any other object.
public long binderSetContextMgr(int id) {
    if (id < 0 || id >= MAX_PROCS || !g_procs[id].used) return -22; // EINVAL
    if (g_contextMgr >= 0 && g_contextMgr != id) return -16;        // EBUSY
    g_contextMgr = id;
    if (g_ctxMgrNode < 0) g_ctxMgrNode = nodeFindOrCreate(id, 0, 0);
    else                  g_nodes[g_ctxMgrNode].owner = id;
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

// ---- A3: nodes, handles, flat-object translation --------------------------------------------

// Find the node for (owner, ptr), or create one; -1 when the node table is full.
private int nodeFindOrCreate(int owner, ulong ptr, ulong cookie) {
    foreach (i; 0 .. MAX_NODES)
        if (g_nodes[i].used && g_nodes[i].owner == owner && g_nodes[i].ptr == ptr)
            return i;
    foreach (i; 0 .. MAX_NODES)
        if (!g_nodes[i].used) {
            g_nodes[i] = Node.init;
            g_nodes[i].used   = true;
            g_nodes[i].owner  = owner;
            g_nodes[i].ptr    = ptr;
            g_nodes[i].cookie = cookie;
            return i;
        }
    return -1;
}

// The handle `proc` uses for `nidx`, reusing an existing one or allocating the lowest free handle
// (handle 0 is reserved for the context manager); -1 when the table is full.
private int handleForNode(int proc, int nidx) {
    auto p = &g_procs[proc];
    foreach (h; 1 .. MAX_HANDLES) if (p.handleNode[h] == nidx) return h;
    foreach (h; 1 .. MAX_HANDLES) if (p.handleNode[h] < 0) { p.handleNode[h] = nidx; return h; }
    return -1;
}

// Resolve a handle in `proc` to a node index; handle 0 is the context manager.  -1 if unknown.
private int handleResolve(int proc, uint handle) {
    if (handle == 0) return g_ctxMgrNode;
    if (handle >= MAX_HANDLES) return -1;
    return g_procs[proc].handleNode[handle];
}

// Translate one flat_binder_object in place as it crosses from `sender` to `target`.  A local
// BINDER becomes a HANDLE in the target; a HANDLE becomes a BINDER when it returns to the owner, or
// is re-expressed as a handle in the target otherwise.  false => the object cannot cross (a bad
// handle, or a TYPE_FD, which needs the target's fd table -- deferred to A3b), so the whole
// transaction fails rather than deliver a bogus reference.
private bool translateObject(int sender, int target, FlatBinderObject* fo) {
    switch (fo.type) {
        case BINDER_TYPE_BINDER:
        case BINDER_TYPE_WEAK_BINDER: {
            const int nidx = nodeFindOrCreate(sender, fo.payload, fo.cookie);
            if (nidx < 0) return false;
            ++g_nodes[nidx].strongRefs;
            const int h = handleForNode(target, nidx);
            if (h < 0) return false;
            fo.type    = (fo.type == BINDER_TYPE_WEAK_BINDER) ? BINDER_TYPE_WEAK_HANDLE : BINDER_TYPE_HANDLE;
            fo.payload = cast(uint)h;
            fo.cookie  = 0;
            return true;
        }
        case BINDER_TYPE_HANDLE:
        case BINDER_TYPE_WEAK_HANDLE: {
            const int nidx = handleResolve(sender, cast(uint)fo.payload);
            if (nidx < 0) return false;
            if (g_nodes[nidx].owner == target) {
                fo.type    = (fo.type == BINDER_TYPE_WEAK_HANDLE) ? BINDER_TYPE_WEAK_BINDER : BINDER_TYPE_BINDER;
                fo.payload = g_nodes[nidx].ptr;
                fo.cookie  = g_nodes[nidx].cookie;
            } else {
                const int h = handleForNode(target, nidx);
                if (h < 0) return false;
                fo.payload = cast(uint)h;
            }
            return true;
        }
        case BINDER_TYPE_FD: {
            // A3b: the low 32 bits hold the sender's fd; dup it into the target's fd table and
            // rewrite to the target's new fd.  Without an installer, or across procs whose owning
            // task is unknown, the fd cannot cross -- fail rather than hand over a bogus number.
            if (g_binderFdDup is null) return false;
            const int fromTab = g_procs[sender].ownerTab;
            const int toTab   = g_procs[target].ownerTab;
            if (fromTab < 0 || toTab < 0) return false;
            const long nf = g_binderFdDup(fromTab, cast(uint)fo.payload, toTab);
            if (nf < 0) return false;
            fo.payload = cast(uint)nf;
            return true;
        }
        default:
            // Anything unexpected: fail closed.
            return false;
    }
}

// Copy a transaction's data and offsets from `sender`'s address space into `target`'s receive
// region, translate every flat object the offsets point at, and rewrite `tx` to point into the
// target region.  Returns 0 on success, -1 on failure (no room, bad offsets, or an object that
// cannot cross); on failure nothing is enqueued.
private long deliverTxn(int sender, int target, ref BinderTxData tx, bool isReply, BinderCopyIn copyin) {
    if (target < 0 || target >= MAX_PROCS || !g_procs[target].used || g_procs[target].regionPhys == 0)
        return -1;
    const uint dsz = (tx.data_size    > BINDER_VM_MAX) ? 0 : cast(uint)tx.data_size;
    const uint osz = (tx.offsets_size > BINDER_VM_MAX) ? 0 : cast(uint)tx.offsets_size;
    const uint dAligned = (dsz + 7) & ~7u;
    const long base = bufAlloc(target, dAligned + osz);
    if (base < 0) return -1;
    auto region = cast(ubyte*)phys_to_virt(g_procs[target].regionPhys) + cast(uint)base;
    if (dsz > 0 && copyin !is null) copyin(tx.data_buffer,  region,            dsz);
    if (osz > 0 && copyin !is null) copyin(tx.data_offsets, region + dAligned, osz);
    // Walk the offsets array and translate each flat object sitting in the copied data.
    const uint noff = osz / 8;
    foreach (k; 0 .. noff) {
        const ulong offVal = rdU64(region + dAligned, k * 8);
        if (offVal + FlatBinderObject.sizeof > dsz) return -1;
        if (!translateObject(sender, target, cast(FlatBinderObject*)(region + offVal))) return -1;
    }
    tx.data_size    = dsz;
    tx.offsets_size = osz;
    tx.data_buffer  = g_procs[target].regionUserBase + cast(ulong)base;
    tx.data_offsets = g_procs[target].regionUserBase + cast(ulong)base + dAligned;
    return mailPush(target, isReply ? BR_REPLY : BR_TRANSACTION, tx) ? 0 : -1;
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

// Peek the head return code without consuming it, so the drain can size-check before popping.
private bool mailPeek(int id, ref uint code) {
    auto p = &g_procs[id];
    if (p.mailLen == 0) return false;
    code = p.mail[p.mailHead].code;
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
private void putU64(ubyte* b, ulong cap, ref ulong off, ulong v) {
    if (off + 8 > cap) return;
    foreach (i; 0 .. 8) b[off + i] = cast(ubyte)(v >> (8 * i));
    off += 8;
}
private ulong rdU64(const(ubyte)* b, ulong off) {
    ulong v = 0;
    foreach (i; 0 .. 8) v |= cast(ulong)b[off + i] << (8 * i);
    return v;
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
                wpos += 4;   // a u32 ref target; acknowledged, no BR here
                break;
            case BC_INCREFS_DONE: case BC_ACQUIRE_DONE:
                wpos += 16;  // binder_ptr_cookie (ptr + cookie); acknowledged
                break;
            case BC_REQUEST_DEATH_NOTIFICATION: {
                if (wpos + 12 > wsize) { wpos = wsize; break; }
                const uint handle = rdU32(wbuf, wpos);
                const ulong cookie = rdU64(wbuf, wpos + 4);
                wpos += 12;
                const int nidx = handleResolve(id, handle);
                if (nidx >= 0 && g_nodes[nidx].subN < MAX_DEATH) {
                    g_nodes[nidx].subProc[g_nodes[nidx].subN]   = id;
                    g_nodes[nidx].subCookie[g_nodes[nidx].subN] = cookie;
                    ++g_nodes[nidx].subN;
                }
                break;
            }
            case BC_CLEAR_DEATH_NOTIFICATION: {
                if (wpos + 12 > wsize) { wpos = wsize; break; }
                const uint handle = rdU32(wbuf, wpos);
                const ulong cookie = rdU64(wbuf, wpos + 4);
                wpos += 12;
                const int nidx = handleResolve(id, handle);
                if (nidx >= 0) {
                    auto nd = &g_nodes[nidx];
                    foreach (s; 0 .. nd.subN)
                        if (nd.subProc[s] == id && nd.subCookie[s] == cookie) {
                            foreach (t; s .. nd.subN - 1) {
                                nd.subProc[t]   = nd.subProc[t + 1];
                                nd.subCookie[t] = nd.subCookie[t + 1];
                            }
                            --nd.subN;
                            break;
                        }
                }
                // Acknowledge the clear in this proc's own read stream.
                putU32(rbuf, rsize, rpos, BR_CLEAR_DEATH_NOTIFICATION_DONE);
                putU64(rbuf, rsize, rpos, cookie);
                break;
            }
            case BC_DEAD_BINDER_DONE:
                wpos += 8;   // binder_uintptr_t ack of a delivered BR_DEAD_BINDER
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
                const uint origFlags = tx.flags;
                // Route by target: handle 0 is the context manager; any other handle resolves
                // through this proc's handle table to the owning proc (A3).
                int tgt = -1;
                if (tx.target == 0) tgt = g_contextMgr;
                else {
                    const int nidx = handleResolve(id, cast(uint)tx.target);
                    if (nidx >= 0) tgt = g_nodes[nidx].owner;
                }
                if (tgt >= 0 && deliverTxn(id, tgt, tx, false, copyin) == 0) {
                    // A synchronous call records us as the sender so the target's BC_REPLY routes
                    // back here; a one-way call expects no reply.
                    if ((origFlags & TF_ONE_WAY) == 0) {
                        auto tp = &g_procs[tgt];
                        if (tp.txStackN < MAX_TXSTACK) tp.txStackSender[tp.txStackN++] = id;
                    }
                    putU32(rbuf, rsize, rpos, BR_TRANSACTION_COMPLETE);
                } else {
                    putU32(rbuf, rsize, rpos, BR_FAILED_REPLY);
                }
                break;
            }
            case BC_REPLY: {
                if (wpos + BinderTxData.sizeof > wsize) { wpos = wsize; break; }
                BinderTxData tx;
                auto d = cast(ubyte*)&tx;
                foreach (i; 0 .. BinderTxData.sizeof) d[i] = wbuf[wpos + i];
                wpos += BinderTxData.sizeof;
                // Pop the sender of the transaction we are replying to, and deliver BR_REPLY there.
                auto me = &g_procs[id];
                int dest = -1;
                if (me.txStackN > 0) dest = me.txStackSender[--me.txStackN];
                if (dest >= 0 && deliverTxn(id, dest, tx, true, copyin) == 0)
                    putU32(rbuf, rsize, rpos, BR_TRANSACTION_COMPLETE);
                else
                    putU32(rbuf, rsize, rpos, BR_FAILED_REPLY);
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
    // each pending return.  A transaction/reply carries a binder_transaction_data; a death
    // notification carries only its cookie.  Size-check before popping so a record that will not fit
    // stays queued for the next read.
    if (rsize >= 4) putU32(rbuf, rsize, rpos, BR_NOOP);
    for (;;) {
        uint code;
        if (!mailPeek(id, code)) break;
        const bool isDeath = (code == BR_DEAD_BINDER || code == BR_CLEAR_DEATH_NOTIFICATION_DONE);
        const ulong need = isDeath ? (4 + 8) : (4 + BinderTxData.sizeof);
        if (rpos + need > rsize) break;
        Mail m;
        mailPop(id, m);
        putU32(rbuf, rsize, rpos, m.code);
        if (isDeath) putU64(rbuf, rsize, rpos, m.tx.cookie);
        else         putTx(rbuf, rsize, rpos, m.tx);
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

// Scan a BR return stream for the first record of code `want` (BR_TRANSACTION/BR_REPLY), copying its
// binder_transaction_data out; returns false if absent.  Skips the sizes of the records it passes.
private bool testFindTxn(const(ubyte)* b, ulong len, uint want, ref BinderTxData o) @nogc nothrow {
    ulong p = 0;
    while (p + 4 <= len) {
        const uint code = rdU32(b, p); p += 4;
        if (code == BR_TRANSACTION || code == BR_REPLY) {
            if (p + BinderTxData.sizeof > len) break;
            if (code == want) {
                auto d = cast(ubyte*)&o;
                foreach (i; 0 .. BinderTxData.sizeof) d[i] = b[p + i];
                return true;
            }
            p += BinderTxData.sizeof;
        } else if (code == BR_DEAD_BINDER || code == BR_CLEAR_DEATH_NOTIFICATION_DONE) {
            p += 8;
        }
        // BR_NOOP / BR_TRANSACTION_COMPLETE carry no payload.
    }
    return false;
}

// Scan a BR return stream for a BR_DEAD_BINDER and read its cookie; false if absent.
private bool testFindDead(const(ubyte)* b, ulong len, ref ulong cookie) @nogc nothrow {
    ulong p = 0;
    while (p + 4 <= len) {
        const uint code = rdU32(b, p); p += 4;
        if (code == BR_DEAD_BINDER) {
            if (p + 8 > len) break;
            cookie = rdU64(b, p);
            return true;
        } else if (code == BR_CLEAR_DEATH_NOTIFICATION_DONE) {
            p += 8;
        } else if (code == BR_TRANSACTION || code == BR_REPLY) {
            if (p + BinderTxData.sizeof > len) break;
            p += BinderTxData.sizeof;
        }
    }
    return false;
}

// Read the flat_binder_object a delivered transaction points at (offset 0 of its offsets array),
// following the kernel-alias pointers the test sees.
private FlatBinderObject* testFirstFlat(const ref BinderTxData t) @nogc nothrow {
    const ulong offVal = rdU64(cast(const(ubyte)*)t.data_offsets, 0);
    return cast(FlatBinderObject*)(t.data_buffer + offVal);
}

// A stub fd installer for the self-test (the real one lives in posix.d and needs user fd tables):
// it records the arguments and returns a remapped fd, so the test can prove the TYPE_FD path calls
// the installer with the right (fromTab, fd, toTab) and delivers the new fd.
private __gshared int   g_testFdFrom, g_testFdTo;
private __gshared uint  g_testFdOld;
private long testFdDup(int fromTab, uint fromFd, int toTab) @nogc nothrow {
    g_testFdFrom = fromTab; g_testFdTo = toTab; g_testFdOld = fromFd;
    return fromFd + 0x100;   // a distinctive remap the test can check for
}

/// A3 proof: a client and a context-manager server, each with a receive region.
///  (1) the client sends a transaction to handle 0 carrying a LOCAL binder object; the server must
///      receive it rewritten to a HANDLE.
///  (2) the server BC_REPLYs; the reply must route back to the client as BR_REPLY with its bytes.
///  (3) the server sends that handle back toward the client (its owner); it must arrive as the
///      original BINDER ptr/cookie -- the round trip.
///  (4) the server requests a death notification on the handle, the client "crashes"
///      (binderFree), and the server must read BR_DEAD_BINDER carrying the cookie.
private bool binderSelfTestA3() {
    bool ok = true;
    const int sv = binderAlloc();           // the service / context manager
    const int cl = binderAlloc();           // the client
    ok = ok && (sv >= 0) && (cl >= 0);
    ok = ok && (binderSetContextMgr(sv) == 0);
    const ulong svPhys = binderMmapAlloc(sv, 64 * 1024);
    const ulong clPhys = binderMmapAlloc(cl, 64 * 1024);
    ok = ok && (svPhys != 0) && (clPhys != 0);
    binderNoteMmap(sv, phys_to_virt(svPhys), 64 * 1024);
    binderNoteMmap(cl, phys_to_virt(clPhys), 64 * 1024);
    if (!ok) return false;

    // (1) client -> handle 0: a BINDER_TYPE_BINDER (the client's own service object).
    FlatBinderObject fbo; fbo.type = BINDER_TYPE_BINDER; fbo.payload = 0xA000; fbo.cookie = 0xC0DE;
    ulong[1] offs0 = [0UL];
    ubyte[4 + BinderTxData.sizeof] wb0 = 0; ulong w0 = 0;
    putU32(wb0.ptr, wb0.length, w0, BC_TRANSACTION);
    BinderTxData t0; t0.target = 0; t0.code = 1; t0.flags = 0;
    t0.data_size = FlatBinderObject.sizeof; t0.data_buffer = cast(ulong)&fbo;
    t0.offsets_size = 8; t0.data_offsets = cast(ulong)offs0.ptr;
    putTx(wb0.ptr, wb0.length, w0, t0);
    ubyte[256] rbCl0 = 0; ulong rc0 = 0;
    ok = ok && (binderWriteRead(cl, wb0.ptr, w0, null, rbCl0.ptr, rbCl0.length, &rc0, &testCopyIn) == 0);

    ubyte[256] rbSv0 = 0; ulong rcSv0 = 0;
    ok = ok && (binderWriteRead(sv, null, 0, null, rbSv0.ptr, rbSv0.length, &rcSv0, &testCopyIn) == 0);
    BinderTxData got0;
    int svHandle = -1;
    if (ok && testFindTxn(rbSv0.ptr, rcSv0, BR_TRANSACTION, got0) && got0.offsets_size == 8) {
        auto f = testFirstFlat(got0);
        ok = ok && (f.type == BINDER_TYPE_HANDLE) && (f.payload != 0);
        svHandle = cast(int)f.payload;
        binderFreeBuffer(sv, got0.data_buffer);
    } else ok = false;

    // (2) server BC_REPLY -> client sees BR_REPLY with the reply bytes.
    ubyte[4] replyBytes = [0xDE, 0xAD, 0xBE, 0xEF];
    ubyte[4 + BinderTxData.sizeof] wbR = 0; ulong wR = 0;
    putU32(wbR.ptr, wbR.length, wR, BC_REPLY);
    BinderTxData tR; tR.flags = 0; tR.data_size = 4; tR.data_buffer = cast(ulong)replyBytes.ptr;
    putTx(wbR.ptr, wbR.length, wR, tR);
    ubyte[128] rbSvR = 0; ulong rcSvR = 0;
    ok = ok && (binderWriteRead(sv, wbR.ptr, wR, null, rbSvR.ptr, rbSvR.length, &rcSvR, &testCopyIn) == 0);
    ubyte[256] rbClR = 0; ulong rcClR = 0;
    ok = ok && (binderWriteRead(cl, null, 0, null, rbClR.ptr, rbClR.length, &rcClR, &testCopyIn) == 0);
    BinderTxData gotR;
    if (ok && testFindTxn(rbClR.ptr, rcClR, BR_REPLY, gotR) && gotR.data_size == 4) {
        auto rp = cast(const(ubyte)*)gotR.data_buffer;
        ok = ok && rp[0] == 0xDE && rp[1] == 0xAD && rp[2] == 0xBE && rp[3] == 0xEF;
        binderFreeBuffer(cl, gotR.data_buffer);
    } else ok = false;

    // (3) server -> svHandle (owned by the client) carrying that same handle: it must arrive back at
    //     the client as the original BINDER ptr/cookie.  One-way: no reply expected.
    FlatBinderObject fbo2; fbo2.type = BINDER_TYPE_HANDLE; fbo2.payload = svHandle; fbo2.cookie = 0;
    ulong[1] offs2 = [0UL];
    ubyte[4 + BinderTxData.sizeof] wb2 = 0; ulong w2 = 0;
    putU32(wb2.ptr, wb2.length, w2, BC_TRANSACTION);
    BinderTxData t2; t2.target = cast(ulong)svHandle; t2.code = 2; t2.flags = TF_ONE_WAY;
    t2.data_size = FlatBinderObject.sizeof; t2.data_buffer = cast(ulong)&fbo2;
    t2.offsets_size = 8; t2.data_offsets = cast(ulong)offs2.ptr;
    putTx(wb2.ptr, wb2.length, w2, t2);
    ubyte[128] rbSv2 = 0; ulong rcSv2 = 0;
    ok = ok && (binderWriteRead(sv, wb2.ptr, w2, null, rbSv2.ptr, rbSv2.length, &rcSv2, &testCopyIn) == 0);
    ubyte[256] rbCl2 = 0; ulong rcCl2 = 0;
    ok = ok && (binderWriteRead(cl, null, 0, null, rbCl2.ptr, rbCl2.length, &rcCl2, &testCopyIn) == 0);
    BinderTxData got2;
    if (ok && testFindTxn(rbCl2.ptr, rcCl2, BR_TRANSACTION, got2)) {
        auto f2 = testFirstFlat(got2);
        ok = ok && (f2.type == BINDER_TYPE_BINDER) && (f2.payload == 0xA000) && (f2.cookie == 0xC0DE);
        binderFreeBuffer(cl, got2.data_buffer);
    } else ok = false;

    // (3b) fd passing: client -> handle 0 carrying a BINDER_TYPE_FD (fd 5).  With a stub installer
    // and the procs given fd-table ids, the server must receive the object as a TYPE_FD with the
    // remapped fd, and the installer must have been called with (client tab, 5, server tab).
    {
        const BinderFdDup saved = g_binderFdDup;
        binderSetFdDup(&testFdDup);
        binderSetProcTab(cl, 9);
        binderSetProcTab(sv, 7);
        g_testFdFrom = g_testFdTo = -1; g_testFdOld = 0xFFFF_FFFF;
        FlatBinderObject fbf; fbf.type = BINDER_TYPE_FD; fbf.payload = 5; fbf.cookie = 0;
        ulong[1] offsF = [0UL];
        ubyte[4 + BinderTxData.sizeof] wbF = 0; ulong wF = 0;
        putU32(wbF.ptr, wbF.length, wF, BC_TRANSACTION);
        BinderTxData tF; tF.target = 0; tF.code = 3; tF.flags = TF_ONE_WAY;
        tF.data_size = FlatBinderObject.sizeof; tF.data_buffer = cast(ulong)&fbf;
        tF.offsets_size = 8; tF.data_offsets = cast(ulong)offsF.ptr;
        putTx(wbF.ptr, wbF.length, wF, tF);
        ubyte[128] rbClF = 0; ulong rcClF = 0;
        ok = ok && (binderWriteRead(cl, wbF.ptr, wF, null, rbClF.ptr, rbClF.length, &rcClF, &testCopyIn) == 0);
        ubyte[256] rbSvF = 0; ulong rcSvF = 0;
        ok = ok && (binderWriteRead(sv, null, 0, null, rbSvF.ptr, rbSvF.length, &rcSvF, &testCopyIn) == 0);
        BinderTxData gotF;
        if (ok && testFindTxn(rbSvF.ptr, rcSvF, BR_TRANSACTION, gotF)) {
            auto fF = testFirstFlat(gotF);
            ok = ok && (fF.type == BINDER_TYPE_FD) && (fF.payload == 5 + 0x100);
            binderFreeBuffer(sv, gotF.data_buffer);
        } else ok = false;
        ok = ok && (g_testFdFrom == 9) && (g_testFdTo == 7) && (g_testFdOld == 5);
        binderSetProcTab(cl, -1);
        binderSetProcTab(sv, -1);
        binderSetFdDup(saved);   // never leave the stub installed in a running kernel
    }

    // (4) server requests a death notification on svHandle, the client crashes, server reads the death.
    ubyte[4 + 12] wbD = 0; ulong wD = 0;
    putU32(wbD.ptr, wbD.length, wD, BC_REQUEST_DEATH_NOTIFICATION);
    putU32(wbD.ptr, wbD.length, wD, cast(uint)svHandle);
    putU64(wbD.ptr, wbD.length, wD, 0xDEAD_BEEF_F00DUL);
    ubyte[64] rbDrq = 0; ulong rcDrq = 0;
    ok = ok && (binderWriteRead(sv, wbD.ptr, wD, null, rbDrq.ptr, rbDrq.length, &rcDrq, &testCopyIn) == 0);
    binderFree(cl);   // the client crashes
    ubyte[64] rbDrd = 0; ulong rcDrd = 0;
    ok = ok && (binderWriteRead(sv, null, 0, null, rbDrd.ptr, rbDrd.length, &rcDrd, &testCopyIn) == 0);
    ulong deadCookie = 0;
    ok = ok && testFindDead(rbDrd.ptr, rcDrd, deadCookie) && (deadCookie == 0xDEAD_BEEF_F00DUL);

    binderFree(sv);
    ok = ok && (g_contextMgr == -1);
    return ok;
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

    // A3: objects/handles, reply routing, death notifications (two procs).
    ok = ok && binderSelfTestA3();

    if (ok) klog("[binder] selftest PASS (A1+A2+A3+A3b: version 8, context-mgr, mmap region, data round-trip, handle translation, reply routing, fd passing, death notify)\n");
    else    klog("[binder] selftest FAIL\n");
}
