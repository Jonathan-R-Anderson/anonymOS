// ext4.d -- a read-only ext4 driver (ANDROID bring-up phase A9.3).
//
// Waydroid's Android lives in ext4 images (system.img, vendor.img) that are too large to stage in
// the boot ISO, so they are attached to the machine as raw disks and mounted read-only.  anonymOS
// had no ext4 reader; this is one, scoped to exactly what reading an Android /system needs:
// superblock, block-group descriptors (32- or 64-bit), inodes, extent trees, and linear directories.
// No journal, no writes, no hashed-dir (htree) -- a plain sequential scan, which is correct (htree
// dirs still carry a linear-compatible layout).
//
// Constraints mirror the kernel: -betterC, plain structs, __gshared scratch, @nogc nothrow.
module core.android.ext4;

import core.io : klog, klog_dec;
import drivers.block.disk : diskReadSectorsOn, diskReady;

@nogc nothrow:

private enum uint  SECTOR          = 512;
private enum ushort EXT4_MAGIC     = 0xEF53;    // superblock s_magic (byte offset 0x38)
private enum ushort EXT4_EXT_MAGIC = 0xF30A;    // extent header eh_magic
private enum uint  INCOMPAT_64BIT  = 0x0080;
private enum uint  ROOT_INO        = 2;
private enum uint  MAX_BLOCK       = 4096;

private ushort rd16(const(ubyte)* b, uint o) { return cast(ushort)(b[o] | (b[o+1] << 8)); }
private uint   rd32(const(ubyte)* b, uint o) {
    return b[o] | (cast(uint)b[o+1] << 8) | (cast(uint)b[o+2] << 16) | (cast(uint)b[o+3] << 24);
}
private ulong  rd64lohi(uint lo, uint hi) { return cast(ulong)lo | (cast(ulong)hi << 32); }

struct Ext4Mount {
    bool  ok;
    int   idx;              // AHCI disk index this filesystem lives on
    uint  blockSize;        // 1024 << s_log_block_size
    uint  inodeSize;        // s_inode_size
    uint  descSize;         // block-group descriptor size (32, or s_desc_size when 64-bit)
    uint  inodesPerGroup;
    uint  firstDataBlock;   // s_first_data_block (0 for >1 KiB blocks, 1 for 1 KiB)
    bool  bit64;
}

private __gshared ubyte[MAX_BLOCK + SECTOR] g_rawTmp;   // module-level scratch (boot is single-threaded)

// Read `n` (<= MAX_BLOCK) bytes at absolute byte offset `off` on disk `idx`, via whole sectors.
private bool readRaw(int idx, ulong off, ubyte* dst, uint n) {
    if (n == 0 || n > MAX_BLOCK) return false;
    alias tmp = g_rawTmp;
    const ulong firstSec = off / SECTOR;
    const ulong lastSec  = (off + n - 1) / SECTOR;
    const uint  nsec     = cast(uint)(lastSec - firstSec + 1);
    if (nsec * SECTOR > tmp.length) return false;
    if (!diskReadSectorsOn(idx, firstSec, nsec, tmp.ptr)) return false;
    const uint within = cast(uint)(off - firstSec * SECTOR);
    foreach (i; 0 .. n) dst[i] = tmp[within + i];
    return true;
}

// Read one filesystem block (its whole contents) into `dst` (must be >= blockSize).
private bool readBlock(const ref Ext4Mount m, ulong blk, ubyte* dst) {
    return diskReadSectorsOn(m.idx, blk * (m.blockSize / SECTOR), m.blockSize / SECTOR, dst);
}

/// Probe disk `idx` for an ext4 superblock and fill a mount; .ok is false when it is not ext4.
Ext4Mount ext4Mount(int idx) {
    Ext4Mount m;
    m.idx = idx;
    ubyte[1024] sb;
    if (!readRaw(idx, 1024, sb.ptr, 1024)) return m;          // superblock at byte 1024
    if (rd16(sb.ptr, 0x38) != EXT4_MAGIC) return m;
    const uint logbs      = rd32(sb.ptr, 0x18);
    if (logbs > 6) return m;                                  // sane block size only
    m.blockSize      = 1024u << logbs;
    m.inodesPerGroup = rd32(sb.ptr, 0x28);
    m.firstDataBlock = rd32(sb.ptr, 0x14);
    const ushort isz = rd16(sb.ptr, 0x58);
    m.inodeSize      = (isz == 0) ? 128 : isz;
    const uint incompat = rd32(sb.ptr, 0x60);
    m.bit64          = (incompat & INCOMPAT_64BIT) != 0;
    const ushort dsz = rd16(sb.ptr, 0xFE);
    m.descSize       = (m.bit64 && dsz >= 32) ? dsz : 32;
    if (m.blockSize == 0 || m.inodesPerGroup == 0) return m;
    m.ok = true;
    return m;
}

// Load inode `ino` (256 bytes max) into `dst`.
private bool readInode(const ref Ext4Mount m, uint ino, ubyte* dst) {
    if (ino == 0) return false;
    const uint group = (ino - 1) / m.inodesPerGroup;
    const uint index = (ino - 1) % m.inodesPerGroup;
    // Block-group descriptor table starts in the block after the superblock.
    const ulong gdtByte = cast(ulong)(m.firstDataBlock + 1) * m.blockSize + cast(ulong)group * m.descSize;
    ubyte[64] gd;
    if (!readRaw(m.idx, gdtByte, gd.ptr, m.descSize < 64 ? m.descSize : 64)) return false;
    ulong itBlock = rd32(gd.ptr, 0x08);
    if (m.bit64 && m.descSize > 32) itBlock = rd64lohi(rd32(gd.ptr, 0x08), rd32(gd.ptr, 0x28));
    const ulong inoByte = itBlock * m.blockSize + cast(ulong)index * m.inodeSize;
    const uint take = m.inodeSize < 256 ? m.inodeSize : 256;
    return readRaw(m.idx, inoByte, dst, take);
}

private ulong inodeSize(const(ubyte)* inode) {
    return rd64lohi(rd32(inode, 0x04), rd32(inode, 0x6C));    // i_size_lo | i_size_high<<32
}

// Map a file's logical block to its physical block by walking the extent tree in `inode`'s i_block.
// Handles depth 0 (leaf extents inline) and deeper trees (one index block per level, bounded).
private ulong mapBlock(const ref Ext4Mount m, const(ubyte)* inode, uint logical) {
    ubyte[MAX_BLOCK] node;
    const(ubyte)* hdr = inode + 0x28;                         // i_block[]
    bool inlineHdr = true;
    for (int depth = 0; depth < 6; ++depth) {
        if (rd16(hdr, 0) != EXT4_EXT_MAGIC) return 0;
        const ushort entries = rd16(hdr, 2);
        const ushort edepth  = rd16(hdr, 6);
        if (edepth == 0) {
            // leaf: ext4_extent entries follow the 12-byte header
            foreach (i; 0 .. entries) {
                const(ubyte)* e = hdr + 12 + i * 12;
                const uint   eeBlock = rd32(e, 0);
                ushort       eeLen   = rd16(e, 4);
                if (eeLen > 32768) eeLen = cast(ushort)(eeLen - 32768);   // uninitialised extent
                const ulong  start   = rd64lohi(rd32(e, 8), rd16(e, 6));
                if (logical >= eeBlock && logical < eeBlock + eeLen)
                    return start + (logical - eeBlock);
            }
            return 0;                                         // a hole
        }
        // interior: pick the last index whose ei_block <= logical, descend
        ulong next = 0;
        for (int i = 0; i < entries; ++i) {
            const(ubyte)* ix = hdr + 12 + i * 12;
            if (rd32(ix, 0) <= logical) next = rd64lohi(rd32(ix, 4), rd16(ix, 8));
        }
        if (next == 0 || !readBlock(m, next, node.ptr)) return 0;
        hdr = node.ptr;
        inlineHdr = false;
    }
    return 0;
}

// Read up to `maxN` bytes of a file (given its loaded inode) into `dst`; returns bytes read.
private uint readFileData(const ref Ext4Mount m, const(ubyte)* inode, ubyte* dst, uint maxN) {
    ulong sz = inodeSize(inode);
    if (sz > maxN) sz = maxN;
    ubyte[MAX_BLOCK] blk;
    uint done = 0;
    uint logical = 0;
    while (done < sz) {
        const ulong phys = mapBlock(m, inode, logical);
        if (phys == 0 || !readBlock(m, phys, blk.ptr)) break;
        uint chunk = m.blockSize;
        if (done + chunk > sz) chunk = cast(uint)(sz - done);
        foreach (i; 0 .. chunk) dst[done + i] = blk[i];
        done += chunk;
        ++logical;
    }
    return done;
}

private bool nameEq(const(ubyte)* a, uint alen, const(char)* b, uint blen) {
    if (alen != blen) return false;
    foreach (i; 0 .. alen) if (a[i] != cast(ubyte)b[i]) return false;
    return true;
}

// Find `name` in directory inode `dirInode`; returns the child inode number, or 0.
private uint dirLookup(const ref Ext4Mount m, const(ubyte)* dirInode, const(char)* name, uint nameLen) {
    const ulong sz = inodeSize(dirInode);
    ubyte[MAX_BLOCK] blk;
    uint logical = 0;
    ulong scanned = 0;
    while (scanned < sz) {
        const ulong phys = mapBlock(m, dirInode, logical);
        if (phys == 0 || !readBlock(m, phys, blk.ptr)) break;
        uint off = 0;
        while (off + 8 <= m.blockSize) {
            const uint   ino    = rd32(blk.ptr, off);
            const ushort recLen = rd16(blk.ptr, off + 4);
            const ubyte  nlen   = blk[off + 6];
            if (recLen < 8) break;
            if (ino != 0 && nameEq(&blk[off + 8], nlen, name, nameLen)) return ino;
            off += recLen;
        }
        ++logical;
        scanned += m.blockSize;
    }
    return 0;
}

/// Resolve an absolute path to its inode number (0 = not found), loading its inode into `inodeOut`.
uint ext4Resolve(const ref Ext4Mount m, const(char)* path, ubyte* inodeOut) {
    if (!m.ok) return 0;
    uint cur = ROOT_INO;
    if (!readInode(m, cur, inodeOut)) return 0;
    uint i = 0;
    if (path[i] == '/') ++i;
    while (path[i] != '\0') {
        uint j = i;
        while (path[j] != '\0' && path[j] != '/') ++j;
        const uint clen = j - i;
        if (clen > 0) {
            const uint child = dirLookup(m, inodeOut, path + i, clen);
            if (child == 0) return 0;
            cur = child;
            if (!readInode(m, cur, inodeOut)) return 0;
        }
        i = j;
        if (path[i] == '/') ++i;
    }
    return cur;
}

/// Read a file by path into `dst` (up to `maxN` bytes); returns bytes read, or -1 if absent.
long ext4ReadFile(const ref Ext4Mount m, const(char)* path, ubyte* dst, uint maxN) {
    ubyte[256] inode;
    const uint ino = ext4Resolve(m, path, inode.ptr);
    if (ino == 0) return -1;
    return readFileData(m, inode.ptr, dst, maxN);
}

// Scan the attached disks for an ext4 filesystem whose root looks like an Android /system or
// /vendor; returns a mounted handle (.ok=false if none).  Android system images are sometimes
// "system-as-root" (build.prop at /), sometimes nested (/system/build.prop) -- accept either.
Ext4Mount ext4FindAndroid(bool wantVendor) {
    Ext4Mount none;
    if (!diskReady()) return none;
    foreach (idx; 0 .. 8) {
        auto m = ext4Mount(idx);
        if (!m.ok) continue;
        ubyte[256] inode;
        const(char)* marker = wantVendor ? "/build.prop\0".ptr : "/build.prop\0".ptr;
        const(char)* marker2 = wantVendor ? "/vendor/build.prop\0".ptr : "/system/build.prop\0".ptr;
        if (ext4Resolve(m, marker, inode.ptr) != 0) return m;
        if (ext4Resolve(m, marker2, inode.ptr) != 0) return m;
        // vendor images carry /etc or /lib64 at the root even without build.prop
        if (ext4Resolve(m, "/bin\0".ptr, inode.ptr) != 0 ||
            ext4Resolve(m, "/lib64\0".ptr, inode.ptr) != 0 ||
            ext4Resolve(m, "/etc\0".ptr, inode.ptr) != 0) return m;
    }
    return none;
}

// Boot self-test: find the Android system image among the attached disks, read a real file out of
// its ext4, and show it -- proving the kernel can read Android's /system without the host.
public void ext4SelfTest() {
    if (!diskReady()) { klog("[ext4] selftest SKIP (no disk)\n"); return; }
    auto m = ext4FindAndroid(false);
    if (!m.ok) { klog("[ext4] selftest SKIP (no Android ext4 image attached)\n"); return; }

    // Read build.prop (root or /system) and confirm it looks like an Android build descriptor.
    ubyte[4096] buf;
    long n = ext4ReadFile(m, "/build.prop\0".ptr, buf.ptr, buf.length);
    if (n <= 0) n = ext4ReadFile(m, "/system/build.prop\0".ptr, buf.ptr, buf.length);
    bool sawRo = false;
    if (n > 4) foreach (i; 0 .. cast(uint)n - 3)
        if (buf[i] == 'r' && buf[i+1] == 'o' && buf[i+2] == '.') { sawRo = true; break; }

    if (n > 0 && sawRo) {
        klog("[ext4] selftest PASS (read Android build.prop from ext4 image on disk "); klog_dec(cast(ulong)m.idx);
        klog(", "); klog_dec(cast(ulong)n); klog(" bytes, block="); klog_dec(m.blockSize);
        klog(m.bit64 ? ", 64-bit)\n" : ")\n");
    } else {
        klog("[ext4] selftest FAIL (ext4 mounted but build.prop unreadable)\n");
    }
}
