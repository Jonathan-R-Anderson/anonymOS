module drivers.block.nvme;

import drivers.pci;
import userland.shell.console : print, printHex, printLine, printUnsigned;
import memory.dma : dma_alloc;
import memory.physmem : allocFrame, freeFrame;
import core.globals : hhdm_offset;
import core.stdc.string : memset;

@nogc nothrow:

private void* p2v(size_t phys) { return cast(void*)(phys + cast(size_t)hhdm_offset); }
private size_t v2p(void* virt) { return cast(size_t)virt - cast(size_t)hhdm_offset; }

enum NVME_CLASS_CODE    = 0x01;
enum NVME_SUBCLASS_CODE = 0x08;
enum NVME_PROG_IF       = 0x02;

enum NVME_ADMIN_DELETE_IO_SQ = 0x00;
enum NVME_ADMIN_CREATE_IO_SQ = 0x01;
enum NVME_ADMIN_DELETE_IO_CQ = 0x04;
enum NVME_ADMIN_CREATE_IO_CQ = 0x05;
enum NVME_ADMIN_IDENTIFY     = 0x06;

enum NVME_IO_WRITE = 0x01;
enum NVME_IO_READ  = 0x02;
enum NVME_IO_FLUSH = 0x00;

enum NVME_CSTS_RDY = 1u << 0;
enum NVME_CC_EN    = 1u << 0;

enum ADMIN_QID = 0;
enum IO_QID    = 1;

enum ADMIN_Q_DEPTH = 32;
enum IO_Q_DEPTH    = 64;

struct NVMeRegs
{
    ulong cap;      // 0x00
    uint  vs;       // 0x08
    uint  intms;    // 0x0C
    uint  intmc;    // 0x10
    uint  cc;       // 0x14
    uint  rsv0;     // 0x18
    uint  csts;     // 0x1C
    uint  nssr;     // 0x20
    uint  aqa;      // 0x24
    ulong asq;      // 0x28
    ulong acq;      // 0x30
}

struct NVMeCmd
{
    uint  cdw0;
    uint  nsid;
    ulong rsvd2;
    ulong mptr;
    ulong prp1;
    ulong prp2;
    uint  cdw10;
    uint  cdw11;
    uint  cdw12;
    uint  cdw13;
    uint  cdw14;
    uint  cdw15;
}

static assert(NVMeCmd.sizeof == 64);

struct NVMeCpl
{
    uint  result;
    uint  rsvd;
    ushort sqHead;
    ushort sqId;
    ushort cid;
    ushort status;
}

static assert(NVMeCpl.sizeof == 16);

struct NVMeQueue
{
    NVMeCmd* sq;
    NVMeCpl* cq;
    size_t sqPhys;
    size_t cqPhys;
    uint depth;
    uint qid;
    uint sqTail;
    uint cqHead;
    uint phase;
    shared(uint)* sqDoorbell;
    shared(uint)* cqDoorbell;
}

struct NVMeController
{
    NVMeRegs* regs;
    size_t regsPhys;
    uint doorbellStrideBytes;
    uint pageSize;

    NVMeQueue adminQ;
    NVMeQueue ioQ;

    uint namespaceId;
    ulong namespaceBlocks;
    uint blockSize;

    // PRP list for transfers larger than two pages (see nvmeBuildPrps).  One 4 KiB page holds 512
    // entries, which covers a 2 MiB transfer -- past that a real list would have to chain, so
    // maxTransferBytes is capped below that and no chaining is needed.
    ubyte* prpList;
    size_t prpListPhys;
    uint maxTransferBytes;      // min(controller MDTS, what one PRP list page can describe)

    bool present;
    bool ready;
}

__gshared NVMeController g_nvme;

private uint mmioRead32(shared(uint)* p)
{
    return *p;
}

private void mmioWrite32(shared(uint)* p, uint v)
{
    *p = v;
}

private ulong mmioRead64(shared(ulong)* p)
{
    return *p;
}

private void mmioWrite64(shared(ulong)* p, ulong v)
{
    *p = v;
}

private void nvmePause()
{
    asm @nogc nothrow { rep; nop; }
}

private void ringSQ(ref NVMeQueue q)
{
    mmioWrite32(q.sqDoorbell, q.sqTail);
}

private void ringCQ(ref NVMeQueue q)
{
    mmioWrite32(q.cqDoorbell, q.cqHead);
}

private bool waitReady(bool wantReady)
{
    uint timeout = 100000000;

    while (timeout-- != 0)
    {
        bool rdy = (g_nvme.regs.csts & NVME_CSTS_RDY) != 0;
        if (rdy == wantReady)
            return true;

        nvmePause();
    }

    printLine("[nvme] timeout waiting for CSTS.RDY");
    print("[nvme] CSTS=");
    printHex(g_nvme.regs.csts);
    print(" CC=");
    printHex(g_nvme.regs.cc);
    printLine("");
    return false;
}

private void setupDoorbells(ref NVMeQueue q)
{
    size_t base = cast(size_t)g_nvme.regs;
    size_t doorbellBase = base + 0x1000;
    size_t stride = g_nvme.doorbellStrideBytes;

    q.sqDoorbell = cast(shared(uint)*)(doorbellBase + (2 * q.qid) * stride);
    q.cqDoorbell = cast(shared(uint)*)(doorbellBase + (2 * q.qid + 1) * stride);
}

private bool allocQueue(ref NVMeQueue q, uint qid, uint depth)
{
    size_t sqPhys;
    size_t cqPhys;

    auto sq = cast(NVMeCmd*)dma_alloc(NVMeCmd.sizeof * depth, 4096, &sqPhys);
    auto cq = cast(NVMeCpl*)dma_alloc(NVMeCpl.sizeof * depth, 4096, &cqPhys);

    if (sq is null || cq is null)
    {
        printLine("[nvme] failed to allocate queue memory");
        return false;
    }

    memset(sq, 0, NVMeCmd.sizeof * depth);
    memset(cq, 0, NVMeCpl.sizeof * depth);

    q.sq = sq;
    q.cq = cq;
    q.sqPhys = sqPhys;
    q.cqPhys = cqPhys;
    q.depth = depth;
    q.qid = qid;
    q.sqTail = 0;
    q.cqHead = 0;
    q.phase = 1;

    setupDoorbells(q);
    return true;
}

private bool submitCommand(ref NVMeQueue q, ref NVMeCmd cmd, NVMeCpl* outCpl)
{
    ushort cid = cast(ushort)q.sqTail;

    // CDW0 layout: opcode [7:0], fuse [9:8], psdt [15:14], CID [31:16].
    cmd.cdw0 &= 0x0000FFFFu;
    cmd.cdw0 |= cast(uint)cid << 16;

    q.sq[q.sqTail] = cmd;

    q.sqTail++;
    if (q.sqTail >= q.depth)
        q.sqTail = 0;

    ringSQ(q);

    uint timeout = 200000000;

    while (timeout-- != 0)
    {
        auto cpl = &q.cq[q.cqHead];

        uint phase = (cpl.status & 1);
        if (phase == q.phase && cpl.cid == cid)
        {
            if (outCpl !is null)
                *outCpl = *cpl;

            q.cqHead++;
            if (q.cqHead >= q.depth)
            {
                q.cqHead = 0;
                q.phase ^= 1;
            }

            ringCQ(q);

            uint status = (cpl.status >> 1) & 0x7FFF;
            if (status != 0)
            {
                print("[nvme] command failed status=");
                printHex(status);
                print(" sqid=");
                printHex(cpl.sqId);
                print(" cid=");
                printHex(cpl.cid);
                printLine("");
                return false;
            }

            return true;
        }

        nvmePause();
    }

    printLine("[nvme] command timeout");
    print("[nvme] qid=");
    printHex(q.qid);
    print(" sqTail=");
    printHex(q.sqTail);
    print(" cqHead=");
    printHex(q.cqHead);
    print(" phase=");
    printHex(q.phase);
    printLine("");

    return false;
}

private bool adminIdentify(uint nsid, uint cns, size_t bufferPhys)
{
    NVMeCmd cmd = NVMeCmd.init;
    NVMeCpl cpl = NVMeCpl.init;

    cmd.cdw0 = NVME_ADMIN_IDENTIFY;
    cmd.nsid = nsid;
    cmd.prp1 = bufferPhys;
    cmd.cdw10 = cns;

    return submitCommand(g_nvme.adminQ, cmd, &cpl);
}

private bool adminCreateIOCompletionQueue()
{
    NVMeCmd cmd = NVMeCmd.init;
    NVMeCpl cpl = NVMeCpl.init;

    cmd.cdw0 = NVME_ADMIN_CREATE_IO_CQ;
    cmd.prp1 = g_nvme.ioQ.cqPhys;

    cmd.cdw10 =
        (IO_QID & 0xFFFF) |
        ((IO_Q_DEPTH - 1) << 16);

    // PC = physically contiguous, IEN = 0 polling mode.
    cmd.cdw11 = 1;

    return submitCommand(g_nvme.adminQ, cmd, &cpl);
}

private bool adminCreateIOSubmissionQueue()
{
    NVMeCmd cmd = NVMeCmd.init;
    NVMeCpl cpl = NVMeCpl.init;

    cmd.cdw0 = NVME_ADMIN_CREATE_IO_SQ;
    cmd.prp1 = g_nvme.ioQ.sqPhys;

    cmd.cdw10 =
        (IO_QID & 0xFFFF) |
        ((IO_Q_DEPTH - 1) << 16);

    // CQID = IO_QID, PC = physically contiguous, priority = 0.
    cmd.cdw11 =
        (IO_QID & 0xFFFF) |
        (1u << 16);

    return submitCommand(g_nvme.adminQ, cmd, &cpl);
}

private bool identifyNamespace()
{
    size_t phys = 0;
    auto buf = cast(ubyte*)dma_alloc(4096, 4096, &phys);

    if (buf is null)
    {
        printLine("[nvme] failed to allocate identify buffer");
        return false;
    }

    memset(buf, 0, 4096);

    if (!adminIdentify(1, 0, phys))
    {
        printLine("[nvme] Identify Namespace failed");
        return false;
    }

    auto nsze = cast(ulong*)buf;
    g_nvme.namespaceBlocks = nsze[0];

    // FLBAS at byte 26. Low nibble selects active LBA format.
    ubyte flbas = buf[26];
    ubyte lbaFormat = flbas & 0x0F;

    // LBAF table begins at byte 128. Each entry is 4 bytes.
    uint lbafOffset = 128 + cast(uint)lbaFormat * 4;
    ubyte lbads = buf[lbafOffset + 2];

    g_nvme.blockSize = 1u << lbads;
    g_nvme.namespaceId = 1;

    print("[nvme] namespace 1 blocks=");
    printHex(g_nvme.namespaceBlocks);
    print(" blockSize=");
    printUnsigned(cast(size_t)g_nvme.blockSize);
    printLine("");

    if (g_nvme.namespaceBlocks == 0 || g_nvme.blockSize == 0)
    {
        printLine("[nvme] invalid namespace geometry");
        return false;
    }

    return true;
}

private bool identifyController()
{
    size_t phys = 0;
    auto buf = cast(ubyte*)dma_alloc(4096, 4096, &phys);

    if (buf is null)
    {
        printLine("[nvme] failed to allocate controller identify buffer");
        return false;
    }

    memset(buf, 0, 4096);

    if (!adminIdentify(0, 1, phys))
    {
        printLine("[nvme] Identify Controller failed");
        return false;
    }

    print("[nvme] controller identified; serial='");

    foreach (i; 4 .. 24)
    {
        char c = cast(char)buf[i];
        if (c == 0) break;
        char[2] s;
        s[0] = c;
        s[1] = 0;
        print(s[0 .. 1]);
    }

    printLine("'");

    // MDTS (byte 77) is the Maximum Data Transfer Size as a power-of-two multiple of the memory
    // page size (CAP.MPSMIN); 0 means "no limit".  Exceeding it is a command error, so the
    // per-command size below is the smallest of: what the controller allows, what one PRP list
    // page can describe, and the 1 MiB bounce buffer the block layer actually hands us.
    {
        const ubyte mdts = buf[77];
        const uint pageSz = g_nvme.pageSize != 0 ? g_nvme.pageSize : 4096;
        uint limit = PRP_LIST_MAX_BYTES;
        if (mdts != 0 && mdts < 20)
        {
            const ulong ctrlMax = cast(ulong)pageSz << mdts;
            if (ctrlMax < limit) limit = cast(uint)ctrlMax;
        }
        g_nvme.maxTransferBytes = limit;
        print("[nvme] max transfer per command: ");
        printUnsigned(cast(size_t)(limit / 1024));
        printLine(" KiB");
    }

    return true;
}

private bool nvmeControllerResetAndEnable()
{
    ulong cap = g_nvme.regs.cap;

    uint dstrd = cast(uint)((cap >> 32) & 0xF);
    g_nvme.doorbellStrideBytes = 4u << dstrd;

    uint mpsmin = cast(uint)((cap >> 48) & 0xF);
    g_nvme.pageSize = 1u << (12 + mpsmin);

    print("[nvme] CAP=");
    printHex(cap);
    print(" VS=");
    printHex(g_nvme.regs.vs);
    print(" doorbellStride=");
    printUnsigned(cast(size_t)g_nvme.doorbellStrideBytes);
    print(" pageSize=");
    printUnsigned(cast(size_t)g_nvme.pageSize);
    printLine("");

    g_nvme.regs.cc &= ~NVME_CC_EN;

    if (!waitReady(false))
        return false;

    if (!allocQueue(g_nvme.adminQ, ADMIN_QID, ADMIN_Q_DEPTH))
        return false;

    uint aqa =
        ((ADMIN_Q_DEPTH - 1) & 0xFFF) |
        (((ADMIN_Q_DEPTH - 1) & 0xFFF) << 16);

    g_nvme.regs.aqa = aqa;
    g_nvme.regs.asq = g_nvme.adminQ.sqPhys;
    g_nvme.regs.acq = g_nvme.adminQ.cqPhys;

    /*
       CC:
       EN     bit 0
       CSS    bits 6:4 = 000b NVM command set
       MPS    bits 10:7 = 0 for 4 KiB pages, if supported
       AMS    bits 13:11 = 000b round-robin
       SHN    bits 15:14 = 00 no shutdown notification
       IOSQES bits 19:16 = 6  => 64-byte submission entry
       IOCQES bits 23:20 = 4  => 16-byte completion entry
    */
    uint cc = 0;
    cc |= 0u << 4;
    cc |= 0u << 7;
    cc |= 0u << 11;
    cc |= 6u << 16;
    cc |= 4u << 20;
    cc |= NVME_CC_EN;

    g_nvme.regs.cc = cc;

    if (!waitReady(true))
        return false;

    printLine("[nvme] controller ready");
    return true;
}

private bool setupIOQueues()
{
    if (!allocQueue(g_nvme.ioQ, IO_QID, IO_Q_DEPTH))
        return false;

    if (!adminCreateIOCompletionQueue())
    {
        printLine("[nvme] create IO CQ failed");
        return false;
    }

    if (!adminCreateIOSubmissionQueue())
    {
        printLine("[nvme] create IO SQ failed");
        return false;
    }

    printLine("[nvme] IO queues ready");
    return true;
}


// ---------------------------------------------------------------------------
// PRP (Physical Region Page) list.
//
// NVMe describes a transfer with two fields: prp1 is the first page, and prp2 is either the
// SECOND page (transfers of at most two pages) or the physical address of a list of the remaining
// pages.  Until now this driver only ever set prp1, which capped every command at one 4 KiB page
// -- so writing a gigabyte took 262144 separate commands and their completions.  The installer
// hands down a physically contiguous 1 MiB bounce buffer, which is 256 pages: prp1 plus a
// 255-entry list, comfortably inside one 4 KiB list page (512 entries).
//
// PRP rules this relies on: the buffer is page-aligned (dma_alloc is called with alignment 4096),
// so no PRP has a non-zero offset, and every entry after the first must be page-aligned.
private enum uint PRP_PAGE = 4096;
private enum uint PRP_LIST_MAX_BYTES = 2 * 1024 * 1024;   // one list page, no chaining

// Fill in cmd.prp1/prp2 for `bytes` starting at `physAddr`.  Returns false if the transfer needs
// more than this driver's single list page can describe.
private bool nvmeBuildPrps(ref NVMeCmd cmd, size_t physAddr, ulong bytes)
{
    // Two things this list is only correct under, both checked rather than assumed, because the
    // failure mode is not a failed command -- it is the controller DMAing into whatever physical
    // memory the wrong address happens to name, during a disk install, with no error reported.
    //
    //  1. PRP granularity is CC.MPS, programmed to 0 (= 4 KiB) in nvmeControllerResetAndEnable.
    //     That is a different register from the CAP.MPSMIN this driver stores in pageSize, and
    //     nothing but this check couples the two; if CC.MPS is ever raised, every entry below is
    //     off by a factor.
    //  2. Every PRP after the first must be page-aligned, and the first is assumed to have no
    //     offset.  dma_alloc is called with alignment 4096 so that holds -- today.
    if (g_nvme.pageSize != PRP_PAGE)
    {
        printLine("[nvme] controller page size is not 4 KiB; refusing to build a PRP list");
        return false;
    }
    if ((physAddr & (PRP_PAGE - 1)) != 0)
    {
        printLine("[nvme] transfer buffer is not page-aligned; refusing to build a PRP list");
        return false;
    }
    cmd.prp1 = physAddr;
    if (bytes <= PRP_PAGE)
    {
        cmd.prp2 = 0;
        return true;
    }
    if (bytes <= 2 * PRP_PAGE)
    {
        cmd.prp2 = physAddr + PRP_PAGE;
        return true;
    }
    if (g_nvme.prpList is null)
        return false;
    // Pages after the first go in the list, in order.
    const ulong rest = bytes - PRP_PAGE;
    const ulong entries = (rest + PRP_PAGE - 1) / PRP_PAGE;
    if (entries > PRP_PAGE / 8)
        return false;                                  // would need a chained list
    auto list = cast(ulong*)g_nvme.prpList;
    foreach (i; 0 .. cast(size_t)entries)
        list[i] = cast(ulong)physAddr + PRP_PAGE + cast(ulong)i * PRP_PAGE;
    cmd.prp2 = g_nvme.prpListPhys;
    return true;
}

// How many blocks one command may carry.  Callers chunk to this.
public uint nvmeMaxBlocksPerCommand()
{
    if (!g_nvme.ready || g_nvme.blockSize == 0)
        return 8;
    uint bytes = g_nvme.maxTransferBytes != 0 ? g_nvme.maxTransferBytes : PRP_PAGE;
    uint blocks = bytes / g_nvme.blockSize;
    if (blocks == 0) blocks = 1;
    if (blocks > 0xFFFF) blocks = 0xFFFF;              // cdw12 NLB is 16-bit (zero-based)
    return blocks;
}

public bool nvmeReadBlocks(ulong lba, ushort count, size_t physAddr)
{
    if (!g_nvme.ready)
        return false;

    if (count == 0)
        return true;

    NVMeCmd cmd = NVMeCmd.init;
    NVMeCpl cpl = NVMeCpl.init;

    cmd.cdw0 = NVME_IO_READ;
    cmd.nsid = g_nvme.namespaceId;

    ulong bytes = cast(ulong)count * g_nvme.blockSize;

    if (!nvmeBuildPrps(cmd, physAddr, bytes))
    {
        printLine("[nvme] read too large to describe with one PRP list page");
        return false;
    }

    cmd.cdw10 = cast(uint)(lba & 0xFFFFFFFF);
    cmd.cdw11 = cast(uint)(lba >> 32);
    cmd.cdw12 = cast(uint)(count - 1);

    return submitCommand(g_nvme.ioQ, cmd, &cpl);
}

public bool nvmeWriteBlocks(ulong lba, ushort count, size_t physAddr)
{
    if (!g_nvme.ready)
        return false;

    if (count == 0)
        return true;

    NVMeCmd cmd = NVMeCmd.init;
    NVMeCpl cpl = NVMeCpl.init;

    cmd.cdw0 = NVME_IO_WRITE;
    cmd.nsid = g_nvme.namespaceId;

    ulong bytes = cast(ulong)count * g_nvme.blockSize;

    if (!nvmeBuildPrps(cmd, physAddr, bytes))
    {
        printLine("[nvme] write too large to describe with one PRP list page");
        return false;
    }

    cmd.cdw10 = cast(uint)(lba & 0xFFFFFFFF);
    cmd.cdw11 = cast(uint)(lba >> 32);
    cmd.cdw12 = cast(uint)(count - 1);

    return submitCommand(g_nvme.ioQ, cmd, &cpl);
}

public bool nvmeFlush()
{
    if (!g_nvme.ready)
        return false;

    NVMeCmd cmd = NVMeCmd.init;
    NVMeCpl cpl = NVMeCpl.init;

    cmd.cdw0 = NVME_IO_FLUSH;
    cmd.nsid = g_nvme.namespaceId;

    return submitCommand(g_nvme.ioQ, cmd, &cpl);
}

public ulong nvmeCapacityBytes()
{
    if (!g_nvme.ready)
        return 0;

    return g_nvme.namespaceBlocks * cast(ulong)g_nvme.blockSize;
}

public uint nvmeBlockSize()
{
    if (!g_nvme.ready)
        return 0;

    return g_nvme.blockSize;
}

public bool nvmeReady()
{
    return g_nvme.ready;
}

public void initNVMe()
{
    printLine("[nvme] Initializing NVMe...");
    g_nvme = NVMeController.init;

    foreach (bus; 0 .. 256)
    {
        foreach (slot; 0 .. 32)
        {
            foreach (func; 0 .. 8)
            {
                const uint vendorDevice =
                    pciConfigRead32(cast(ubyte)bus,
                                    cast(ubyte)slot,
                                    cast(ubyte)func,
                                    0);

                if ((vendorDevice & 0xFFFF) == 0xFFFF)
                {
                    if (func == 0)
                        break;
                    continue;
                }

                const uint classCode =
                    pciConfigRead32(cast(ubyte)bus,
                                    cast(ubyte)slot,
                                    cast(ubyte)func,
                                    8);

                const ubyte baseClass = cast(ubyte)((classCode >> 24) & 0xFF);
                const ubyte subClass  = cast(ubyte)((classCode >> 16) & 0xFF);
                const ubyte progIf    = cast(ubyte)((classCode >> 8) & 0xFF);

                if (baseClass == 0x01)
                {
                    print("[pci] storage ");
                    printUnsigned(cast(size_t)bus);
                    print(":");
                    printUnsigned(cast(size_t)slot);
                    print(".");
                    printUnsigned(cast(size_t)func);
                    print(" subclass=");
                    printHex(subClass);
                    print(" progIf=");
                    printHex(progIf);
                    printLine("");
                }

                if (baseClass == NVME_CLASS_CODE &&
                    subClass  == NVME_SUBCLASS_CODE &&
                    progIf    == NVME_PROG_IF)
                {
                    print("[nvme] Found controller at ");
                    printUnsigned(cast(size_t)bus);
                    print(":");
                    printUnsigned(cast(size_t)slot);
                    print(".");
                    printUnsigned(cast(size_t)func);
                    printLine("");

                    uint cmd =
                        pciConfigRead32(cast(ubyte)bus,
                                        cast(ubyte)slot,
                                        cast(ubyte)func,
                                        0x04);

                    pciConfigWrite32(cast(ubyte)bus,
                                     cast(ubyte)slot,
                                     cast(ubyte)func,
                                     0x04,
                                     cmd | 0x06);

                    uint bar0 =
                        pciConfigRead32(cast(ubyte)bus,
                                        cast(ubyte)slot,
                                        cast(ubyte)func,
                                        0x10);

                    uint bar1 =
                        pciConfigRead32(cast(ubyte)bus,
                                        cast(ubyte)slot,
                                        cast(ubyte)func,
                                        0x14);

                    ulong barPhys =
                        (cast(ulong)bar0 & 0xFFFFFFF0UL) |
                        (cast(ulong)bar1 << 32);

                    g_nvme.regsPhys = cast(size_t)barPhys;
                    g_nvme.regs = cast(NVMeRegs*)p2v(cast(size_t)barPhys);
                    g_nvme.present = true;

                    print("[nvme] BAR0 phys=0x");
                    printHex(g_nvme.regsPhys);
                    print(" virt=0x");
                    printHex(cast(size_t)g_nvme.regs);
                    printLine("");

                    if (!nvmeControllerResetAndEnable())
                    {
                        printLine("[nvme] controller enable failed");
                        return;
                    }

                    // One page for the PRP list, allocated before Identify so a controller that
                    // reports a large MDTS can actually be used.  Without it every command is
                    // limited to the two pages prp1/prp2 can name directly.
                    g_nvme.prpList = cast(ubyte*)dma_alloc(4096, 4096, &g_nvme.prpListPhys);
                    if (g_nvme.prpList is null)
                        printLine("[nvme] no PRP list page: commands limited to 8 KiB");
                    else
                        memset(g_nvme.prpList, 0, 4096);

                    if (!identifyController())
                        return;

                    if (!identifyNamespace())
                        return;

                    if (!setupIOQueues())
                        return;

                    g_nvme.ready = true;

                    print("[nvme] READY capacity=");
                    printHex(nvmeCapacityBytes());
                    print(" blockSize=");
                    printUnsigned(cast(size_t)g_nvme.blockSize);
                    printLine("");

                    return;
                }
            }
        }
    }

    printLine("[nvme] No NVMe controller found.");
}