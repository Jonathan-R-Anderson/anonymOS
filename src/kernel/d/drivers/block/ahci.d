module drivers.block.ahci;

import drivers.pci;
import userland.shell.console : print, printHex, printLine, printUnsigned;
import memory.physmem : allocFrame, freeFrame;
import memory.dma : dma_alloc;
import core.globals : hhdm_offset;
import core.stdc.string : memset;

@nogc nothrow:

private void* p2v(size_t phys) { return cast(void*)(phys + cast(size_t)hhdm_offset); }
private size_t v2p(void* virt) { return cast(size_t)virt - cast(size_t)hhdm_offset; }

enum AHCI_CLASS_CODE = 0x01;
enum AHCI_SUBCLASS_CODE = 0x06;
enum AHCI_PROG_IF = 0x01;

enum HBA_PORT_IPM_ACTIVE = 1;
enum HBA_PORT_DET_PRESENT = 3;

enum AHCI_DEV_NULL   = 0;
enum AHCI_DEV_SATA   = 1;
enum AHCI_DEV_SEMB   = 2;
enum AHCI_DEV_PM     = 3;
enum AHCI_DEV_SATAPI = 4;

enum SATA_SIG_ATA   = 0x00000101;
enum SATA_SIG_ATAPI = 0xEB140101;
enum SATA_SIG_SEMB  = 0xC33C0101;
enum SATA_SIG_PM    = 0x96690101;

enum ATA_CMD_READ_DMA_EXT  = 0x25;
enum ATA_CMD_WRITE_DMA_EXT = 0x35;
enum ATA_CMD_IDENTIFY      = 0xEC;
enum ATA_CMD_PACKET        = 0xA0;

enum ATA_DEV_BUSY = 1u << 7;
enum ATA_DEV_DRQ  = 1u << 3;
enum HBA_PxIS_TFES = 1u << 30;

enum HBA_PxCMD_ST  = 1u << 0;
enum HBA_PxCMD_FRE = 1u << 4;
enum HBA_PxCMD_FR  = 1u << 14;
enum HBA_PxCMD_CR  = 1u << 15;

enum FIS_TYPE_REG_H2D = 0x27;

struct HBA_PORT
{
    uint clb;
    uint clbu;
    uint fb;
    uint fbu;
    uint is_;
    uint ie;
    uint cmd;
    uint rsv0;
    uint tfd;
    uint sig;
    uint ssts;
    uint sctl;
    uint serr;
    uint sact;
    uint ci;
    uint sntf;
    uint fbs;
    uint[11] rsv1;
    uint[4] vendor;
}

struct HBA_MEM
{
    uint cap;
    uint ghc;
    uint is_;
    uint pi;
    uint vs;
    uint ccc_ctl;
    uint ccc_pts;
    uint em_loc;
    uint em_ctl;
    uint cap2;
    uint bohc;
    ubyte[0xA0-0x2C] rsv;
    ubyte[0x100-0xA0] vendor;
    HBA_PORT[32] ports;
}

struct HBA_CMD_HEADER
{
    uint dw0;
    uint prdbc;
    uint ctba;
    uint ctbau;
    uint[4] rsv1;
}

struct HBA_PRDT_ENTRY
{
    uint dba;
    uint dbau;
    uint rsv0;
    uint dbc;
}

struct HBA_CMD_TBL
{
    ubyte[0x40] cfis;
    ubyte[0x10] acmd;
    ubyte[0x30] rsv;
    HBA_PRDT_ENTRY[128] prdt_entry;
}

struct SGEntry
{
    size_t phys;
    size_t len;
}

struct FIS_REG_H2D
{
    ubyte fis_type;
    ubyte pmport;
    ubyte command;
    ubyte featurel;
    ubyte lba0;
    ubyte lba1;
    ubyte lba2;
    ubyte device;
    ubyte lba3;
    ubyte lba4;
    ubyte lba5;
    ubyte featureh;
    ubyte countl;
    ubyte counth;
    ubyte icc;
    ubyte control;
    ubyte[4] rsv1;
}

public struct AHCIDeviceInfo
{
    int port;
    int type;
    ulong capacity;
    bool present;
}

struct MBR
{
    ubyte[446] code;
    ubyte[64] partitions;
    ushort signature;
}

struct AHCIPortContext
{
    HBA_PORT* port;
    HBA_CMD_HEADER* cmdList;
    HBA_CMD_TBL* cmdTables;
    ubyte* fis;
}

__gshared HBA_MEM* abar;
public __gshared AHCIDeviceInfo[32] g_ahciDevices;
public __gshared bool g_mbrDetected = false;
public __gshared bool g_hiddenOsDetected = false;
__gshared AHCIPortContext[32] g_portCtx;
__gshared HBA_PORT* g_primaryPort;
public __gshared HBA_PORT* g_dataPort;

private T* physToVirt(T)(size_t phys)
{
    return cast(T*)(phys + cast(size_t)hhdm_offset);
}

public HBA_PORT* getPort(int index)
{
    if (abar is null || index < 0 || index >= 32) return null;
    return &abar.ports[index];
}

public HBA_PORT* ahciDataPort()
{
    return g_dataPort;
}

private void ahciPause()
{
    asm @nogc nothrow { rep; nop; }
}

private void dumpPortState(HBA_PORT* port, const(char)[] prefix)
{
    print(prefix);
    print(" CI=");   printHex(port.ci);
    print(" SACT="); printHex(port.sact);
    print(" TFD=");  printHex(port.tfd);
    print(" IS=");   printHex(port.is_);
    print(" SERR="); printHex(port.serr);
    print(" CMD=");  printHex(port.cmd);
    printLine("");
}

private bool waitWhileBusy(HBA_PORT* port,
                           uint timeout,
                           const(char)[] where)
{
    while ((port.tfd & (ATA_DEV_BUSY | ATA_DEV_DRQ)) != 0)
    {
        if (--timeout == 0)
        {
            print("[ahci] Error: device busy before command at ");
            printLine(where);
            dumpPortState(port, "[ahci] busy-state:");
            return false;
        }

        ahciPause();
    }

    return true;
}

private int findFreeSlot(HBA_PORT* port)
{
    uint occupied = port.sact | port.ci;

    uint slots = (abar.cap >> 8) & 0x1F;
    slots += 1;
    if (slots == 0 || slots > 32) slots = 32;

    for (int i = 0; i < cast(int)slots; i++)
    {
        if ((occupied & (1u << i)) == 0)
            return i;
    }

    printLine("[ahci] Error: no free command slot");
    dumpPortState(port, "[ahci] no-slot:");
    return -1;
}

void initAHCI()
{
    printLine("[ahci] Initializing AHCI...");

    foreach (bus; 0 .. 256)
    {
        foreach (slot; 0 .. 32)
        {
            foreach (func; 0 .. 8)
            {
                const uint vendorDevice = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, 0);

                if ((vendorDevice & 0xFFFF) == 0xFFFF)
                {
                    if (func == 0) break;
                    continue;
                }

                const uint classCode = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, 8);
                const ubyte baseClass = cast(ubyte)((classCode >> 24) & 0xFF);
                const ubyte subClass  = cast(ubyte)((classCode >> 16) & 0xFF);

                if (baseClass == AHCI_CLASS_CODE && subClass == AHCI_SUBCLASS_CODE)
                {
                    print("[ahci] Found controller at ");
                    printHex(bus); print(":"); printHex(slot); print("."); printHex(func);
                    printLine("");

                    uint cmd = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, 0x04);
                    pciConfigWrite32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, 0x04, cmd | 0x06);

                    uint bar5 = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, 0x24);
                    const size_t abarPhys = cast(size_t)(cast(ulong)bar5 & 0xFFFFFFF0);
                    abar = cast(HBA_MEM*)p2v(abarPhys);

                    print("[ahci] ABAR phys=0x"); printHex(abarPhys);
                    print(" virt=0x"); printHex(cast(size_t)abar);
                    printLine("");

                    abar.ghc |= 1u << 31;

                    probePorts();
                    return;
                }
            }
        }
    }

    printLine("[ahci] No controller found.");
}

bool detectMBR(HBA_PORT* port)
{
    if (port is null) return false;

    size_t phys = allocFrame();
    if (phys == 0) return false;

    if (!readSector(port, 0, 1, phys))
    {
        freeFrame(phys);
        return false;
    }

    MBR* mbr = physToVirt!MBR(phys);
    bool valid = (mbr.signature == 0xAA55);

    freeFrame(phys);

    if (valid)
    {
        printLine("[ahci] Valid MBR detected.");
        g_mbrDetected = true;
        return true;
    }

    return false;
}

bool detectHiddenOS(HBA_PORT* port)
{
    if (port is null) return false;

    size_t phys = allocFrame();
    if (phys == 0) return false;

    if (!readSector(port, 63, 1, phys))
    {
        freeFrame(phys);
        return false;
    }

    ubyte* buffer = physToVirt!ubyte(phys);
    const(char)* magic = "ANONYMOS_HIDDEN";

    bool found = true;
    for (int i = 0; i < 15; i++)
    {
        if (buffer[i] != magic[i])
        {
            found = false;
            break;
        }
    }

    freeFrame(phys);

    if (found)
    {
        printLine("[ahci] Hidden OS detected!");
        g_hiddenOsDetected = true;
        return true;
    }

    return false;
}

void probePorts()
{
    uint pi = abar.pi;
    print("[ahci] Ports Implemented register: ");
    printHex(pi);
    printLine("");

    for (int i = 0; i < 32; i++)
    {
        if (pi & 1)
        {
            print("[ahci] Checking port ");
            printUnsigned(i);
            printLine("");

            int dt = checkType(&abar.ports[i]);

            print("[ahci] Port ");
            printUnsigned(i);
            print(" type: ");
            printUnsigned(dt);
            printLine("");

            g_ahciDevices[i].port = i;
            g_ahciDevices[i].type = dt;
            g_ahciDevices[i].present = (dt != AHCI_DEV_NULL);

            if (dt == AHCI_DEV_SATA)
            {
                print("[ahci] SATA drive found at port ");
                printUnsigned(i);
                printLine("");

                portRebase(&abar.ports[i], i);
                g_ahciDevices[i].capacity = getDiskCapacity(&abar.ports[i]);

                if (g_dataPort is null)
                    g_dataPort = &abar.ports[i];
            }
            else if (dt == AHCI_DEV_SATAPI)
            {
                print("[ahci] SATAPI (CD-ROM) drive found at port ");
                printUnsigned(i);
                printLine("");

                portRebase(&abar.ports[i], i);
                g_ahciDevices[i].capacity = 0;
            }
        }

        pi >>= 1;
    }
}

int checkType(HBA_PORT* port)
{
    uint ssts = port.ssts;
    ubyte ipm = cast(ubyte)((ssts >> 8) & 0x0F);
    ubyte det = cast(ubyte)(ssts & 0x0F);

    print("[ahci] checkType: ssts=");
    printHex(ssts);
    print(" det=");
    printUnsigned(det);
    print(" ipm=");
    printUnsigned(ipm);
    print(" sig=");
    printHex(port.sig);
    printLine("");

    if (det != HBA_PORT_DET_PRESENT)
    {
        printLine("[ahci] checkType: DET != PRESENT, returning NULL");
        return AHCI_DEV_NULL;
    }

    if (ipm != HBA_PORT_IPM_ACTIVE)
    {
        printLine("[ahci] checkType: IPM != ACTIVE, returning NULL");
        return AHCI_DEV_NULL;
    }

    switch (port.sig)
    {
        case SATA_SIG_ATAPI: return AHCI_DEV_SATAPI;
        case SATA_SIG_SEMB:  return AHCI_DEV_SEMB;
        case SATA_SIG_PM:    return AHCI_DEV_PM;
        default:             return AHCI_DEV_SATA;
    }
}

int portIndex(HBA_PORT* port)
{
    foreach (idx, ref ctx; g_portCtx)
    {
        if (ctx.port is port)
            return cast(int)idx;
    }

    return -1;
}

bool allocatePortResources(HBA_PORT* port, int index)
{
    const size_t kCmdListSize = 1024;
    const size_t kFISSize = 256;
    const size_t kCmdTableSize = 4096 * 32;

    size_t clbPhys;
    size_t fisPhys;
    size_t cmdTblPhys;

    auto cmdList = cast(HBA_CMD_HEADER*)dma_alloc(kCmdListSize, 1024, &clbPhys);
    auto fisBase = cast(ubyte*)dma_alloc(kFISSize, 256, &fisPhys);
    auto cmdTbls = cast(HBA_CMD_TBL*)dma_alloc(kCmdTableSize, 128, &cmdTblPhys);

    if (cmdList is null || fisBase is null || cmdTbls is null)
        return false;

    memset(cmdList, 0, kCmdListSize);
    memset(fisBase, 0, kFISSize);
    memset(cmdTbls, 0, kCmdTableSize);

    port.clb = cast(uint)clbPhys;
    port.clbu = cast(uint)(clbPhys >> 32);
    port.fb = cast(uint)fisPhys;
    port.fbu = cast(uint)(fisPhys >> 32);

    for (int i = 0; i < 32; i++)
    {
        size_t tblPhys = cmdTblPhys + cast(size_t)i * 4096;
        cmdList[i].ctba = cast(uint)tblPhys;
        cmdList[i].ctbau = cast(uint)(tblPhys >> 32);
    }

    g_portCtx[index].port = port;
    g_portCtx[index].cmdList = cmdList;
    g_portCtx[index].cmdTables = cmdTbls;
    g_portCtx[index].fis = fisBase;

    return true;
}

void startCmd(HBA_PORT* port)
{
    uint timeout = 1000000;

    while ((port.cmd & HBA_PxCMD_CR) != 0)
    {
        if (--timeout == 0)
        {
            printLine("[ahci] Error: startCmd timeout, CR bit stuck");
            dumpPortState(port, "[ahci] startCmd:");
            return;
        }

        ahciPause();
    }

    port.cmd |= HBA_PxCMD_FRE;
    port.cmd |= HBA_PxCMD_ST;
}

void stopCmd(HBA_PORT* port)
{
    port.cmd &= ~HBA_PxCMD_ST;

    uint timeout = 1000000;
    while ((port.cmd & HBA_PxCMD_CR) != 0)
    {
        if (--timeout == 0)
        {
            printLine("[ahci] Error: stopCmd timeout, CR bit stuck");
            dumpPortState(port, "[ahci] stopCmd CR:");
            break;
        }

        ahciPause();
    }

    port.cmd &= ~HBA_PxCMD_FRE;

    timeout = 1000000;
    while ((port.cmd & HBA_PxCMD_FR) != 0)
    {
        if (--timeout == 0)
        {
            printLine("[ahci] Error: stopCmd timeout, FR bit stuck");
            dumpPortState(port, "[ahci] stopCmd FR:");
            break;
        }

        ahciPause();
    }
}

private void resetPort(HBA_PORT* port)
{
    printLine("[ahci] resetting port after failed command");
    dumpPortState(port, "[ahci] before-reset:");

    stopCmd(port);

    port.is_ = 0xFFFFFFFF;
    port.serr = 0xFFFFFFFF;

    port.sctl = (port.sctl & ~0xFu) | 1u;

    for (uint i = 0; i < 100000; i++)
        ahciPause();

    port.sctl &= ~0xFu;

    for (uint i = 0; i < 100000; i++)
        ahciPause();

    port.is_ = 0xFFFFFFFF;
    port.serr = 0xFFFFFFFF;

    startCmd(port);

    dumpPortState(port, "[ahci] after-reset:");
}

void releasePortResources(int index)
{
    auto ctx = g_portCtx[index];

    /*
       NOTE:
       These were allocated with dma_alloc(), not allocFrame().
       If your DMA allocator has a dma_free(), use that here.
       Do not free HHDM virtual addresses with freeFrame().
    */

    g_portCtx[index] = AHCIPortContext.init;
}

void portRebase(HBA_PORT* port, int portNumber)
{
    stopCmd(port);

    port.is_ = 0xFFFFFFFF;
    port.serr = 0xFFFFFFFF;

    if (!allocatePortResources(port, portNumber))
    {
        print("[ahci] Failed to allocate port resources for ");
        printUnsigned(portNumber);
        printLine("");
        return;
    }

    print("[ahci] Port rebased ");
    printUnsigned(portNumber);
    printLine("");

    if (g_primaryPort is null)
        g_primaryPort = port;

    startCmd(port);
}

bool waitForCommand(HBA_PORT* port, ubyte slot)
{
    const uint slotMask = 1u << slot;

    uint timeout = 100000000;

    while ((port.ci & slotMask) != 0)
    {
        if ((port.is_ & HBA_PxIS_TFES) != 0)
        {
            printLine("[ahci] Error: Task File Error");
            dumpPortState(port, "[ahci] task-file-error:");
            resetPort(port);
            return false;
        }

        if (--timeout == 0)
        {
            printLine("[ahci] Error: Command Timeout");
            dumpPortState(port, "[ahci] timeout:");
            resetPort(port);
            return false;
        }

        ahciPause();
    }

    return true;
}

bool prepareFIS(HBA_CMD_TBL* cmdTbl, ubyte command, ulong lba, ushort count)
{
    auto fis = cast(FIS_REG_H2D*)cmdTbl.cfis.ptr;

    fis.fis_type = FIS_TYPE_REG_H2D;
    fis.pmport = 1 << 7;
    fis.command = command;
    fis.device = 1 << 6;

    fis.lba0 = cast(ubyte)(lba & 0xFF);
    fis.lba1 = cast(ubyte)((lba >> 8) & 0xFF);
    fis.lba2 = cast(ubyte)((lba >> 16) & 0xFF);
    fis.lba3 = cast(ubyte)((lba >> 24) & 0xFF);
    fis.lba4 = cast(ubyte)((lba >> 32) & 0xFF);
    fis.lba5 = cast(ubyte)((lba >> 40) & 0xFF);

    fis.countl = cast(ubyte)(count & 0xFF);
    fis.counth = cast(ubyte)((count >> 8) & 0xFF);

    return true;
}

bool issueTransfer(HBA_PORT* port, uint slot)
{
    if (!waitWhileBusy(port, 10000000, "issueTransfer"))
        return false;

    port.is_ = 0xFFFFFFFF;
    port.serr = 0xFFFFFFFF;

    port.ci = 1u << slot;

    bool res = waitForCommand(port, cast(ubyte)slot);
    if (!res)
        printLine("[ahci] waitForCommand failed");

    return res;
}

bool executeCommand(
    HBA_PORT* port,
    HBA_CMD_HEADER* cmdList,
    HBA_CMD_TBL* cmdTables,
    SGEntry[] sgList,
    ulong lba,
    ushort count,
    bool isWrite,
    ubyte cmdCode = 0)
{
    if (port is null || cmdList is null || cmdTables is null)
        return false;

    if (sgList.length == 0 || sgList.length > 128)
        return false;

    int slot = findFreeSlot(port);
    if (slot < 0)
        return false;

    auto header = &cmdList[slot];
    auto tbl = &cmdTables[slot];

    memset(tbl, 0, HBA_CMD_TBL.sizeof);

    uint flags = 5;
    if (isWrite)
        flags |= 1 << 6;

    flags |= cast(uint)sgList.length << 16;

    const size_t tblPhys = v2p(tbl);

    header.dw0 = flags;
    header.prdbc = 0;
    header.ctba = cast(uint)tblPhys;
    header.ctbau = cast(uint)(tblPhys >> 32);
    header.rsv1[] = 0;

    foreach (i, sg; sgList)
    {
        if (sg.len == 0)
            return false;

        auto entry = HBA_PRDT_ENTRY.init;
        entry.dba = cast(uint)sg.phys;
        entry.dbau = cast(uint)(sg.phys >> 32);
        entry.rsv0 = 0;
        entry.dbc = cast(uint)(sg.len - 1);

        if (i == sgList.length - 1)
            entry.dbc |= 1u << 31;

        tbl.prdt_entry[i] = entry;
    }

    ubyte cmd = cmdCode;
    if (cmd == 0)
        cmd = isWrite ? ATA_CMD_WRITE_DMA_EXT : ATA_CMD_READ_DMA_EXT;

    prepareFIS(tbl, cmd, lba, count);

    return issueTransfer(port, cast(uint)slot);
}

bool executeCommand(
    HBA_PORT* port,
    HBA_CMD_HEADER* cmdList,
    HBA_CMD_TBL* cmdTables,
    size_t physAddr,
    ulong lba,
    ushort count,
    bool isWrite,
    ubyte cmdCode = 0)
{
    SGEntry[1] sg;
    sg[0].phys = physAddr;
    sg[0].len = cast(size_t)count * 512;

    return executeCommand(port, cmdList, cmdTables, sg[], lba, count, isWrite, cmdCode);
}

bool packetCommand(
    HBA_PORT* port,
    HBA_CMD_HEADER* cmdList,
    HBA_CMD_TBL* cmdTables,
    SGEntry[] sgList,
    ubyte[16] cdb,
    uint byteCount)
{
    if (port is null || cmdList is null || cmdTables is null)
        return false;

    if (sgList.length == 0 || sgList.length > 128)
        return false;

    int slot = findFreeSlot(port);
    if (slot < 0)
        return false;

    auto header = &cmdList[slot];
    auto tbl = &cmdTables[slot];

    memset(tbl, 0, HBA_CMD_TBL.sizeof);

    uint flags = 5 | (1 << 5);
    flags |= cast(uint)sgList.length << 16;

    const size_t tblPhys = v2p(tbl);

    header.dw0 = flags;
    header.prdbc = 0;
    header.ctba = cast(uint)tblPhys;
    header.ctbau = cast(uint)(tblPhys >> 32);
    header.rsv1[] = 0;

    foreach (i, sg; sgList)
    {
        if (sg.len == 0)
            return false;

        auto entry = HBA_PRDT_ENTRY.init;
        entry.dba = cast(uint)sg.phys;
        entry.dbau = cast(uint)(sg.phys >> 32);
        entry.rsv0 = 0;
        entry.dbc = cast(uint)(sg.len - 1);

        if (i == sgList.length - 1)
            entry.dbc |= 1u << 31;

        tbl.prdt_entry[i] = entry;
    }

    for (int i = 0; i < 16; i++)
        tbl.acmd[i] = cdb[i];

    auto fis = cast(FIS_REG_H2D*)tbl.cfis.ptr;
    fis.fis_type = FIS_TYPE_REG_H2D;
    fis.pmport = 1 << 7;
    fis.command = ATA_CMD_PACKET;
    fis.featurel = 1;
    fis.lba1 = cast(ubyte)(byteCount & 0xFF);
    fis.lba2 = cast(ubyte)((byteCount >> 8) & 0xFF);

    return issueTransfer(port, cast(uint)slot);
}

bool readSector(HBA_PORT* port, ulong lba, ushort count, SGEntry[] sgList)
{
    const int idx = portIndex(port);
    if (idx < 0)
    {
        printLine("[ahci] Invalid port index");
        return false;
    }

    auto ctx = g_portCtx[idx];

    if (ctx.cmdList is null || ctx.cmdTables is null)
    {
        printLine("[ahci] Null ctx resources");
        return false;
    }

    if (g_ahciDevices[idx].type == AHCI_DEV_SATAPI)
    {
        const ushort CHUNK_SECTORS = 1;
        ushort sectorsRemaining = count;
        ulong currentLba = lba;
        size_t currentBufferPhys = sgList[0].phys;

        while (sectorsRemaining > 0)
        {
            ushort sectorsToRead =
                (sectorsRemaining > CHUNK_SECTORS) ? CHUNK_SECTORS : sectorsRemaining;

            uint byteCount = cast(uint)sectorsToRead * 2048;

            SGEntry[1] chunkSg;
            chunkSg[0].phys = currentBufferPhys;
            chunkSg[0].len = byteCount;

            ubyte[16] cdb;
            cdb[0] = 0x28;
            cdb[1] = 0;
            cdb[2] = cast(ubyte)((currentLba >> 24) & 0xFF);
            cdb[3] = cast(ubyte)((currentLba >> 16) & 0xFF);
            cdb[4] = cast(ubyte)((currentLba >> 8) & 0xFF);
            cdb[5] = cast(ubyte)(currentLba & 0xFF);
            cdb[6] = 0;
            cdb[7] = cast(ubyte)((sectorsToRead >> 8) & 0xFF);
            cdb[8] = cast(ubyte)(sectorsToRead & 0xFF);
            cdb[9] = 0;

            bool chunkSuccess = false;

            for (int i = 0; i < 3; i++)
            {
                if (packetCommand(port, ctx.cmdList, ctx.cmdTables, chunkSg[], cdb, byteCount))
                {
                    chunkSuccess = true;
                    break;
                }

                print("[ahci] ATAPI chunk failed. Retry ");
                printUnsigned(cast(size_t)(i + 1));
                printLine("...");

                resetPort(port);
            }

            if (!chunkSuccess)
                return false;

            sectorsRemaining -= sectorsToRead;
            currentLba += sectorsToRead;
            currentBufferPhys += byteCount;
        }

        return true;
    }

    return executeCommand(port, ctx.cmdList, ctx.cmdTables, sgList, lba, count, false);
}

bool writeSector(HBA_PORT* port, ulong lba, ushort count, SGEntry[] sgList)
{
    const int idx = portIndex(port);
    if (idx < 0)
        return false;

    auto ctx = g_portCtx[idx];

    if (ctx.cmdList is null || ctx.cmdTables is null)
        return false;

    if (g_ahciDevices[idx].type == AHCI_DEV_SATAPI)
        return false;

    return executeCommand(port, ctx.cmdList, ctx.cmdTables, sgList, lba, count, true);
}

bool readSector(HBA_PORT* port, ulong lba, ushort count, size_t physAddr)
{
    const int idx = portIndex(port);
    if (idx < 0)
        return false;

    uint sectorSize = (g_ahciDevices[idx].type == AHCI_DEV_SATAPI) ? 2048 : 512;

    SGEntry[1] sg;
    sg[0].phys = physAddr;
    sg[0].len = cast(size_t)count * sectorSize;

    return readSector(port, lba, count, sg[]);
}

bool writeSector(HBA_PORT* port, ulong lba, ushort count, size_t physAddr)
{
    const int idx = portIndex(port);
    if (idx < 0)
        return false;

    uint sectorSize = (g_ahciDevices[idx].type == AHCI_DEV_SATAPI) ? 2048 : 512;

    SGEntry[1] sg;
    sg[0].phys = physAddr;
    sg[0].len = cast(size_t)count * sectorSize;

    return writeSector(port, lba, count, sg[]);
}

bool identifyDevice(HBA_PORT* port, size_t physAddr)
{
    const int idx = portIndex(port);
    if (idx < 0)
        return false;

    auto ctx = g_portCtx[idx];

    if (ctx.cmdList is null || ctx.cmdTables is null)
        return false;

    return executeCommand(
        port,
        ctx.cmdList,
        ctx.cmdTables,
        physAddr,
        0,
        1,
        false,
        ATA_CMD_IDENTIFY
    );
}

ulong getDiskCapacity(HBA_PORT* port)
{
    if (port is null)
        return 0;

    size_t phys = allocFrame();
    if (phys == 0)
        return 0;

    if (!identifyDevice(port, phys))
    {
        freeFrame(phys);
        return 0;
    }

    ushort* data = physToVirt!ushort(phys);

    ulong lba48 =
        cast(ulong)data[100] |
        (cast(ulong)data[101] << 16) |
        (cast(ulong)data[102] << 32) |
        (cast(ulong)data[103] << 48);

    freeFrame(phys);

    return lba48 * 512;
}