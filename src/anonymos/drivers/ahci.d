module anonymos.drivers.ahci;

import anonymos.drivers.pci;
import anonymos.console : print, printHex, printLine, printUnsigned;
import anonymos.kernel.physmem : allocFrame, freeFrame;
import core.stdc.string : memset;

@nogc nothrow:

// AHCI Constants
enum AHCI_CLASS_CODE = 0x01;
enum AHCI_SUBCLASS_CODE = 0x06;
enum AHCI_PROG_IF = 0x01;

enum HBA_PORT_IPM_ACTIVE = 1;
enum HBA_PORT_DET_PRESENT = 3;

struct HBA_PORT
{
    uint clb;       // 0x00, command list base address, 1K-byte aligned
    uint clbu;      // 0x04, command list base address upper 32 bits
    uint fb;        // 0x08, FIS base address, 256-byte aligned
    uint fbu;       // 0x0C, FIS base address upper 32 bits
    uint is_;       // 0x10, interrupt status
    uint ie;        // 0x14, interrupt enable
    uint cmd;       // 0x18, command and status
    uint rsv0;      // 0x1C, Reserved
    uint tfd;       // 0x20, task file data
    uint sig;       // 0x24, signature
    uint ssts;      // 0x28, SATA status (SCR0:SStatus)
    uint sctl;      // 0x2C, SATA control (SCR2:SControl)
    uint serr;      // 0x30, SATA error (SCR1:SError)
    uint sact;      // 0x34, SATA active (SCR3:SActive)
    uint ci;        // 0x38, command issue
    uint sntf;      // 0x3C, SATA notification (SCR4:SNotification)
    uint fbs;       // 0x40, FIS-based switch control
    uint[11] rsv1;  // 0x44 ~ 0x7F, Reserved
    uint[4] vendor; // 0x80 ~ 0x8F, vendor specific
}

struct HBA_MEM
{
    uint cap;       // 0x00, Host capability
    uint ghc;       // 0x04, Global host control
    uint is_;        // 0x08, Interrupt status
    uint pi;        // 0x0C, Ports implemented
    uint vs;        // 0x10, Version
    uint ccc_ctl;   // 0x14, Command completion coalescing control
    uint ccc_pts;   // 0x18, Command completion coalescing ports
    uint em_loc;    // 0x1C, Enclosure management location
    uint em_ctl;    // 0x20, Enclosure management control
    uint cap2;      // 0x24, Host capabilities extended
    uint bohc;      // 0x28, BIOS/OS handoff control and status
    ubyte[0xA0-0x2C] rsv; // 0x2C - 0x9F, Reserved
    ubyte[0x100-0xA0] vendor; // 0xA0 - 0xFF, Vendor specific
    HBA_PORT[32] ports; // 1 ~ 32
}

struct HBA_CMD_HEADER
{
    uint commandFlags;
    ushort prdtl;
    ushort rsv0;
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
    ubyte[0x40] cfis; // Command FIS
    ubyte[0x10] acmd; // ATAPI command, 12 or 16 bytes
    ubyte[0x30] rsv;  // Reserved
    HBA_PRDT_ENTRY[1] prdt_entry; // Physical region descriptor table entries, 0 ~ 65535
}

struct FIS_REG_H2D
{
    ubyte fis_type;
    ubyte pmport;   // Bits 0-3: port multiplier, bit7: command flag
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

enum FIS_TYPE_REG_H2D = 0x27;

HBA_MEM* abar;

void initAHCI()
{
    printLine("[ahci] Initializing AHCI...");
    
    // Find AHCI controller on PCI bus
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
                const ubyte progIf    = cast(ubyte)((classCode >> 8) & 0xFF);

                if (baseClass == AHCI_CLASS_CODE && subClass == AHCI_SUBCLASS_CODE && progIf == AHCI_PROG_IF)
                {
                    print("[ahci] Found controller at ");
                    printHex(bus); print(":"); printHex(slot); print("."); printHex(func);
                    printLine("");
                    
                    // Get BAR5 (ABAR)
                    uint bar5 = pciConfigRead32(cast(ubyte)bus, cast(ubyte)slot, cast(ubyte)func, 0x24);
                    abar = cast(HBA_MEM*)(cast(ulong)bar5 & 0xFFFFFFF0); // Mask out lower 4 bits
                    
                    print("[ahci] ABAR: 0x"); printHex(cast(size_t)abar); printLine("");
                    
                    probePorts();
                    return;
                }
            }
        }
    }
    printLine("[ahci] No controller found.");
}

void probePorts()
{
    uint pi = abar.pi;
    for (int i = 0; i < 32; i++)
    {
        if (pi & 1)
        {
            int dt = checkType(&abar.ports[i]);
            if (dt == AHCI_DEV_SATA)
            {
                print("[ahci] SATA drive found at port ");
                printUnsigned(i);
                printLine("");
                
                // Configure port (simplified)
                portRebase(&abar.ports[i], i);
            }
        }
        pi >>= 1;
    }
}

enum AHCI_DEV_NULL = 0;
enum AHCI_DEV_SATA = 1;
enum AHCI_DEV_SEMB = 2;
enum AHCI_DEV_PM = 3;
enum AHCI_DEV_SATAPI = 4;

enum SATA_SIG_ATA = 0x00000101;
enum SATA_SIG_ATAPI = 0xEB140101;
enum SATA_SIG_SEMB = 0xC33C0101;
enum SATA_SIG_PM = 0x96690101;

int checkType(HBA_PORT* port)
{
    uint ssts = port.ssts;
    ubyte ipm = (ssts >> 8) & 0x0F;
    ubyte det = ssts & 0x0F;

    if (det != HBA_PORT_DET_PRESENT) return AHCI_DEV_NULL;
    if (ipm != HBA_PORT_IPM_ACTIVE) return AHCI_DEV_NULL;

    switch (port.sig)
    {
        case SATA_SIG_ATAPI: return AHCI_DEV_SATAPI;
        case SATA_SIG_SEMB: return AHCI_DEV_SEMB;
        case SATA_SIG_PM: return AHCI_DEV_PM;
        default: return AHCI_DEV_SATA;
    }
}

struct AHCIPortContext
{
    HBA_PORT* port;
    HBA_CMD_HEADER* cmdList;
    HBA_CMD_TBL* cmdTable;
    ubyte* fis;
}

__gshared AHCIPortContext[32] g_portCtx;

int portIndex(HBA_PORT* port)
{
    foreach (idx, ref ctx; g_portCtx)
    {
        if (ctx.port is port) return cast(int)idx;
    }
    return -1;
}

bool allocatePortResources(HBA_PORT* port, int index)
{
    const size_t kCmdListSize = 1024;
    const size_t kFISSize = 256;
    const size_t kCmdTableSize = 4096;

    const size_t clbPhys = allocFrame();
    const size_t fisPhys = allocFrame();
    const size_t cmdTblPhys = allocFrame();
    if (clbPhys == 0 || fisPhys == 0 || cmdTblPhys == 0)
    {
        return false;
    }

    auto cmdList = cast(HBA_CMD_HEADER*)clbPhys;
    auto fisBase = cast(ubyte*)fisPhys;
    auto cmdTbl = cast(HBA_CMD_TBL*)cmdTblPhys;

    memset(cmdList, 0, kCmdListSize);
    memset(fisBase, 0, kFISSize);
    memset(cmdTbl, 0, kCmdTableSize);

    port.clb = cast(uint)clbPhys;
    port.clbu = cast(uint)(clbPhys >> 32);
    port.fb = cast(uint)fisPhys;
    port.fbu = cast(uint)(fisPhys >> 32);

    g_portCtx[index].port = port;
    g_portCtx[index].cmdList = cmdList;
    g_portCtx[index].cmdTable = cmdTbl;
    g_portCtx[index].fis = fisBase;

    return true;
}

import core.stdc.string : memset;

// Kernel linear map offset
private enum ulong KERNEL_BASE = 0xFFFF_8000_0000_0000;

private T* physToVirt(T)(size_t phys)
{
    return cast(T*)(phys + KERNEL_BASE);
}

void startCmd(HBA_PORT* port)
{
    while (port.cmd & (1 << 15)) {}
    port.cmd |= (1 << 4);
    port.cmd |= (1 << 0);
}

void stopCmd(HBA_PORT* port)
{
    port.cmd &= ~(1 << 0);
    port.cmd &= ~(1 << 4);
    while (true)
    {
        if (port.cmd & (1 << 15)) continue;
        if (port.cmd & (1 << 14)) continue;
        break;
    }
}

void releasePortResources(int index)
{
    auto ctx = g_portCtx[index];
    if (ctx.cmdList !is null) freeFrame(cast(size_t)ctx.cmdList);
    if (ctx.fis !is null) freeFrame(cast(size_t)ctx.fis);
    if (ctx.cmdTable !is null) freeFrame(cast(size_t)ctx.cmdTable);
    g_portCtx[index] = AHCIPortContext.init;
}

__gshared HBA_PORT* g_primaryPort;

void portRebase(HBA_PORT* port, int portNumber)
{
    stopCmd(port);

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
    {
        g_primaryPort = port;
    }

    startCmd(port);
}

bool waitForCommand(HBA_PORT* port, ubyte slot)
{
    const uint slotMask = 1u << slot;
    while ((port.ci & slotMask) != 0)
    {
        if ((port.is_ & (1u << 30)) != 0)
            break;
    }
    return (port.ci & slotMask) == 0;
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
    port.is_ = 0xFFFFFFFF;
    port.ci |= 1u << slot;
    return waitForCommand(port, cast(ubyte)slot);
}

bool executeCommand(HBA_PORT* port, HBA_CMD_HEADER* header, HBA_CMD_TBL* tbl, void* buffer, ulong lba, ushort count, bool isWrite)
{
    enum CMD_FLAG_CFL = 0x1Fu;
    enum CMD_FLAG_WRITE = 1u << 6;

    header.commandFlags = 0;
    header.commandFlags |= 5;
    if (isWrite)
        header.commandFlags |= CMD_FLAG_WRITE;
    header.prdtl = 1;
    header.prdbc = 0;
    header.ctba = cast(uint)(cast(size_t)tbl);
    header.ctbau = cast(uint)((cast(size_t)tbl) >> 32);

    auto entry = tbl.prdt_entry[0];
    entry.dba = cast(uint)(cast(ulong)buffer);
    entry.dbau = cast(uint)((cast(ulong)buffer) >> 32);
    const uint byteCount = cast(uint)(count * 512);
    entry.dbc = (byteCount - 1) | (1u << 31);
    tbl.prdt_entry[0] = entry;

    memset(tbl.cfis.ptr, 0, tbl.cfis.length);
    prepareFIS(tbl, isWrite ? 0x35 : 0x25, lba, count);

    return issueTransfer(port, 0);
}

bool readSector(HBA_PORT* port, ulong lba, ushort count, void* buffer)
{
    const int idx = portIndex(port);
    if (idx < 0) return false;
    auto ctx = g_portCtx[idx];
    if (ctx.cmdList is null || ctx.cmdTable is null) return false;
    return executeCommand(port, ctx.cmdList, ctx.cmdTable, buffer, lba, count, false);
}

bool writeSector(HBA_PORT* port, ulong lba, ushort count, const void* buffer)
{
    const int idx = portIndex(port);
    if (idx < 0) return false;
    auto ctx = g_portCtx[idx];
    if (ctx.cmdList is null || ctx.cmdTable is null) return false;
    return executeCommand(port, ctx.cmdList, ctx.cmdTable, cast(void*)buffer, lba, count, true);
}
