module drivers.block.ahci;

import drivers.pci;
import userland.shell.console : print, printHex, printLine, printUnsigned;
import memory.physmem : allocFrame, freeFrame;
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
    uint dw0;       // Command FIS Length, flags, and PRDTL
    uint prdbc;     // Transferred byte count
    uint ctba;      // Command Table Descriptor Base Address
    uint ctbau;     // Command Table Descriptor Base Address Upper 32 bits
    uint[4] rsv1;   // Reserved
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
    HBA_PRDT_ENTRY[128] prdt_entry; // Physical region descriptor table entries
}

struct SGEntry
{
    size_t phys;
    size_t len;
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

__gshared HBA_MEM* abar;

public struct AHCIDeviceInfo {
    int port;
    int type; // 1=SATA, 4=SATAPI
    ulong capacity;
    bool present;
}

public __gshared AHCIDeviceInfo[32] g_ahciDevices;

public HBA_PORT* getPort(int index) {
    if (abar is null || index < 0 || index >= 32) return null;
    return &abar.ports[index];
}

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

                if (baseClass == AHCI_CLASS_CODE && subClass == AHCI_SUBCLASS_CODE)
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

// MBR Detection
struct MBR {
    ubyte[446] code;
    ubyte[64] partitions;
    ushort signature;
}

public __gshared bool g_mbrDetected = false;
public __gshared bool g_hiddenOsDetected = false;

bool detectMBR(HBA_PORT* port) {
    if (port == null) return false;
    
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
    
    if (valid) {
        printLine("[ahci] Valid MBR detected.");
        g_mbrDetected = true;
        return true;
    }
    return false;
}

bool detectHiddenOS(HBA_PORT* port) {
    if (port == null) return false;
    
    size_t phys = allocFrame();
    if (phys == 0) return false;
    
    if (!readSector(port, 63, 1, phys))
    {
        freeFrame(phys);
        return false;
    }
    
    ubyte* buffer = physToVirt!ubyte(phys);
    
    // Check for "ANONYMOS_HIDDEN" magic string at offset 0
    const(char)* magic = "ANONYMOS_HIDDEN";
    bool found = true;
    for (int i = 0; i < 15; i++) {
        if (buffer[i] != magic[i]) {
            found = false;
            break;
        }
    }
    
    freeFrame(phys);
    
    if (found) {
        printLine("[ahci] Hidden OS detected!");
        g_hiddenOsDetected = true;
        return true;
    }
    return false;
}

void probePorts()
{
    uint pi = abar.pi;
    print("[ahci] Ports Implemented register: "); printHex(pi); printLine("");
    
    for (int i = 0; i < 32; i++)
    {
        if (pi & 1)
        {
            print("[ahci] Checking port "); printUnsigned(i); printLine("");
            int dt = checkType(&abar.ports[i]);
            
            print("[ahci] Port "); printUnsigned(i); 
            print(" type: "); printUnsigned(dt); printLine("");
            
            g_ahciDevices[i].port = i;
            g_ahciDevices[i].type = dt;
            g_ahciDevices[i].present = true;
            
            if (dt == AHCI_DEV_SATA)
            {
                print("[ahci] SATA drive found at port ");
                printUnsigned(i);
                printLine("");
                
                // Configure port (simplified)
                portRebase(&abar.ports[i], i);
                
                // Run detection
                detectMBR(&abar.ports[i]);
                detectHiddenOS(&abar.ports[i]);
                
                g_ahciDevices[i].capacity = getDiskCapacity(&abar.ports[i]);
            }
            else if (dt == AHCI_DEV_SATAPI)
            {
                print("[ahci] SATAPI (CD-ROM) drive found at port ");
                printUnsigned(i);
                printLine("");
                
                // Configure port
                portRebase(&abar.ports[i], i);
                
                g_ahciDevices[i].capacity = 0; // TODO: Get capacity via READ CAPACITY
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

    print("[ahci] checkType: ssts="); printHex(ssts);
    print(" det="); printUnsigned(det);
    print(" ipm="); printUnsigned(ipm);
    print(" sig="); printHex(port.sig);
    printLine("");

    if (det != HBA_PORT_DET_PRESENT) {
        printLine("[ahci] checkType: DET != PRESENT, returning NULL");
        return AHCI_DEV_NULL;
    }
    if (ipm != HBA_PORT_IPM_ACTIVE) {
        printLine("[ahci] checkType: IPM != ACTIVE, returning NULL");
        return AHCI_DEV_NULL;
    }

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
    int timeout = 1000000;
    while (port.cmd & (1 << 15)) 
    {
        timeout--;
        if (timeout == 0)
        {
             printLine("[ahci] Error: startCmd timeout (CR bit stuck)");
             return;
        }
        asm @nogc nothrow { rep; nop; }
    }
    port.cmd |= (1 << 4);
    port.cmd |= (1 << 0);
}

void stopCmd(HBA_PORT* port)
{
    port.cmd &= ~(1 << 0);
    port.cmd &= ~(1 << 4);
    
    int timeout = 1000000;
    while (true)
    {
        if (port.cmd & (1 << 15)) {}
        else if (port.cmd & (1 << 14)) {}
        else break;
        
        timeout--;
        if (timeout == 0)
        {
            printLine("[ahci] Error: stopCmd timeout");
            return;
        }
        asm @nogc nothrow { rep; nop; }
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
    // Timeout to prevent infinite hang
    uint timeout = 1000000;
    while ((port.ci & slotMask) != 0)
    {
        if ((port.is_ & (1u << 30)) != 0) // TFES - Task File Error Status
        {
            printLine("[ahci] Error: Task File Error");
            print("[ahci] TFD: "); printHex(port.tfd);
            print(" SERR: "); printHex(port.serr);
            print(" IS: "); printHex(port.is_);
            printLine("");
            return false;
        }
        
        timeout--;
        if (timeout == 0)
        {
            printLine("[ahci] Error: Command Timeout");
            return false;
        }
        
        asm @nogc nothrow { rep; nop; }
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
    bool res = waitForCommand(port, cast(ubyte)slot);
    if (!res) printLine("[ahci] waitForCommand failed");
    return res;
}

bool executeCommand(HBA_PORT* port, HBA_CMD_HEADER* header, HBA_CMD_TBL* tbl, SGEntry[] sgList, ulong lba, ushort count, bool isWrite, ubyte cmdCode = 0)
{
    // Setup DW0: CFL=5, W (bit 6), PRDTL=sgList.length (bits 16-31)
    uint flags = 5; // CFL = 5 (Host to Device)
    if (isWrite)
        flags |= (1 << 6);
    
    if (sgList.length > 128) return false; // Too many entries
    
    flags |= (cast(uint)sgList.length << 16); // PRDTL
    
    header.dw0 = flags;
    header.prdbc = 0;
    header.ctba = cast(uint)(cast(size_t)tbl);
    header.ctbau = cast(uint)((cast(size_t)tbl) >> 32);

    foreach (i, sg; sgList)
    {
        auto entry = tbl.prdt_entry[i];
        entry.dba = cast(uint)(sg.phys);
        entry.dbau = cast(uint)(sg.phys >> 32);
        entry.dbc = (cast(uint)sg.len - 1) | (1u << 31); // Set Interrupt on Completion for last? Or all? Usually last. But here we set bit 31 (I) for all? No, usually just last.
        // Actually, bit 31 is 'I' (Interrupt on completion). We can set it for the last one.
        // But the AHCI spec says we can set it for any.
        // Let's set it for all for now or just the last one.
        // The original code set it for the single entry.
        tbl.prdt_entry[i] = entry;
    }

    memset(tbl.cfis.ptr, 0, tbl.cfis.length);
    
    ubyte cmd = cmdCode;
    if (cmd == 0) cmd = isWrite ? 0x35 : 0x25;
    
    prepareFIS(tbl, cmd, lba, count);

    return issueTransfer(port, 0);
}

// Overload for single buffer backward compatibility
bool executeCommand(HBA_PORT* port, HBA_CMD_HEADER* header, HBA_CMD_TBL* tbl, size_t physAddr, ulong lba, ushort count, bool isWrite, ubyte cmdCode = 0)
{
    SGEntry[1] sg;
    sg[0].phys = physAddr;
    sg[0].len = count * 512;
    return executeCommand(port, header, tbl, sg[], lba, count, isWrite, cmdCode);
}

bool packetCommand(HBA_PORT* port, HBA_CMD_HEADER* header, HBA_CMD_TBL* tbl, SGEntry[] sgList, ubyte[16] cdb, uint byteCount)
{
    //printLine("[ahci] packetCommand start");
    // Setup DW0: CFL=5, A (Atapi)=1
    uint flags = 5 | (1 << 5); 
    
    if (sgList.length > 128) return false;
    
    header.dw0 = flags | (cast(uint)sgList.length << 16);
    header.prdbc = 0;
    header.ctba = cast(uint)(cast(size_t)tbl);
    header.ctbau = cast(uint)((cast(size_t)tbl) >> 32);

    //printLine("[ahci] packetCommand: PRDT setup");
    foreach (i, sg; sgList)
    {
        auto entry = tbl.prdt_entry[i];
        entry.dba = cast(uint)(sg.phys);
        entry.dbau = cast(uint)(sg.phys >> 32);
        entry.dbc = (cast(uint)sg.len - 1); // | (1u << 31); // Interrupt on completion DISABLED
        tbl.prdt_entry[i] = entry;
    }

    //printLine("[ahci] packetCommand: memset fis");
    if (tbl.cfis.ptr is null) printLine("[ahci] Error: cfis.ptr is null");
    memset(tbl.cfis.ptr, 0, tbl.cfis.length);
    
    // Copy CDB
    //printLine("[ahci] packetCommand: copy CDB");
    for(int i=0; i<16; i++) tbl.acmd[i] = cdb[i];
    
    auto fis = cast(FIS_REG_H2D*)tbl.cfis.ptr;
    fis.fis_type = FIS_TYPE_REG_H2D;
    fis.pmport = 1 << 7;
    fis.command = 0xA0; // PACKET
    fis.featurel = 1;   // DMA
    
    fis.lba1 = cast(ubyte)(byteCount & 0xFF);
    fis.lba2 = cast(ubyte)((byteCount >> 8) & 0xFF);

    //printLine("[ahci] packetCommand: issuing transfer");
    return issueTransfer(port, 0);
}

bool readSector(HBA_PORT* port, ulong lba, ushort count, SGEntry[] sgList)
{
    //printLine("[ahci] readSector start");
    const int idx = portIndex(port);
    if (idx < 0) { printLine("[ahci] Invalid port index"); return false; }
    
    auto ctx = g_portCtx[idx];
    if (ctx.cmdList is null || ctx.cmdTable is null) { printLine("[ahci] Null ctx resources"); return false; }
    
    if (g_ahciDevices[idx].type == AHCI_DEV_SATAPI)
    {
        // Reduce to 1 sector (2KB) to debug data corruption issues.
        // Extremely safe size.
        const ushort CHUNK_SECTORS = 1;
        ushort sectorsRemaining = count;
        ulong currentLba = lba;
        size_t currentBufferPhys = sgList[0].phys; // Assuming single SG entry for ISO reads
        
        while (sectorsRemaining > 0)
        {
            ushort sectorsToRead = (sectorsRemaining > CHUNK_SECTORS) ? CHUNK_SECTORS : sectorsRemaining;
            uint byteCount = sectorsToRead * 2048;
            
            // Temporary SG list for this chunk
            SGEntry[1] chunkSg;
            chunkSg[0].phys = currentBufferPhys;
            chunkSg[0].len = byteCount;
            
            //print("[ahci] Chunk LBA: "); printUnsigned(currentLba);
            //print(" Buffer: "); printHex(cast(size_t)currentBufferPhys);
            //print(" Count: "); printUnsigned(sectorsToRead); printLine("");
            
            // SCSI READ(10) - 0x28
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
            // Retry logic for Unit Attention (0x60) or other transient errors
            for (int i = 0; i < 3; i++)
            {
                if (packetCommand(port, ctx.cmdList, ctx.cmdTable, chunkSg[], cdb, byteCount))
                {
                    chunkSuccess = true;
                    break;
                }
                
                print("[ahci] ATAPI chunk failed. Retry "); printUnsigned(cast(size_t)(i+1)); printLine("...");
                
                uint err = (port.tfd >> 8) & 0xFF;
                if ((err & 0xF0) == 0x60) {
                    printLine("[ahci] Detected Unit Attention.");
                }
                
                stopCmd(port);
                port.serr = 0xFFFFFFFF;
                port.is_ = 0xFFFFFFFF;
                startCmd(port);
            }
            
            if (!chunkSuccess) return false;
            
            sectorsRemaining -= sectorsToRead;
            currentLba += sectorsToRead;
            currentBufferPhys += byteCount;
        }
        
        return true;
    }
    
    return executeCommand(port, ctx.cmdList, ctx.cmdTable, sgList, lba, count, false);
}


bool writeSector(HBA_PORT* port, ulong lba, ushort count, SGEntry[] sgList)
{
    const int idx = portIndex(port);
    if (idx < 0) return false;
    auto ctx = g_portCtx[idx];
    if (ctx.cmdList is null || ctx.cmdTable is null) return false;
    
    if (g_ahciDevices[idx].type == AHCI_DEV_SATAPI) return false; // Write not supported for CD
    
    return executeCommand(port, ctx.cmdList, ctx.cmdTable, sgList, lba, count, true);
}

bool readSector(HBA_PORT* port, ulong lba, ushort count, size_t physAddr)
{
    const int idx = portIndex(port);
    if (idx < 0) return false;
    
    uint sectorSize = (g_ahciDevices[idx].type == AHCI_DEV_SATAPI) ? 2048 : 512;
    
    SGEntry[1] sg;
    sg[0].phys = physAddr;
    sg[0].len = count * sectorSize;
    
    return readSector(port, lba, count, sg[]);
}

bool writeSector(HBA_PORT* port, ulong lba, ushort count, size_t physAddr)
{
    const int idx = portIndex(port);
    if (idx < 0) return false;
    
    uint sectorSize = (g_ahciDevices[idx].type == AHCI_DEV_SATAPI) ? 2048 : 512;
    
    SGEntry[1] sg;
    sg[0].phys = physAddr;
    sg[0].len = count * sectorSize;
    
    return writeSector(port, lba, count, sg[]);
}

bool identifyDevice(HBA_PORT* port, size_t physAddr)
{
    const int idx = portIndex(port);
    if (idx < 0) return false;
    auto ctx = g_portCtx[idx];
    if (ctx.cmdList is null || ctx.cmdTable is null) return false;
    
    // IDENTIFY DEVICE = 0xEC
    // Transfer 1 sector (512 bytes)
    return executeCommand(port, ctx.cmdList, ctx.cmdTable, physAddr, 0, 1, false, 0xEC);
}

ulong getDiskCapacity(HBA_PORT* port)
{
    if (port is null) return 0;
    
    size_t phys = allocFrame();
    if (phys == 0) return 0;
    
    if (!identifyDevice(port, phys))
    {
        freeFrame(phys);
        return 0;
    }
    
    ushort* data = physToVirt!ushort(phys);
    
    // Words 100-103: Max 48-bit LBA
    ulong lba48 = cast(ulong)data[100] |
                  (cast(ulong)data[101] << 16) |
                  (cast(ulong)data[102] << 32) |
                  (cast(ulong)data[103] << 48);
                  
    freeFrame(phys);
    
    return lba48 * 512;
}
