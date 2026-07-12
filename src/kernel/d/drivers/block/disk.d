module drivers.block.disk;

import drivers.block.ahci : initAHCI, ahciDataPort, readSector, writeSector,
                            HBA_PORT, g_ahciDevices, getPort;
import drivers.block.nvme : initNVMe, nvmeReady, nvmeReadBlocks, nvmeWriteBlocks,
                            nvmeCapacityBytes, nvmeBlockSize, nvmeFlush;
import memory.dma : dma_alloc;
import core.stdc.string : memcpy, memset;
import core.io : klog, klog_hex;

@nogc nothrow:

enum uint SECTOR = 512;
enum uint BOUNCE_SECTORS = 128;
enum uint BOUNCE_BYTES = BOUNCE_SECTORS * SECTOR;
enum uint NVME_MAX_SECTORS = 8;

enum DiskBackend
{
    none,
    ahci,
    nvme
}

private __gshared DiskBackend g_backend = DiskBackend.none;
private __gshared bool   g_diskReady = false;
private __gshared void*  g_bounceVirt = null;
private __gshared size_t g_bouncePhys = 0;
private __gshared ulong  g_diskSectors = 0;

public bool diskReady() { return g_diskReady; }
public ulong diskSectors() { return g_diskSectors; }

public void diskInit()
{
    g_diskReady = false;
    g_backend = DiskBackend.none;
    g_diskSectors = 0;

    initAHCI();

    auto port = ahciDataPort();

    if (port !is null)
    {
        g_backend = DiskBackend.ahci;

        g_bounceVirt = dma_alloc(BOUNCE_BYTES, 4096, &g_bouncePhys);
        if (g_bounceVirt is null)
        {
            klog("[disk] bounce buffer alloc failed\n");
            return;
        }

        foreach (ref d; g_ahciDevices)
        {
            if (d.present && d.type == 1 && d.capacity != 0)
            {
                g_diskSectors = d.capacity / SECTOR;
                break;
            }
        }

        g_diskReady = true;
        klog("[disk] AHCI SATA data disk ready, sectors=0x");
        klog_hex(g_diskSectors);
        klog("\n");
        return;
    }

    initNVMe();

    if (nvmeReady())
    {
        g_backend = DiskBackend.nvme;

        uint bs = nvmeBlockSize();
        if (bs != SECTOR)
        {
            // The whole disk layer speaks 512-byte LBAs; a 4K-native namespace
            // would silently corrupt LBA math, so refuse it loudly instead.
            klog("[disk] NVMe LBA size unsupported (need 512): 0x");
            klog_hex(bs);
            klog("\n");
            return;
        }

        // NVMe DMA needs PHYSICAL addresses; callers hand us kernel-virtual
        // buffers, so all I/O bounces through this DMA-safe buffer.
        g_bounceVirt = dma_alloc(BOUNCE_BYTES, 4096, &g_bouncePhys);
        if (g_bounceVirt is null)
        {
            klog("[disk] bounce buffer alloc failed\n");
            return;
        }

        g_diskSectors = nvmeCapacityBytes() / SECTOR;

        g_diskReady = true;
        klog("[disk] NVMe disk ready, sectors=0x");
        klog_hex(g_diskSectors);
        klog("\n");
        return;
    }

    klog("[disk] no block device found; object store stays in-memory\n");
}

private bool diskReadAhci(ulong lba, uint count, void* dst)
{
    auto port = ahciDataPort();
    if (port is null || g_bounceVirt is null)
        return false;

    ubyte* out_ = cast(ubyte*)dst;

    while (count > 0)
    {
        const ushort chunk = cast(ushort)(count > BOUNCE_SECTORS ? BOUNCE_SECTORS : count);

        if (!readSector(port, lba, chunk, g_bouncePhys))
            return false;

        memcpy(out_, g_bounceVirt, chunk * SECTOR);

        out_ += chunk * SECTOR;
        lba += chunk;
        count -= chunk;
    }

    return true;
}

private bool diskWriteAhci(ulong lba, uint count, const(void)* src)
{
    auto port = ahciDataPort();
    if (port is null || g_bounceVirt is null)
        return false;

    const(ubyte)* in_ = cast(const(ubyte)*)src;

    while (count > 0)
    {
        const ushort chunk = cast(ushort)(count > BOUNCE_SECTORS ? BOUNCE_SECTORS : count);

        memcpy(g_bounceVirt, in_, chunk * SECTOR);

        if (!writeSector(port, lba, chunk, g_bouncePhys))
            return false;

        in_ += chunk * SECTOR;
        lba += chunk;
        count -= chunk;
    }

    return true;
}

private bool diskReadNvme(ulong lba, uint count, void* dst)
{
    if (g_bounceVirt is null)
        return false;

    ubyte* out_ = cast(ubyte*)dst;

    while (count > 0)
    {
        ushort chunk = cast(ushort)(count > NVME_MAX_SECTORS ? NVME_MAX_SECTORS : count);

        if (!nvmeReadBlocks(lba, chunk, g_bouncePhys))
            return false;

        memcpy(out_, g_bounceVirt, chunk * SECTOR);

        out_ += cast(size_t)chunk * SECTOR;
        lba += chunk;
        count -= chunk;
    }

    return true;
}

private bool diskWriteNvme(ulong lba, uint count, const(void)* src)
{
    if (g_bounceVirt is null)
        return false;

    const(ubyte)* in_ = cast(const(ubyte)*)src;

    while (count > 0)
    {
        ushort chunk = cast(ushort)(count > NVME_MAX_SECTORS ? NVME_MAX_SECTORS : count);

        memcpy(g_bounceVirt, in_, chunk * SECTOR);

        if (!nvmeWriteBlocks(lba, chunk, g_bouncePhys))
            return false;

        in_ += cast(size_t)chunk * SECTOR;
        lba += chunk;
        count -= chunk;
    }

    return true;
}

public bool diskReadSectors(ulong lba, uint count, void* dst)
{
    if (!g_diskReady || count == 0)
        return false;

    final switch (g_backend)
    {
        case DiskBackend.ahci:
            return diskReadAhci(lba, count, dst);

        case DiskBackend.nvme:
            return diskReadNvme(lba, count, dst);

        case DiskBackend.none:
            return false;
    }
}

public bool diskWriteSectors(ulong lba, uint count, const(void)* src)
{
    if (!g_diskReady || count == 0)
        return false;

    final switch (g_backend)
    {
        case DiskBackend.ahci:
            return diskWriteAhci(lba, count, src);

        case DiskBackend.nvme:
            return diskWriteNvme(lba, count, src);

        case DiskBackend.none:
            return false;
    }
}

public int diskFindTarget(out ulong targetSectors)
{
    targetSectors = 0;
    if (!g_diskReady)
        return -1;

    if (g_backend == DiskBackend.nvme)
    {
        targetSectors = g_diskSectors;
        return 0;
    }

    foreach (i; 0 .. cast(int)g_ahciDevices.length)
    {
        auto d = &g_ahciDevices[i];
        if (!d.present || d.type != 1 || d.capacity == 0)
            continue;
        if (getPort(d.port) is ahciDataPort())
            continue;

        targetSectors = d.capacity / SECTOR;
        return i;
    }

    return -1;
}

public int diskFindTargetBySize(ulong maxSectors, out ulong targetSectors)
{
    targetSectors = 0;
    if (!g_diskReady)
        return -1;

    if (g_backend == DiskBackend.nvme)
    {
        if (g_diskSectors <= maxSectors)
        {
            targetSectors = g_diskSectors;
            return 0;
        }

        return -1;
    }

    foreach (i; 0 .. cast(int)g_ahciDevices.length)
    {
        auto d = &g_ahciDevices[i];
        if (!d.present || d.type != 1 || d.capacity == 0)
            continue;
        if (getPort(d.port) is ahciDataPort())
            continue;

        ulong sec = d.capacity / SECTOR;
        if (sec <= maxSectors)
        {
            targetSectors = sec;
            return i;
        }
    }

    return -1;
}

public bool diskIsNvme() { return g_backend == DiskBackend.nvme; }

// Capacity of the disk at install-target index `idx` under the active backend
// (NVMe machines expose exactly one disk at index 0; AHCI machines use the
// g_ahciDevices index).  False if the index names no usable data disk.
public bool diskIndexCapacity(int idx, out ulong sectors)
{
    sectors = 0;
    if (!g_diskReady)
        return false;

    if (g_backend == DiskBackend.nvme)
    {
        if (idx != 0)
            return false;

        sectors = g_diskSectors;
        return true;
    }

    if (idx < 0 || idx >= cast(int)g_ahciDevices.length)
        return false;

    auto d = &g_ahciDevices[idx];
    if (!d.present || d.type != 1 || d.capacity == 0)
        return false;

    sectors = d.capacity / SECTOR;
    return true;
}

public int diskStoreIndex(out ulong sectors)
{
    sectors = 0;
    if (!g_diskReady)
        return -1;

    if (g_backend == DiskBackend.nvme)
    {
        sectors = g_diskSectors;
        return 0;
    }

    foreach (i; 0 .. cast(int)g_ahciDevices.length)
    {
        auto d = &g_ahciDevices[i];
        if (!d.present || d.type != 1 || d.capacity == 0)
            continue;

        if (getPort(d.port) is ahciDataPort())
        {
            sectors = d.capacity / SECTOR;
            return i;
        }
    }

    return -1;
}

public bool diskFirstSectorIsGpt()
{
    if (!g_diskReady)
        return false;

    ubyte[SECTOR] mbr = void;

    if (!diskReadSectors(0, 1, mbr.ptr))
        return false;

    return mbr[510] == 0x55 &&
           mbr[511] == 0xAA &&
           mbr[446 + 4] == 0xEE;
}

public bool diskWriteSectorsOn(int idx, ulong lba, uint count, const(void)* src)
{
    if (!g_diskReady || count == 0)
        return false;

    if (g_backend == DiskBackend.nvme)
    {
        if (idx != 0)
            return false;

        return diskWriteNvme(lba, count, src);
    }

    if (idx < 0 || idx >= cast(int)g_ahciDevices.length)
        return false;

    if (!g_ahciDevices[idx].present)
        return false;

    HBA_PORT* port = getPort(g_ahciDevices[idx].port);
    if (port is null || g_bounceVirt is null)
        return false;

    const(ubyte)* in_ = cast(const(ubyte)*)src;

    while (count > 0)
    {
        const ushort chunk = cast(ushort)(count > BOUNCE_SECTORS ? BOUNCE_SECTORS : count);

        memcpy(g_bounceVirt, in_, chunk * SECTOR);

        if (!writeSector(port, lba, chunk, g_bouncePhys))
            return false;

        in_ += chunk * SECTOR;
        lba += chunk;
        count -= chunk;
    }

    return true;
}

public bool diskReadSectorsOn(int idx, ulong lba, uint count, void* dst)
{
    if (!g_diskReady || count == 0)
        return false;

    if (g_backend == DiskBackend.nvme)
    {
        if (idx != 0)
            return false;

        return diskReadNvme(lba, count, dst);
    }

    if (idx < 0 || idx >= cast(int)g_ahciDevices.length)
        return false;

    if (!g_ahciDevices[idx].present)
        return false;

    HBA_PORT* port = getPort(g_ahciDevices[idx].port);
    if (port is null || g_bounceVirt is null)
        return false;

    ubyte* out_ = cast(ubyte*)dst;

    while (count > 0)
    {
        const ushort chunk = cast(ushort)(count > BOUNCE_SECTORS ? BOUNCE_SECTORS : count);

        if (!readSector(port, lba, chunk, g_bouncePhys))
            return false;

        memcpy(out_, g_bounceVirt, chunk * SECTOR);

        out_ += chunk * SECTOR;
        lba += chunk;
        count -= chunk;
    }

    return true;
}

__gshared ubyte[128 * SECTOR] g_benchBuf;

public void diskWriteBenchOn(int idx, int n, uint chunk)
{
    alias buf = g_benchBuf;

    if (chunk > 128)
        chunk = 128;

    foreach (i; 0 .. chunk * SECTOR)
        buf[i] = cast(ubyte)(i & 0xFF);

    klog("[bench] start idx=0x");
    klog_hex(idx);
    klog(" n=0x");
    klog_hex(n);
    klog(" chunk=0x");
    klog_hex(chunk);
    klog("\n");

    foreach (k; 0 .. n)
    {
        if (!diskWriteSectorsOn(idx, 5000 + cast(ulong)k * chunk, chunk, buf.ptr))
        {
            klog("[bench] write FAIL at k=0x");
            klog_hex(k);
            klog("\n");
            return;
        }

        if ((k % 16) == 0)
        {
            klog("[bench] k=0x");
            klog_hex(k);
            klog("\n");
        }
    }

    klog("[bench] DONE\n");
}

public void diskSelfTest()
{
    if (!g_diskReady)
    {
        klog("[disk] selftest SKIP (no disk)\n");
        return;
    }

    enum ulong SCRATCH_LBA = 2048;

    ubyte[SECTOR] wbuf = void;
    ubyte[SECTOR] rbuf = void;

    foreach (i; 0 .. SECTOR)
        wbuf[i] = cast(ubyte)(i * 31 + 7);

    immutable ubyte[8] mark = ['H','O','S','D','I','S','K','1'];
    foreach (i; 0 .. 8)
        wbuf[i] = mark[i];

    if (!diskWriteSectors(SCRATCH_LBA, 1, wbuf.ptr))
    {
        klog("[disk] selftest FAIL (write)\n");
        return;
    }

    memset(rbuf.ptr, 0, SECTOR);

    if (!diskReadSectors(SCRATCH_LBA, 1, rbuf.ptr))
    {
        klog("[disk] selftest FAIL (read)\n");
        return;
    }

    foreach (i; 0 .. SECTOR)
    {
        if (rbuf[i] != wbuf[i])
        {
            klog("[disk] selftest FAIL (mismatch at 0x");
            klog_hex(i);
            klog(")\n");
            return;
        }
    }

    if (g_backend == DiskBackend.nvme)
        nvmeFlush();

    klog("[disk] selftest PASS (sector round-trip verified)\n");
}