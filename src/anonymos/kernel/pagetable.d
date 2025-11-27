module anonymos.kernel.pagetable;

import core.stdc.string : memset;
import anonymos.kernel.physmem : allocFrame;

@nogc nothrow:

extern(C) extern __gshared ulong pml4_table; // defined in boot.s

private enum ulong PAGE_PRESENT = 1UL << 0;
private enum ulong PAGE_WRITABLE = 1UL << 1;
private enum ulong PAGE_USER     = 1UL << 2;
private enum ulong PAGE_PS       = 1UL << 7;
private enum ulong PAGE_NX       = 1UL << 63;

private enum size_t ENTRIES = 512;
private enum size_t PAGE_SIZE = 4096;
private enum size_t HUGE_PAGE_SIZE = 2 * 1024 * 1024;

// User/Kernel split constants
// User space: 0x0000_0000_0000_0000 to 0x0000_7FFF_FFFF_FFFF
// Kernel space: 0xFFFF_8000_0000_0000 to 0xFFFF_FFFF_FFFF_FFFF
private enum ulong USER_MAX_ADDR = 0x0000_7FFF_FFFF_FFFF;
private enum ulong KERNEL_MIN_ADDR = 0xFFFF_8000_0000_0000;
private enum ulong KERNEL_BASE_PHYS_OFFSET = 0xFFFF_8000_0000_0000;

private ulong* pml4()
{
    return &pml4_table;
}

public ulong* physToVirt(ulong phys)
{
    // Access physical memory via the linear map in the upper half
    return cast(ulong*)(phys + KERNEL_BASE_PHYS_OFFSET);
}

// Helper for bootstrap/initialization that uses identity mapping
private ulong* physToVirtIdentity(ulong phys)
{
    return cast(ulong*)phys;
}

private ulong allocPageTable()
{
    auto phys = allocFrame();
    assert(phys != 0, "Out of physical memory for page tables");
    auto v = physToVirt(phys);
    memset(v, 0, PAGE_SIZE);
    return phys;
}

private ulong allocPageTableIdentity()
{
    auto phys = allocFrame();
    assert(phys != 0, "Out of physical memory for page tables");
    auto v = physToVirtIdentity(phys);
    memset(v, 0, PAGE_SIZE);
    return phys;
}

/// Shared mapper for both kernel/global and foreign CR3 roots.
private bool mapPageAt(ulong* root, ulong virt, ulong phys, bool writable, bool executable, bool user, bool invalidateCurrent) @nogc nothrow
{
    assert((virt & (PAGE_SIZE - 1)) == 0, "virt not aligned");
    assert((phys & (PAGE_SIZE - 1)) == 0, "phys not aligned");
    assert(root !is null, "root must be valid");

    // Enforce W^X for user mappings.
    if (user && writable && executable)
    {
        return false;
    }

    // Enforce User/Kernel split
    if (user)
    {
        assert(virt <= USER_MAX_ADDR, "User mapping in kernel space");
    }
    else
    {
        assert(virt >= KERNEL_MIN_ADDR, "Kernel mapping in user space");
    }

    auto pml4eIndex = (virt >> 39) & 0x1FF;
    auto pdpteIndex = (virt >> 30) & 0x1FF;
    auto pdeIndex   = (virt >> 21) & 0x1FF;
    auto pteIndex   = (virt >> 12) & 0x1FF;

    auto pml4v = root;
    
    ulong pdptPhys;
    if ((pml4v[pml4eIndex] & PAGE_PRESENT) == 0)
    {
        pdptPhys = allocPageTable();
        pml4v[pml4eIndex] = pdptPhys | PAGE_PRESENT | PAGE_WRITABLE | (user ? PAGE_USER : 0);
    }
    else
    {
        pdptPhys = pml4v[pml4eIndex] & 0x000FFFFFFFFFF000;
    }

    auto pdpt = physToVirt(pdptPhys);
    ulong pdPhys;
    if ((pdpt[pdpteIndex] & PAGE_PRESENT) == 0)
    {
        pdPhys = allocPageTable();
        pdpt[pdpteIndex] = pdPhys | PAGE_PRESENT | PAGE_WRITABLE | (user ? PAGE_USER : 0);
    }
    else
    {
        pdPhys = pdpt[pdpteIndex] & 0x000FFFFFFFFFF000;
    }

    auto pd = physToVirt(pdPhys);
    ulong ptPhys;
    if ((pd[pdeIndex] & PAGE_PRESENT) == 0)
    {
        ptPhys = allocPageTable();
        pd[pdeIndex] = ptPhys | PAGE_PRESENT | PAGE_WRITABLE | (user ? PAGE_USER : 0);
    }
    else
    {
        // ensure not 2MB page
        assert((pd[pdeIndex] & PAGE_PS) == 0, "Huge page present at target");
        ptPhys = pd[pdeIndex] & 0x000FFFFFFFFFF000;
    }

    auto pt = physToVirt(ptPhys);
    if ((pt[pteIndex] & PAGE_PRESENT) != 0)
    {
        return false; // already mapped
    }

    ulong entry = phys | PAGE_PRESENT;
    if (writable) entry |= PAGE_WRITABLE;
    if (user) entry |= PAGE_USER;
    if (!executable) entry |= PAGE_NX;
    pt[pteIndex] = entry;
    if (invalidateCurrent)
    {
        asm @nogc nothrow { invlpg [virt]; }
    }
    return true;
}

/// Map a 4KiB page at `virt` to physical `phys` with requested permissions.
/// executable=false sets NX. user=true sets U bit.
bool mapPage(ulong virt, ulong phys, bool writable, bool executable, bool user) @nogc nothrow
{
    return mapPageAt(pml4(), virt, phys, writable, executable, user, true);
}

/// Unmap helper used by both kernel and foreign CR3 roots.
private bool unmapPageAt(ulong* root, ulong virt, bool invalidateCurrent)
{
    assert((virt & (PAGE_SIZE - 1)) == 0, "virt not aligned");
    auto pml4eIndex = (virt >> 39) & 0x1FF;
    auto pdpteIndex = (virt >> 30) & 0x1FF;
    auto pdeIndex   = (virt >> 21) & 0x1FF;
    auto pteIndex   = (virt >> 12) & 0x1FF;
    auto pml4v = root;
    if ((pml4v[pml4eIndex] & PAGE_PRESENT) == 0) return false;
    auto pdpt = physToVirt(pml4v[pml4eIndex] & 0x000FFFFFFFFFF000);
    if ((pdpt[pdpteIndex] & PAGE_PRESENT) == 0) return false;
    auto pd = physToVirt(pdpt[pdpteIndex] & 0x000FFFFFFFFFF000);
    if ((pd[pdeIndex] & PAGE_PRESENT) == 0 || (pd[pdeIndex] & PAGE_PS) != 0) return false;
    auto pt = physToVirt(pd[pdeIndex] & 0x000FFFFFFFFFF000);
    if ((pt[pteIndex] & PAGE_PRESENT) == 0) return false;
    pt[pteIndex] = 0;
    if (invalidateCurrent)
    {
        asm @nogc nothrow { invlpg [virt]; }
    }
    return true;
}

/// Map a page into a specific page table (identified by cr3 physical address).
/// Used for setting up user process page tables without switching CR3.
bool mapPageInCr3(ulong cr3, ulong virt, ulong phys, bool writable, bool executable, bool user) @nogc nothrow
{
    assert((cr3 & (PAGE_SIZE - 1)) == 0, "cr3 not aligned");
    return mapPageAt(physToVirt(cr3), virt, phys, writable, executable, user, false);
}

/// Clone only the kernel portion of the PML4 (upper half: entries 256-511).
/// Lower half (entries 0-255) is left clear for user-space mappings.
/// Returns the physical address of the new PML4.
ulong cloneKernelPml4()
{
    auto phys = allocPageTable();
    auto dst = physToVirt(phys);
    auto src = pml4();
    
    // Preserve the bootstrap identity map while we are still executing from
    // low addresses; copy the entire PML4 instead of clearing the user half.
    foreach (i; 0 .. ENTRIES)
    {
        dst[i] = src[i];
    }
    
    return phys;
}

/// Load CR3 with the given physical address.
extern(C) @nogc nothrow void loadCr3(ulong phys)
{
    asm @nogc nothrow
    {
        mov RAX, phys;
        mov CR3, RAX;
    }
}

/// Unmap a 4KiB page; does not free the underlying physical frame.
bool unmapPage(ulong virt)
{
    return unmapPageAt(pml4(), virt, true);
}

/// Unmap a 4KiB page in the specified page table (identified by CR3).
/// Does not free underlying physical memory.
bool unmapPageInCr3(ulong cr3, ulong virt) @nogc nothrow
{
    assert((cr3 & (PAGE_SIZE - 1)) == 0, "cr3 not aligned");
    return unmapPageAt(physToVirt(cr3), virt, false);
}

/// Get current CR3 value.
ulong getCurrentCr3()
{
    ulong result;
    asm @nogc nothrow
    {
        mov RAX, CR3;
        mov result, RAX;
    }
    return result;
}

/// Check if an address is in kernel space (upper half).
bool isKernelAddress(ulong addr) @safe pure nothrow
{
    return addr >= KERNEL_MIN_ADDR;
}

/// Initialize the kernel linear mapping in the upper half.
/// Maps [0 .. maxPhys] to [KERNEL_BASE .. KERNEL_BASE + maxPhys] using 2MB pages.
/// This MUST be called early in boot, before any other upper-half mappings are needed.
void initKernelLinearMapping(ulong maxPhys)
{
    auto pml4v = pml4();
    
    // Align maxPhys to 2MB
    ulong end = (maxPhys + HUGE_PAGE_SIZE - 1) & ~(HUGE_PAGE_SIZE - 1);
    
    for (ulong phys = 0; phys < end; phys += HUGE_PAGE_SIZE)
    {
        ulong virt = KERNEL_BASE_PHYS_OFFSET + phys;
        
        auto pml4eIndex = (virt >> 39) & 0x1FF;
        auto pdpteIndex = (virt >> 30) & 0x1FF;
        auto pdeIndex   = (virt >> 21) & 0x1FF;
        
        // Allocate PDPT if needed (using identity alloc)
        ulong pdptPhys;
        if ((pml4v[pml4eIndex] & PAGE_PRESENT) == 0)
        {
            pdptPhys = allocPageTableIdentity();
            pml4v[pml4eIndex] = pdptPhys | PAGE_PRESENT | PAGE_WRITABLE; // Kernel, RW
        }
        else
        {
            pdptPhys = pml4v[pml4eIndex] & 0x000FFFFFFFFFF000;
        }
        
        auto pdpt = physToVirtIdentity(pdptPhys);
        
        // Allocate PD if needed
        ulong pdPhys;
        if ((pdpt[pdpteIndex] & PAGE_PRESENT) == 0)
        {
            pdPhys = allocPageTableIdentity();
            pdpt[pdpteIndex] = pdPhys | PAGE_PRESENT | PAGE_WRITABLE; // Kernel, RW
        }
        else
        {
            pdPhys = pdpt[pdpteIndex] & 0x000FFFFFFFFFF000;
        }
        
        auto pd = physToVirtIdentity(pdPhys);
        
        // Map 2MB page
        // U=0 (Kernel), RW=1, PS=1 (Huge), NX=1 (No Execute for data)
        // Note: We set NX because this is the linear map (data access).
        
        ulong entry = phys | PAGE_PRESENT | PAGE_WRITABLE | PAGE_PS | PAGE_NX;
        pd[pdeIndex] = entry;
    }
}
