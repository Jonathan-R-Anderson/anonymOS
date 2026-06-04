module core.syscalls.mmap;

import core.io;
import memory.mm;
import arch.x86_64.arch;
import core.hardening : wxProtectMasks; // IR-P8.3: W^X / NX enforcement on protect
import core.cap : g_activeCapTabId;

extern (C):
@nogc nothrow:

// Globals for simple bump allocator
__gshared ulong g_nextMmapAddr = 0x700000000000; // Start at 112TB (arbitrary high address)

// wrapper for alloc_phys_page to match signature expected by map_page_hhdm
ulong alloc_phys_page_wrapper() {
    return alloc_phys_page();
}

long sys_mmap(ulong addr, ulong len, ulong prot, ulong flags, ulong fd, ulong offset) {
    // klog("sys_mmap: addr="); klog_hex(addr);
    // klog(" len="); klog_hex(len);
    // klog(" flags="); klog_hex(flags);
    // klog("\n");

    if (len == 0) return -22; // EINVAL

    ulong PAGE_SIZE = 4096;
    ulong aligned_len = (len + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    ulong num_pages = aligned_len / PAGE_SIZE;

    ulong vaddr;

    // MAP_FIXED = 0x10
    if (flags & 0x10) {
        if ((addr & (PAGE_SIZE - 1)) != 0) return -22; // EINVAL
        if (addr == 0) return -22; // EINVAL (usually not allowed to map at 0)
        vaddr = addr;
    } else {
        // Simple bump allocator
        vaddr = g_nextMmapAddr;
        g_nextMmapAddr += aligned_len;
    }

    // Map the pages
    for (ulong i = 0; i < num_pages; i++) {
        ulong phys = alloc_phys_page();
        if (phys == 0) return -12; // ENOMEM

        // TODO: Handle prot flags (RW, USER, etc.)
        // For now, map everything as Present | RW | User (0x7)
        // map_page_hhdm(phys_target, virt_addr, flags, allocator)
        // flags: bit 0=Present, 1=RW, 2=User
        ulong map_flags = 0x7; 
        
        map_page_hhdm(phys, vaddr + (i * PAGE_SIZE), map_flags, &alloc_phys_page_wrapper);
    }
    
    // Explicitly zero the memory? alloc_phys_page in memory.mm says "Zero the page avoiding SSE"
    // So it should be zeroed already if using HH.

    return cast(long)vaddr;
}

// Munmap implementation.  When `freePages` is set the caller has determined the
// range belongs to an owned (private, alloc_phys_page-backed) region, so each
// unmapped physical frame is returned to the free list for reuse instead of
// leaking.  The caller MUST NOT set freePages for device (g_fb) / shared (memfd)
// maps.
long sys_munmap(ulong addr, ulong len, bool freePages = false) {
    if ((addr & 0xFFF) != 0) return -22; // EINVAL
    if (len == 0) return -22;

    ulong PAGE_SIZE = 4096;
    ulong aligned_len = (len + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    ulong num_pages = aligned_len / PAGE_SIZE;

    for (ulong i = 0; i < num_pages; i++) {
        ulong phys = unmap_page_hhdm(addr + (i * PAGE_SIZE));
        if (freePages && phys != 0)
            free_phys_page(phys);
        else if (phys != 0)
            physPageClearMemOwner(phys);
    }

    return 0;
}

// Mprotect implementation
long sys_mprotect(ulong addr, ulong len, ulong prot) {
    if (len == 0) return -22; // EINVAL
    if ((addr & 0xFFF) != 0) return -22; // EINVAL

    ulong PAGE_SIZE = 4096;
    ulong aligned_len = (len + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    ulong num_pages = aligned_len / PAGE_SIZE;

    // IR-P8.3: W^X / NX policy decides the protection bits.  A request to make a
    // page writable-and-executable comes back writable + NX (exec dropped), so a
    // process can never mprotect a page to W+X; PROT_NONE clears user access.  This
    // is the live W^X enforcement point (the dynamic linker only ever *tightens*
    // permissions here, never to W+X).
    ulong set_mask;
    ulong clear_mask;
    wxProtectMasks(cast(uint)prot, g_activeCapTabId, &set_mask, &clear_mask);

    for (ulong i = 0; i < num_pages; i++) {
        protect_page_hhdm(addr + (i * PAGE_SIZE), set_mask, clear_mask);
    }
    
    return 0;
}
