module core.syscalls.mmap;

import core.io;
import memory.mm;
import arch.x86_64.arch;

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

// Munmap implementation
long sys_munmap(ulong addr, ulong len) {
    if ((addr & 0xFFF) != 0) return -22; // EINVAL
    if (len == 0) return -22;

    ulong PAGE_SIZE = 4096;
    ulong aligned_len = (len + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    ulong num_pages = aligned_len / PAGE_SIZE;

    for (ulong i = 0; i < num_pages; i++) {
        unmap_page_hhdm(addr + (i * PAGE_SIZE));
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

    // Prot flags
    enum PROT_READ = 0x1;
    enum PROT_WRITE = 0x2;
    enum PROT_EXEC = 0x4;
    
    // PTE Flags (must match arch.d)
    enum PTE_PRESENT = 1 << 0;
    enum PTE_RW      = 1 << 1;
    enum PTE_USER    = 1 << 2;
    enum PTE_NX      = 1UL << 63;

    ulong set_mask = PTE_PRESENT | PTE_USER;
    ulong clear_mask = 0;

    if (prot & PROT_WRITE) {
        set_mask |= PTE_RW;
    } else {
        clear_mask |= PTE_RW;
    }

    if (prot & PROT_EXEC) {
        clear_mask |= PTE_NX;
    } else {
        set_mask |= PTE_NX;
    }
    
    // Check for PROT_NONE (no access) -> Clear Present?
    // Linux man page: "The memory is reserved, but cannot be accessed."
    // If we clear PRESENT, it will fault. 
    // But we need to distinguish "not mapped" from "mapped but protected".
    // For now, let's keep it PRESENT but clear RW and maybe User?
    // Existing logic above handles RW/NX.
    // If PROT_NONE (0), it will be Read-Only and NX.
    // Ideally we'd mark it Supervisor only (clear PTE_USER)? 
    // But if we clear PTE_USER, user access faults.
    if (prot == 0) {
        clear_mask |= PTE_USER;
        set_mask &= ~PTE_USER;
    }

    for (ulong i = 0; i < num_pages; i++) {
        protect_page_hhdm(addr + (i * PAGE_SIZE), set_mask, clear_mask);
    }
    
    return 0;
}

