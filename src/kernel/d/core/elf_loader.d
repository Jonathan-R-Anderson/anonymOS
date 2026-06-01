module core.elf_loader;

import core.task;
import core.io;
import core.globals;
import memory.mm;
import arch.x86_64.arch;

extern (C) @nogc nothrow:

enum PT_LOAD   = 1;
enum PT_INTERP = 3;

// e_type values
enum ET_EXEC = 2;
enum ET_DYN  = 3;

// Flags in p_flags
enum PF_X = 1;
enum PF_W = 2;
enum PF_R = 4;

struct ElfLoadResult {
    bool   ok;
    ulong  entry;     // virtual entry point (loadBias + e_entry)
    ulong  topVirt;   // highest mapped virtual address (brk base)
    ulong  phdrVaddr; // in-memory virtual address of the program header table
    ushort phEnt;     // e_phentsize
    ushort phNum;     // e_phnum
    bool   hasInterp; // a PT_INTERP segment was present (dynamic executable)
    bool   isDyn;     // e_type == ET_DYN (PIE / shared object)
}

// Parse an ELF64 binary that is already mapped at elfVirtBase (in the currently
// active page table, via HHDM using elfPhysBase).  Allocates physical pages,
// copies ELF content into them, and maps them into the current CR3.
// All physical pages are eagerly allocated so no COW machinery is needed.
//
// loadBias is added to every p_vaddr — 0 for a fixed-address ET_EXEC, or a
// chosen base for an ET_DYN (PIE main exe / the ld.so interpreter).  When
// interpOut is non-null and a PT_INTERP segment is found, the interpreter path
// string is copied into it (NUL-terminated, capped at interpCap).
ElfLoadResult loadElf(ref Task task, ulong elfVirtBase, ulong elfPhysBase,
                      ulong loadBias = 0, char* interpOut = null, size_t interpCap = 0) {
    ElfLoadResult r;
    r.ok = false;

    if (interpOut !is null && interpCap > 0) interpOut[0] = 0;

    // Validate magic
    auto hdr = cast(ubyte*)elfVirtBase;
    if (hdr[0] != 0x7f || hdr[1] != 'E' || hdr[2] != 'L' || hdr[3] != 'F') {
        klog("[elf] bad magic\n");
        return r;
    }
    // EI_CLASS must be 2 (64-bit)
    if (hdr[4] != 2) {
        klog("[elf] not ELF64\n");
        return r;
    }

    ushort e_type     = *cast(ushort*)(elfVirtBase + 16);
    ulong e_entry     = *cast(ulong*)(elfVirtBase + 24);
    ulong e_phoff     = *cast(ulong*)(elfVirtBase + 32);
    ushort e_phentsize= *cast(ushort*)(elfVirtBase + 54);
    ushort e_phnum    = *cast(ushort*)(elfVirtBase + 56);

    r.isDyn = (e_type == ET_DYN);
    r.phEnt = e_phentsize;
    r.phNum = e_phnum;

    klog("[elf] type="); klog_hex(e_type);
    klog(" entry="); klog_hex(e_entry);
    klog(" bias="); klog_hex(loadBias);
    klog(" phnum="); klog_hex(e_phnum);
    klog("\n");

    ulong topVirt   = 0;
    ulong phdrVaddr = 0;

    for (uint i = 0; i < e_phnum; i++) {
        ulong ph = elfVirtBase + e_phoff + cast(ulong)(i) * e_phentsize;

        uint  p_type   = *cast(uint *)(ph + 0);
        uint  p_flags  = *cast(uint *)(ph + 4);
        ulong p_offset = *cast(ulong*)(ph + 8);
        ulong p_vaddr0 = *cast(ulong*)(ph + 16);
        ulong p_filesz = *cast(ulong*)(ph + 32);
        ulong p_memsz  = *cast(ulong*)(ph + 40);

        // Record the interpreter path (PT_INTERP) for the caller.
        if (p_type == PT_INTERP) {
            r.hasInterp = true;
            if (interpOut !is null && interpCap > 0) {
                size_t n = cast(size_t)p_filesz;
                if (n > interpCap - 1) n = interpCap - 1;
                auto src = cast(const(char)*)(elfVirtBase + p_offset);
                size_t k = 0;
                while (k < n && src[k] != 0) { interpOut[k] = src[k]; ++k; }
                interpOut[k] = 0;
            }
            continue;
        }

        if (p_type != PT_LOAD || p_memsz == 0) continue;

        ulong p_vaddr = p_vaddr0 + loadBias;

        // The program header table lives inside whichever PT_LOAD covers e_phoff.
        if (phdrVaddr == 0 && p_offset <= e_phoff &&
            e_phoff < p_offset + p_filesz) {
            phdrVaddr = p_vaddr + (e_phoff - p_offset);
        }

        RegionPerms perms = (p_flags & PF_W)
            ? RegionPerms.ReadWrite
            : RegionPerms.ReadOnly;

        ulong alignedStart = p_vaddr & ~0xFFFUL;
        ulong alignedEnd   = (p_vaddr + p_memsz + 0xFFF) & ~0xFFFUL;
        ulong fileEnd      = (p_vaddr + p_filesz + 0xFFF) & ~0xFFFUL;

        klog("[elf] LOAD va="); klog_hex(p_vaddr);
        klog(" memsz="); klog_hex(p_memsz);
        klog(" filesz="); klog_hex(p_filesz);
        klog("\n");

        // Map file-backed pages: copy bytes from the ELF image
        for (ulong vpage = alignedStart; vpage < fileEnd; vpage += 4096) {
            ulong newPhys = alloc_phys_page();
            if (newPhys == 0) {
                klog("[elf] OOM at file page\n");
                return r;
            }

            // Offset within this page in the file
            ulong pageStart = vpage;                 // virtual
            ulong intoFile  = p_offset + (pageStart > p_vaddr ? pageStart - p_vaddr : 0);
            // If vaddr is not page-aligned, the first partial page has a leading zero gap
            ulong leadZeros = (p_vaddr > pageStart) ? p_vaddr - pageStart : 0;

            auto dst = cast(ubyte*)(newPhys + hhdm_offset);
            // Zero leading bytes (before p_vaddr within first page)
            for (ulong z = 0; z < leadZeros && z < 4096; z++)
                dst[z] = 0;

            // Copy file bytes
            ulong copyStart = leadZeros;
            ulong copyEnd   = 4096;
            // Don't copy past end of file data
            ulong fileDataEnd = p_offset + p_filesz;
            for (ulong b = copyStart; b < copyEnd; b++) {
                ulong fileIdx = intoFile + (b - copyStart);
                if (fileIdx < fileDataEnd)
                    dst[b] = *cast(ubyte*)(elfVirtBase + fileIdx);
                else
                    dst[b] = 0; // trailing BSS within a partially-file-backed page
            }

            ulong flags = PTE_PRESENT | PTE_USER;
            if (perms == RegionPerms.ReadWrite) flags |= PTE_RW;
            map_page_hhdm(newPhys, vpage, flags, &alloc_phys_page);
        }

        // Map BSS pages: demand-zero (already zeroed by alloc_phys_page)
        for (ulong vpage = fileEnd; vpage < alignedEnd; vpage += 4096) {
            ulong newPhys = alloc_phys_page();
            if (newPhys == 0) {
                klog("[elf] OOM at BSS page\n");
                return r;
            }
            ulong flags = PTE_PRESENT | PTE_USER;
            if (perms == RegionPerms.ReadWrite) flags |= PTE_RW;
            map_page_hhdm(newPhys, vpage, flags, &alloc_phys_page);
        }

        // Record region for fault handling
        addRegion(task, alignedStart, alignedEnd, RegionType.Mapped, perms, 0);

        if (alignedEnd > topVirt) topVirt = alignedEnd;
    }

    // Fall back to a simple estimate if the phdrs weren't inside a PT_LOAD.
    if (phdrVaddr == 0) phdrVaddr = loadBias + e_phoff;

    r.ok        = true;
    r.entry     = e_entry + loadBias;
    r.topVirt   = topVirt;
    r.phdrVaddr = phdrVaddr;
    return r;
}
