module kernel.elf_loader;

pragma(LDC_no_moduleinfo);

import kernel.fs : fs_lookup, Node, NodeType;
import kernel.lib.stdc.stdlib : malloc, free;
import kernel.types : memcpy, memset, strlen; // for memory ops
import kernel.logger : log_message, log_hex;

public:

struct Elf64_Ehdr
{
    ubyte[16] e_ident;
    ushort    e_type;
    ushort    e_machine;
    uint      e_version;
    ulong     e_entry;
    ulong     e_phoff;
    ulong     e_shoff;
    uint      e_flags;
    ushort    e_ehsize;
    ushort    e_phentsize;
    ushort    e_phnum;
    ushort    e_shentsize;
    ushort    e_shnum;
    ushort    e_shstrndx;
}

struct Elf64_Phdr
{
    uint   p_type;
    uint   p_flags;
    ulong  p_offset;
    ulong  p_vaddr;
    ulong  p_paddr;
    ulong  p_filesz;
    ulong  p_memsz;
    ulong  p_align;
}

private struct LoadedSeg
{
    ulong vaddr;
    void* mem;
    ulong memsz;
}

extern(C) int load_elf(const(char)* path, void** entry)
{
    log_message("load_elf called with path=");
    log_hex(cast(ulong)path);
    log_message(" entry=");
    log_hex(cast(ulong)entry);
    log_message("\n");
    
    if(path is null || entry is null) {
        log_message("load_elf: null arguments\n");
        return -1;
    }
    
    // Check if path is readable
    if(cast(ulong)path < 0x1000) {
        log_message("load_elf: invalid path pointer\n");
        return -1;
    }
    
    auto pathLen = strlen(path);
    log_message("load_elf: path='");
    log_message(path);
    log_message("' len=");
    log_hex(pathLen);
    log_message("\n");
    
    auto node = fs_lookup(path);
    if(node is null || node.kind != NodeType.File)
    {
        log_message("load_elf: file not found or not a file\n");
        return -1;
    }
    auto data = node.data;
    auto len = node.size;
    if(len < Elf64_Ehdr.sizeof)
    {
        log_message("load_elf: file too small for ELF header\n");
        return -1;
    }
    auto hdr = cast(const(Elf64_Ehdr)*)data;
    // Minimal ELF validation (0x7F 'E' 'L' 'F')
    if(hdr.e_ident[0] != 0x7F || hdr.e_ident[1] != 'E' || hdr.e_ident[2] != 'L' || hdr.e_ident[3] != 'F')
    {
        log_message("load_elf: invalid ELF magic\n");
        return -1;
    }
    if(hdr.e_phoff + hdr.e_phnum * hdr.e_phentsize > len)
    {
        log_message("load_elf: program headers extend past file\n");
        return -1;
    }

    LoadedSeg[8] segs;
    size_t segCount = 0;
    foreach(i; 0 .. hdr.e_phnum)
    {
        auto ph = cast(const(Elf64_Phdr)*)(data + hdr.e_phoff + i * hdr.e_phentsize);
        if(ph.p_type != 1) // PT_LOAD
            continue;
        if(segCount >= segs.length)
        {
            log_message("load_elf: too many loadable segments\n");
            return -1;
        }
        
        // CRITICAL FIX: Don't write to arbitrary virtual addresses!
        // Instead, allocate memory for the segment
        log_message("load_elf: allocating ");
        log_hex(ph.p_memsz);
        log_message(" bytes for segment at vaddr ");
        log_hex(ph.p_vaddr);
        log_message("\n");
        
        void* dest = malloc(cast(size_t)ph.p_memsz);
        if(dest is null)
        {
            log_message("load_elf: failed to allocate memory for segment\n");
            // Free previously allocated segments
            foreach(j; 0 .. segCount)
                free(segs[j].mem);
            return -1;
        }
        
        memcpy(dest, data + ph.p_offset, cast(size_t)ph.p_filesz);
        if(ph.p_memsz > ph.p_filesz)
            memset(cast(void*)(cast(ubyte*)dest + ph.p_filesz), 0, cast(size_t)(ph.p_memsz - ph.p_filesz));
        segs[segCount++] = LoadedSeg(ph.p_vaddr, dest, ph.p_memsz);
    }

    *entry = cast(void*)hdr.e_entry;
    log_message("load_elf: success, entry point at ");
    log_hex(cast(ulong)*entry);
    log_message("\n");
    return 0;
}

