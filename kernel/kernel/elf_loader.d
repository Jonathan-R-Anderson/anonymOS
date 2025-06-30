module kernel.elf_loader;

pragma(LDC_no_moduleinfo);

import kernel.fs : fs_lookup, Node, NodeType;
import kernel.lib.stdc.stdlib : malloc, free;
import kernel.types : memcpy, memset; // for memory ops

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
    auto node = fs_lookup(path);
    if(node is null || node.kind != NodeType.File)
        return -1;
    auto data = node.data;
    auto len = node.size;
    if(len < Elf64_Ehdr.sizeof)
        return -1;
    auto hdr = cast(const(Elf64_Ehdr)*)data;
    // Minimal ELF validation (0x7F 'E' 'L' 'F')
    if(hdr.e_ident[0] != 0x7F || hdr.e_ident[1] != 'E' || hdr.e_ident[2] != 'L' || hdr.e_ident[3] != 'F')
        return -1;
    if(hdr.e_phoff + hdr.e_phnum * hdr.e_phentsize > len)
        return -1;

    LoadedSeg[8] segs;
    size_t segCount = 0;
    foreach(i; 0 .. hdr.e_phnum)
    {
        auto ph = cast(const(Elf64_Phdr)*)(data + hdr.e_phoff + i * hdr.e_phentsize);
        if(ph.p_type != 1) // PT_LOAD
            continue;
        if(segCount >= segs.length)
            return -1;
        void* dest = cast(void*)ph.p_vaddr;
        memcpy(dest, data + ph.p_offset, cast(size_t)ph.p_filesz);
        if(ph.p_memsz > ph.p_filesz)
            memset(cast(void*)(cast(ubyte*)dest + ph.p_filesz), 0, cast(size_t)(ph.p_memsz - ph.p_filesz));
        segs[segCount++] = LoadedSeg(ph.p_vaddr, dest, ph.p_memsz);
    }

    *entry = cast(void*)hdr.e_entry;
    return 0;
}

