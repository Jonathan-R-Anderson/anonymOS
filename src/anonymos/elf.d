module anonymos.elf;

static if (!__traits(compiles, { size_t dummy; }))
{
    alias size_t = typeof(int.sizeof);
}

private enum pageSize = 4096;

// ELF64 Header
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

// ELF64 Program Header
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

// ELF64 Section Header
struct Elf64_Shdr
{
    uint   sh_name;
    uint   sh_type;
    ulong  sh_flags;
    ulong  sh_addr;
    ulong  sh_offset;
    ulong  sh_size;
    uint   sh_link;
    uint   sh_info;
    ulong  sh_addralign;
    ulong  sh_entsize;
}

enum EI_MAG0       = 0;
enum EI_MAG1       = 1;
enum EI_MAG2       = 2;
enum EI_MAG3       = 3;
enum EI_CLASS      = 4;
enum EI_DATA       = 5;
enum EI_VERSION    = 6;
enum EI_OSABI      = 7;
enum EI_ABIVERSION = 8;

enum ELFMAG0       = 0x7f;
enum ELFMAG1       = 'E';
enum ELFMAG2       = 'L';
enum ELFMAG3       = 'F';

enum ELFCLASS64    = 2;
enum ELFDATA2LSB   = 1;
enum EV_CURRENT    = 1;
enum EM_X86_64     = 62;

enum PT_LOAD       = 1;

enum PF_X          = 0x1;
enum PF_W          = 0x2;
enum PF_R          = 0x4;

import anonymos.console : printLine, printHex;
import anonymos.kernel.memory : memcpy, memset;
import anonymos.kernel.vm_map : VMMap;

@nogc nothrow bool validateElfHeader(const(Elf64_Ehdr)* hdr)
{
    if (hdr.e_ident[EI_MAG0] != ELFMAG0 ||
        hdr.e_ident[EI_MAG1] != ELFMAG1 ||
        hdr.e_ident[EI_MAG2] != ELFMAG2 ||
        hdr.e_ident[EI_MAG3] != ELFMAG3)
    {
        printLine("[elf] Invalid magic bytes");
        return false;
    }

    if (hdr.e_ident[EI_CLASS] != ELFCLASS64)
    {
        printLine("[elf] Not a 64-bit ELF");
        return false;
    }

    if (hdr.e_ident[EI_DATA] != ELFDATA2LSB)
    {
        printLine("[elf] Not little-endian");
        return false;
    }

    if (hdr.e_machine != EM_X86_64)
    {
        printLine("[elf] Not x86_64");
        return false;
    }

    return true;
}

struct ElfLoaderContext
{
    const(ubyte)[] fileData;
    ulong entryPoint;
    bool loaded;
}

@nogc nothrow bool loadElf(const(ubyte)[] fileData, out ElfLoaderContext context)
{
    if (fileData.length < Elf64_Ehdr.sizeof)
    {
        printLine("[elf] File too small");
        return false;
    }

    const(Elf64_Ehdr)* hdr = cast(const(Elf64_Ehdr)*)fileData.ptr;

    if (!validateElfHeader(hdr))
    {
        return false;
    }

    context.fileData = fileData;
    context.entryPoint = hdr.e_entry;
    if (context.entryPoint & 0xFFFF_8000_0000_0000)
    {
        printLine("[elf] Entry point in kernel space");
        return 0;
    }

    const(Elf64_Phdr)* phdr = cast(const(Elf64_Phdr)*)(fileData.ptr + hdr.e_phoff);

    for (int i = 0; i < hdr.e_phnum; ++i)
    {
        if (phdr[i].p_type == PT_LOAD)
        {
            void* dest = cast(void*)phdr[i].p_vaddr;
            const(void)* src = cast(const(void)*)(fileData.ptr + phdr[i].p_offset);
            size_t filesz = cast(size_t)phdr[i].p_filesz;
            size_t memsz = cast(size_t)phdr[i].p_memsz;

            // Basic safety check
            if (phdr[i].p_vaddr < 0x200000) // Avoid first 2MB (kernel usually at 1MB)
            {
                 printLine("[elf] Warning: Segment below 2MB.");
            }

            memcpy(dest, src, filesz);
            if (memsz > filesz)
            {
                memset(dest + filesz, 0, memsz - filesz);
            }
        }
    }

    context.loaded = true;
    return true;
}

/// Load an ELF binary into user-space page tables.
/// Maps segments with proper permissions (R, W, X) into the lower half.
/// Optionally records mappings in `vm` for later teardown.
/// `slide` offsets all segment/entry addresses (page aligned).
/// Returns entry point on success, 0 on failure.
@nogc nothrow ulong loadElfUser(const(ubyte)[] fileData, ulong cr3, VMMap* vm = null, ulong slide = 0)
{
    if (fileData.length < Elf64_Ehdr.sizeof)
    {
        printLine("[elf] File too small");
        return 0;
    }

    const(Elf64_Ehdr)* hdr = cast(const(Elf64_Ehdr)*)fileData.ptr;

    if (!validateElfHeader(hdr))
    {
        return 0;
    }

    // Ensure entry point is in user space (lower half)
    if (hdr.e_entry & 0xFFFF_8000_0000_0000)
    {
        printLine("[elf] Entry point in kernel space");
        return 0;
    }

    const(Elf64_Phdr)* phdr = cast(const(Elf64_Phdr)*)(fileData.ptr + hdr.e_phoff);

    for (int i = 0; i < hdr.e_phnum; ++i)
    {
        if (phdr[i].p_type == PT_LOAD)
        {
            ulong vaddr = phdr[i].p_vaddr + slide;
            ulong filesz = phdr[i].p_filesz;
            ulong memsz = phdr[i].p_memsz;
            ulong offset = phdr[i].p_offset;
            uint flags = phdr[i].p_flags;

            // Ensure segment is in user space
            if (vaddr & 0xFFFF_8000_0000_0000)
            {
                printLine("[elf] Segment in kernel space");
                return 0;
            }

            // Determine permissions
            bool readable = (flags & PF_R) != 0;
            bool writable = (flags & PF_W) != 0;
            bool executable = (flags & PF_X) != 0;

            // Enforce W^X
            if (writable && executable)
            {
                printLine("[elf] W+X segment rejected");
                return 0;
            }

            // Page-align the segment
            ulong pageStart = vaddr & ~(pageSize - 1);
            ulong pageEnd = (vaddr + memsz + pageSize - 1) & ~(pageSize - 1);
            
            if (vm !is null)
            {
                if (!vm.mapLoadSegment(vaddr,
                                       fileData,
                                       offset,
                                       cast(size_t)filesz,
                                       cast(size_t)memsz,
                                       writable,
                                       executable))
                {
                    printLine("[elf] Failed to map segment via VMMap");
                    return 0;
                }
            }
            else
            {
                import anonymos.kernel.pagetable : mapPageInCr3;
                import anonymos.kernel.physmem : allocFrame;

                enum pageSize = 4096;

                // Allocate and map pages
                for (ulong page = pageStart; page < pageEnd; page += pageSize)
                {
                    ulong phys = allocFrame();
                    if (phys == 0)
                    {
                        printLine("[elf] Out of memory");
                        return 0;
                    }

                    // Map with user flag
                    if (!mapPageInCr3(cr3, page, phys, writable, executable, true))
                    {
                        printLine("[elf] Failed to map page");
                        return 0;
                    }

                    // Copy data to the physical page
                    // We need to temporarily map it into kernel space to write to it
                    // Since we have identity mapping in kernel, we can write directly
                    void* dest = cast(void*)phys;
                    
                    // Calculate what portion of this page contains file data
                    if (page >= vaddr && page < vaddr + filesz)
                    {
                        ulong pageOffset = (page > vaddr) ? 0 : (vaddr - page);
                        ulong srcOffset = offset + (page - vaddr) + pageOffset;
                        ulong copySize = pageSize - pageOffset;
                        
                        if (page + pageSize > vaddr + filesz)
                        {
                            copySize = (vaddr + filesz) - page - pageOffset;
                        }
                        
                        if (srcOffset + copySize <= fileData.length)
                        {
                            memcpy(dest + pageOffset, fileData.ptr + srcOffset, copySize);
                        }
                        
                        // Zero remaining portion
                        if (pageOffset + copySize < pageSize)
                        {
                            memset(dest + pageOffset + copySize, 0, pageSize - pageOffset - copySize);
                        }
                    }
                    else if (page >= vaddr && page < vaddr + memsz)
                    {
                        // BSS region - zero it
                        memset(dest, 0, pageSize);
                    }
                }
            }
        }
    }

    return hdr.e_entry;
}
