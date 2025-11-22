module minimal_os.elf;

static if (!__traits(compiles, { size_t dummy; }))
{
    alias size_t = typeof(int.sizeof);
}

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

import minimal_os.console : printLine, printHex;
import minimal_os.kernel.memory : memcpy, memset;

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
