module arch.x86_64.limine;

extern (C):

alias uint64_t = ulong;
alias uint32_t = uint;
alias uint16_t = ushort;
alias uint8_t  = ubyte;
alias int64_t  = long;

enum LIMINE_COMMON_MAGIC_0 = 0xc7b1dd30df4c8b88;
enum LIMINE_COMMON_MAGIC_1 = 0x0a82e883a194f07b;

align(8) struct limine_base_revision {
    uint64_t id0;
    uint64_t id1;
    uint64_t revision;
}

align(8) struct limine_uuid {
    uint32_t a;
    uint16_t b;
    uint16_t c;
    uint8_t id0, id1, id2, id3, id4, id5, id6, id7;
}

enum LIMINE_MEDIA_TYPE_GENERIC = 0;
enum LIMINE_MEDIA_TYPE_OPTICAL = 1;
enum LIMINE_MEDIA_TYPE_TFTP = 2;

align(8) struct limine_file {
    uint64_t revision;
    void* address;
    uint64_t size;
    char* path;
    char* cmdline;
    uint32_t media_type;
    uint32_t unused;
    uint32_t tftp_ip;
    uint32_t tftp_port;
    uint32_t partition_index;
    uint32_t mbr_disk_id;
    limine_uuid gpt_disk_uuid;
    limine_uuid gpt_part_uuid;
    limine_uuid part_uuid;
}

// Memory Map
enum LIMINE_MEMMAP_REQUEST = [LIMINE_COMMON_MAGIC_0, LIMINE_COMMON_MAGIC_1, 0x67cf3d9d378a806f, 0xe304acdfc50c3c62];

enum LIMINE_MEMMAP_USABLE                 = 0;
enum LIMINE_MEMMAP_RESERVED               = 1;
enum LIMINE_MEMMAP_ACPI_RECLAIMABLE       = 2;
enum LIMINE_MEMMAP_ACPI_NVS               = 3;
enum LIMINE_MEMMAP_BAD_MEMORY             = 4;
enum LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE = 5;
enum LIMINE_MEMMAP_KERNEL_AND_MODULES     = 6;
enum LIMINE_MEMMAP_FRAMEBUFFER            = 7;

struct limine_memmap_entry {
    uint64_t base;
    uint64_t length;
    uint64_t type;
}

align(8) struct limine_memmap_response {
    uint64_t revision;
    uint64_t entry_count;
    limine_memmap_entry** entries;
}

align(8) struct limine_memmap_request {
    uint64_t id0, id1, id2, id3;
    uint64_t revision;
    limine_memmap_response* response;
}

// Module
enum LIMINE_MODULE_REQUEST = [LIMINE_COMMON_MAGIC_0, LIMINE_COMMON_MAGIC_1, 0x3e7e279702be32af, 0xca1c4f3bd1280cee];

align(8) struct limine_module_response {
    uint64_t revision;
    uint64_t module_count;
    limine_file** modules;
}

align(8) struct limine_internal_module {
    const(char)* path;
    const(char)* cmdline;
    uint64_t flags;
}

align(8) struct limine_module_request {
    uint64_t id0, id1, id2, id3;
    uint64_t revision;
    limine_module_response* response;
    uint64_t internal_module_count;
    limine_internal_module** internal_modules;
}

// Kernel Address
enum LIMINE_KERNEL_ADDRESS_REQUEST = [LIMINE_COMMON_MAGIC_0, LIMINE_COMMON_MAGIC_1, 0x71ba76863cc55f63, 0xb2644a48c516a487];

align(8) struct limine_kernel_address_response {
    uint64_t revision;
    uint64_t physical_base;
    uint64_t virtual_base;
}

align(8) struct limine_kernel_address_request {
    uint64_t id0, id1, id2, id3;
    uint64_t revision;
    limine_kernel_address_response* response;
}

// HHDM
enum LIMINE_HHDM_REQUEST = [LIMINE_COMMON_MAGIC_0, LIMINE_COMMON_MAGIC_1, 0x48dcf1cb8ad2b852, 0x63984e959a98244b];

align(8) struct limine_hhdm_response {
    uint64_t revision;
    uint64_t offset;
}

align(8) struct limine_hhdm_request {
    uint64_t id0, id1, id2, id3;
    uint64_t revision;
    limine_hhdm_response* response;
}

// Stack Size
enum LIMINE_STACK_SIZE_REQUEST = [LIMINE_COMMON_MAGIC_0, LIMINE_COMMON_MAGIC_1, 0x224ef0460a8e8926, 0xe1cb0fc25f46ea3d];

align(8) struct limine_stack_size_response {
    uint64_t revision;
}

align(8) struct limine_stack_size_request {
    uint64_t id0, id1, id2, id3;
    uint64_t revision;
    limine_stack_size_response* response;
    uint64_t stack_size;
}

// Paging Mode
enum LIMINE_PAGING_MODE_REQUEST = [LIMINE_COMMON_MAGIC_0, LIMINE_COMMON_MAGIC_1, 0x95c1a0edab0944cb, 0xa4e5cb3842f7488a];

enum LIMINE_PAGING_MODE_X86_64_4LVL = 0;
enum LIMINE_PAGING_MODE_X86_64_5LVL = 1;

align(8) struct limine_paging_mode_response {
    uint64_t revision;
    uint64_t mode;
    uint64_t flags;
}

align(8) struct limine_paging_mode_request {
    uint64_t id0, id1, id2, id3;
    uint64_t revision;
    limine_paging_mode_response* response;
    uint64_t mode;
    uint64_t flags;
}

// Framebuffer
enum LIMINE_FRAMEBUFFER_REQUEST = [LIMINE_COMMON_MAGIC_0, LIMINE_COMMON_MAGIC_1, 0x9d5827dcd881dd75, 0xa3148604f6fab11b];

align(8) struct limine_video_mode {
    uint64_t pitch;
    uint64_t width;
    uint64_t height;
    uint16_t bpp;
    uint8_t memory_model;
    uint8_t red_mask_size;
    uint8_t red_mask_shift;
    uint8_t green_mask_size;
    uint8_t green_mask_shift;
    uint8_t blue_mask_size;
    uint8_t blue_mask_shift;
}

align(8) struct limine_framebuffer {
    void* address;
    uint64_t width;
    uint64_t height;
    uint64_t pitch;
    uint16_t bpp;
    uint8_t memory_model;
    uint8_t red_mask_size;
    uint8_t red_mask_shift;
    uint8_t green_mask_size;
    uint8_t green_mask_shift;
    uint8_t blue_mask_size;
    uint8_t blue_mask_shift;
    uint8_t unused;
    uint64_t edid_size;
    void* edid;
    uint64_t mode_count;
    limine_video_mode** modes;
}

align(8) struct limine_framebuffer_response {
    uint64_t revision;
    uint64_t framebuffer_count;
    limine_framebuffer** framebuffers;
}

align(8) struct limine_framebuffer_request {
    uint64_t id0, id1, id2, id3;
    uint64_t revision;
    limine_framebuffer_response* response;
}

// Terminal
enum LIMINE_TERMINAL_REQUEST = [LIMINE_COMMON_MAGIC_0, LIMINE_COMMON_MAGIC_1, 0xc8ac59310c2b0844, 0xa68d0c7265d38878];

alias limine_terminal_write = void function(limine_terminal* terminal, const(char)* string, uint64_t length) @nogc nothrow;
alias limine_terminal_callback = void function(limine_terminal* terminal, uint64_t type, uint64_t arg1, uint64_t arg2, uint64_t arg3) @nogc nothrow;

align(8) struct limine_terminal {
    uint32_t columns;
    uint32_t rows;
    void* framebuffer;
}

align(8) struct limine_terminal_response {
    uint64_t revision;
    uint64_t terminal_count;
    limine_terminal** terminals;
    limine_terminal_write write;
}

align(8) struct limine_terminal_request {
    uint64_t id0, id1, id2, id3;
    uint64_t revision;
    limine_terminal_response* response;
    limine_terminal_callback callback;
}
