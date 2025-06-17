// kernel/types.d

module kernel.types;

// VGA Colors (inspired by OSDev wiki)
enum VGAColor : ubyte {
    BLACK = 0,
    BLUE = 1,
    GREEN = 2,
    CYAN = 3,
    RED = 4,
    MAGENTA = 5,
    BROWN = 6,
    LIGHT_GREY = 7,
    DARK_GREY = 8,
    LIGHT_BLUE = 9,
    LIGHT_GREEN = 10,
    LIGHT_CYAN = 11,
    LIGHT_RED = 12,
    LIGHT_MAGENTA = 13,
    LIGHT_BROWN = 14, // Often Yellow
    WHITE = 15,
}

enum ErrorCode : ubyte {
    NONE = 0,
    GDT_LOAD_FAILURE = 0x01,
    IDT_INIT_FAILURE = 0x02,
    ISR_INSTALL_FAILURE = 0x03,
    UNKNOWN_FAILURE = 0xFF,
}

// Structure to hold register states passed from assembly interrupt stubs
struct Registers {
    uint ds; // Data segment selector pushed by isr_common_stub
    // Pushed by 'pusha' instruction (edi at lowest address, eax at highest for this block)
    uint edi, esi, ebp, esp_dummy, ebx, edx, ecx, eax; // Pushed by pusha
    uint int_no;   // Pushed by specific ISR stubs (interrupt number)
    uint err_code; // Pushed by specific ISR stubs (dummy or real error code)
    // The following are pushed by the CPU automatically on interrupt/exception
    uint eip, cs, eflags, useresp, ss; // Pushed by the processor automatically
}

// Basic C library function implementations needed by the compiler/runtime
extern (C) void* memset(void* ptr, int value, size_t num) {
    ubyte* p = cast(ubyte*)ptr;
    ubyte val = cast(ubyte)value;
    for (size_t i = 0; i < num; i++) {
        p[i] = val;
    }
    return ptr;
}