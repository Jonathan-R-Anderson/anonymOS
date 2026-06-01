module arch.x86_64.bootstrap;

import arch.x86_64.limine;
import arch.x86_64.arch;
import memory.mm;
import arch.x86_64.gdt;
import arch.x86_64.interrupts;
import core.io;
import core.globals;
import core.bundle;
import core.exports : g_module_count, g_mboot_modules, multiboot_module_t, alloc_from_regions;

@nogc nothrow:

extern (C):

extern (C) void d_kernel_main();

__gshared limine_terminal_response* g_terminal = null;
__gshared limine_terminal_write g_term_write = null;
__gshared limine_framebuffer* g_fb = null;
__gshared uint fb_x = 0;
__gshared uint fb_y = 0;

align(8) struct boot_module_record_t {
    uint mod_start;
    uint mod_end;
    char[120] name;
}

static assert(boot_module_record_t.sizeof == 128);

private void recordModuleName(ref boot_module_record_t record, const(char)* path) {
    foreach (i; 0 .. record.name.length) {
        record.name[i] = '\0';
    }
    if (path is null) {
        return;
    }
    size_t i = 0;
    while (i + 1 < record.name.length && path[i] != '\0') {
        record.name[i] = cast(char) path[i];
        ++i;
    }
}

private void publishBootModules(limine_module_response* mods) {
    g_module_count = 0;
    g_mboot_modules = null;
    if (mods is null || mods.module_count == 0 || mods.modules is null) {
        return;
    }

    auto records = cast(boot_module_record_t*) alloc_from_regions(mods.module_count * boot_module_record_t.sizeof);
    if (records is null) {
        return;
    }

    g_module_count = cast(int) mods.module_count;
    g_mboot_modules = cast(multiboot_module_t*) records;

    foreach (i; 0 .. mods.module_count) {
        auto mod = mods.modules[i];
        if (mod is null) {
            continue;
        }
        const ulong phys = cast(ulong) mod.address - hhdm_offset;
        records[i].mod_start = cast(uint) phys;
        records[i].mod_end = cast(uint) (phys + mod.size);
        recordModuleName(records[i], mod.path);
    }
}

void fb_putpixel(uint x, uint y, uint color) {
    if (!g_fb || x >= g_fb.width || y >= g_fb.height) return;
    uint* fb = cast(uint*)g_fb.address; // Already a virtual address from Limine
    fb[y * (g_fb.pitch / 4) + x] = color;
}

void fb_clear() {
    if (!g_fb) return;
    uint* fb = cast(uint*)g_fb.address; // Already a virtual address from Limine
    for (uint i = 0; i < g_fb.height * (g_fb.pitch / 4); i++) {
        fb[i] = 0; // Black background
    }
}

// Simple 8x8 bitmap font - each character is 8 bytes, each byte is a row
__gshared immutable ubyte[8][96] font = [
    // Space (32)
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    // ! (33)
    [0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x18, 0x00],
    // " (34)
    [0x66, 0x66, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00],
    // # (35)
    [0x6C, 0x6C, 0xFE, 0x6C, 0xFE, 0x6C, 0x6C, 0x00],
    // $ (36)
    [0x18, 0x3E, 0x60, 0x3C, 0x06, 0x7C, 0x18, 0x00],
    // % (37)
    [0x00, 0xC6, 0xCC, 0x18, 0x30, 0x66, 0xC6, 0x00],
    // & (38)
    [0x38, 0x6C, 0x38, 0x76, 0xDC, 0xCC, 0x76, 0x00],
    // ' (39)
    [0x18, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00],
    // ( (40)
    [0x0C, 0x18, 0x30, 0x30, 0x30, 0x18, 0x0C, 0x00],
    // ) (41)
    [0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x18, 0x30, 0x00],
    // * (42)
    [0x00, 0x66, 0x3C, 0xFF, 0x3C, 0x66, 0x00, 0x00],
    // + (43)
    [0x00, 0x18, 0x18, 0x7E, 0x18, 0x18, 0x00, 0x00],
    // , (44)
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x30],
    // - (45)
    [0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00],
    // . (46)
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00],
    // / (47)
    [0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0, 0x80, 0x00],
    // 0-9 (48-57)
    [0x7C, 0xCE, 0xDE, 0xF6, 0xE6, 0xC6, 0x7C, 0x00], // 0
    [0x18, 0x38, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00], // 1
    [0x7C, 0xC6, 0x06, 0x1C, 0x30, 0x60, 0xFE, 0x00], // 2
    [0x7C, 0xC6, 0x06, 0x3C, 0x06, 0xC6, 0x7C, 0x00], // 3
    [0x1C, 0x3C, 0x6C, 0xCC, 0xFE, 0x0C, 0x0C, 0x00], // 4
    [0xFE, 0xC0, 0xFC, 0x06, 0x06, 0xC6, 0x7C, 0x00], // 5
    [0x7C, 0xC0, 0xFC, 0xC6, 0xC6, 0xC6, 0x7C, 0x00], // 6
    [0xFE, 0x06, 0x0C, 0x18, 0x30, 0x30, 0x30, 0x00], // 7
    [0x7C, 0xC6, 0xC6, 0x7C, 0xC6, 0xC6, 0x7C, 0x00], // 8
    [0x7C, 0xC6, 0xC6, 0x7E, 0x06, 0x06, 0x7C, 0x00], // 9
    // : ; < = > ? @ (58-64)
    [0x00, 0x18, 0x18, 0x00, 0x00, 0x18, 0x18, 0x00],
    [0x00, 0x18, 0x18, 0x00, 0x00, 0x18, 0x18, 0x30],
    [0x06, 0x0C, 0x18, 0x30, 0x18, 0x0C, 0x06, 0x00],
    [0x00, 0x00, 0x7E, 0x00, 0x7E, 0x00, 0x00, 0x00],
    [0x60, 0x30, 0x18, 0x0C, 0x18, 0x30, 0x60, 0x00],
    [0x7C, 0xC6, 0x0C, 0x18, 0x18, 0x00, 0x18, 0x00],
    [0x7C, 0xC6, 0xDE, 0xDE, 0xDE, 0xC0, 0x7E, 0x00],
    // A-Z (65-90)
    [0x38, 0x6C, 0xC6, 0xC6, 0xFE, 0xC6, 0xC6, 0x00], // A
    [0xFC, 0xC6, 0xC6, 0xFC, 0xC6, 0xC6, 0xFC, 0x00], // B
    [0x7C, 0xC6, 0xC0, 0xC0, 0xC0, 0xC6, 0x7C, 0x00], // C
    [0xF8, 0xCC, 0xC6, 0xC6, 0xC6, 0xCC, 0xF8, 0x00], // D
    [0xFE, 0xC0, 0xC0, 0xF8, 0xC0, 0xC0, 0xFE, 0x00], // E
    [0xFE, 0xC0, 0xC0, 0xF8, 0xC0, 0xC0, 0xC0, 0x00], // F
    [0x7C, 0xC6, 0xC0, 0xCE, 0xC6, 0xC6, 0x7C, 0x00], // G
    [0xC6, 0xC6, 0xC6, 0xFE, 0xC6, 0xC6, 0xC6, 0x00], // H
    [0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00], // I
    [0x06, 0x06, 0x06, 0x06, 0x06, 0xC6, 0x7C, 0x00], // J
    [0xC6, 0xCC, 0xD8, 0xF0, 0xD8, 0xCC, 0xC6, 0x00], // K
    [0xC0, 0xC0, 0xC0, 0xC0, 0xC0, 0xC0, 0xFE, 0x00], // L
    [0xC6, 0xEE, 0xFE, 0xD6, 0xC6, 0xC6, 0xC6, 0x00], // M
    [0xC6, 0xE6, 0xF6, 0xDE, 0xCE, 0xC6, 0xC6, 0x00], // N
    [0x7C, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x7C, 0x00], // O
    [0xFC, 0xC6, 0xC6, 0xFC, 0xC0, 0xC0, 0xC0, 0x00], // P
    [0x7C, 0xC6, 0xC6, 0xC6, 0xD6, 0xDE, 0x7C, 0x06], // Q
    [0xFC, 0xC6, 0xC6, 0xFC, 0xD8, 0xCC, 0xC6, 0x00], // R
    [0x7C, 0xC6, 0xC0, 0x7C, 0x06, 0xC6, 0x7C, 0x00], // S
    [0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00], // T
    [0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0xC6, 0x7C, 0x00], // U
    [0xC6, 0xC6, 0xC6, 0xC6, 0x6C, 0x38, 0x10, 0x00], // V
    [0xC6, 0xC6, 0xC6, 0xD6, 0xFE, 0xEE, 0xC6, 0x00], // W
    [0xC6, 0x6C, 0x38, 0x10, 0x38, 0x6C, 0xC6, 0x00], // X
    [0x66, 0x66, 0x66, 0x3C, 0x18, 0x18, 0x18, 0x00], // Y
    [0xFE, 0x06, 0x0C, 0x18, 0x30, 0x60, 0xFE, 0x00], // Z
    // [ \ ] ^ _ ` (91-96)
    [0x3C, 0x30, 0x30, 0x30, 0x30, 0x30, 0x3C, 0x00],
    [0xC0, 0x60, 0x30, 0x18, 0x0C, 0x06, 0x02, 0x00],
    [0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x3C, 0x00],
    [0x10, 0x38, 0x6C, 0xC6, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF],
    [0x30, 0x18, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00],
    // a-z (97-122) - using same as uppercase for simplicity
    [0x00, 0x00, 0x7C, 0x06, 0x7E, 0xC6, 0x7E, 0x00], // a
    [0xC0, 0xC0, 0xFC, 0xC6, 0xC6, 0xC6, 0xFC, 0x00], // b
    [0x00, 0x00, 0x7C, 0xC6, 0xC0, 0xC6, 0x7C, 0x00], // c
    [0x06, 0x06, 0x7E, 0xC6, 0xC6, 0xC6, 0x7E, 0x00], // d
    [0x00, 0x00, 0x7C, 0xC6, 0xFE, 0xC0, 0x7C, 0x00], // e
    [0x1C, 0x36, 0x30, 0x7C, 0x30, 0x30, 0x30, 0x00], // f
    [0x00, 0x00, 0x7E, 0xC6, 0xC6, 0x7E, 0x06, 0x7C], // g
    [0xC0, 0xC0, 0xFC, 0xC6, 0xC6, 0xC6, 0xC6, 0x00], // h
    [0x18, 0x00, 0x38, 0x18, 0x18, 0x18, 0x3C, 0x00], // i
    [0x06, 0x00, 0x06, 0x06, 0x06, 0xC6, 0xC6, 0x7C], // j
    [0xC0, 0xC0, 0xCC, 0xD8, 0xF0, 0xD8, 0xCC, 0x00], // k
    [0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00], // l
    [0x00, 0x00, 0xCC, 0xFE, 0xD6, 0xC6, 0xC6, 0x00], // m
    [0x00, 0x00, 0xFC, 0xC6, 0xC6, 0xC6, 0xC6, 0x00], // n
    [0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xC6, 0x7C, 0x00], // o
    [0x00, 0x00, 0xFC, 0xC6, 0xC6, 0xFC, 0xC0, 0xC0], // p
    [0x00, 0x00, 0x7E, 0xC6, 0xC6, 0x7E, 0x06, 0x06], // q
    [0x00, 0x00, 0xDC, 0xE6, 0xC0, 0xC0, 0xC0, 0x00], // r
    [0x00, 0x00, 0x7E, 0xC0, 0x7C, 0x06, 0xFC, 0x00], // s
    [0x30, 0x30, 0xFC, 0x30, 0x30, 0x36, 0x1C, 0x00], // t
    [0x00, 0x00, 0xC6, 0xC6, 0xC6, 0xC6, 0x7E, 0x00], // u
    [0x00, 0x00, 0xC6, 0xC6, 0xC6, 0x6C, 0x38, 0x00], // v
    [0x00, 0x00, 0xC6, 0xC6, 0xD6, 0xFE, 0x6C, 0x00], // w
    [0x00, 0x00, 0xC6, 0x6C, 0x38, 0x6C, 0xC6, 0x00], // x
    [0x00, 0x00, 0xC6, 0xC6, 0xC6, 0x7E, 0x06, 0x7C], // y
    [0x00, 0x00, 0xFE, 0x0C, 0x38, 0x60, 0xFE, 0x00], // z
    // { | } ~ (123-126)
    [0x0E, 0x18, 0x18, 0x70, 0x18, 0x18, 0x0E, 0x00],
    [0x18, 0x18, 0x18, 0x00, 0x18, 0x18, 0x18, 0x00],
    [0x70, 0x18, 0x18, 0x0E, 0x18, 0x18, 0x70, 0x00],
    [0x76, 0xDC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
];

void fb_scroll() {
    if (!g_fb) return;
    uint* fb = cast(uint*)g_fb.address;
    ulong pitch_dwords = g_fb.pitch / 4;

    // Move all lines up by 16 pixels (one character height)
    for (ulong y = 16; y < g_fb.height; y++) {
        for (ulong x = 0; x < g_fb.width; x++) {
            fb[(y - 16) * pitch_dwords + x] = fb[y * pitch_dwords + x];
        }
    }

    // Clear the last 16 rows (bottom line)
    for (ulong y = g_fb.height - 16; y < g_fb.height; y++) {
        for (ulong x = 0; x < g_fb.width; x++) {
            fb[y * pitch_dwords + x] = 0;
        }
    }

    // Stay at the last line
    fb_y = cast(uint)((g_fb.height / 16) - 1);
}

void fb_clear_cell(uint cellX, uint cellY) {
    if (!g_fb) return;
    uint* fb = cast(uint*)g_fb.address;
    ulong pitch_dwords = g_fb.pitch / 4;
    uint startX = cellX * 8;
    uint startY = cellY * 16;

    for (uint row = 0; row < 16 && startY + row < g_fb.height; row++) {
        for (uint col = 0; col < 8 && startX + col < g_fb.width; col++) {
            fb[(startY + row) * pitch_dwords + startX + col] = 0;
        }
    }
}

void fb_putchar(char c) {
    if (!g_fb) return;

    if (c == '\n') {
        fb_x = 0;
        fb_y++;
        if (fb_y >= g_fb.height / 16) {
            fb_scroll();
        }
        return;
    }

    if (c == '\r') {
        fb_x = 0;
        return;
    }

    if (c == '\b') {
        if (fb_x > 0) {
            fb_x--;
        } else if (fb_y > 0) {
            fb_y--;
            fb_x = cast(uint)((g_fb.width / 8) - 1);
        }
        fb_clear_cell(fb_x, fb_y);
        return;
    }

    if (c == '\t') {
        for (uint i = 0; i < 4; i++) {
            fb_putchar(' ');
        }
        return;
    }

    fb_clear_cell(fb_x, fb_y);

    // Get font data for this character
    ubyte idx = cast(ubyte)c;
    if (idx < 32 || idx >= 128) {
        idx = 32; // Default to space for unsupported chars
    }
    idx -= 32;

    immutable(ubyte)* glyph = font[idx].ptr;
    uint color = 0x00AAAAAA; // Default gray

    // Draw the character using bitmap font
    for (uint row = 0; row < 8; row++) {
        ubyte bits = glyph[row];
        for (uint col = 0; col < 8; col++) {
            if (bits & (0x80 >> col)) {
                fb_putpixel(fb_x * 8 + col, fb_y * 16 + row * 2, color);
                fb_putpixel(fb_x * 8 + col, fb_y * 16 + row * 2 + 1, color);
            }
        }
    }

    fb_x++;
    if (fb_x >= g_fb.width / 8) {
        fb_x = 0;
        fb_y++;
        if (fb_y >= g_fb.height / 16) {
            fb_scroll();
        }
    }
}

void fb_write(const(char)* str) {
    if (!g_fb) return;
    while (*str) {
        fb_putchar(*str++);
    }
}

void term_write(const(char)* str) {
    if (g_terminal && g_term_write && g_terminal.terminal_count > 0) {
        // Calculate string length
        ulong len = 0;
        while (str[len]) len++;
        g_term_write(g_terminal.terminals[0], str, len);
    }
    // Also write to framebuffer
    fb_write(str);
}

void bootstrap_kernel(limine_memmap_response* mmap, limine_kernel_address_response* kaddr, limine_module_response* mods, limine_terminal_response* term, limine_framebuffer_response* fb_resp) {
    klog("Entering bootstrap_kernel D...\n");

    // Initialize framebuffer
    if (fb_resp && fb_resp.framebuffer_count > 0) {
        g_fb = fb_resp.framebuffers[0];
        klog("Framebuffer: ");
        klog_hex(cast(ulong)g_fb.address);
        klog(" ");
        klog_hex(g_fb.width);
        klog("x");
        klog_hex(g_fb.height);
        klog("\n");

        klog("Clearing framebuffer...\n");
        fb_clear();
        klog("FB cleared! Writing text...\n");
        fb_write("=== EpinAnonymOS ===\n");
        klog("FB text written!\n");
    } else {
        klog("No framebuffer available!\n");
    }

    // Initialize terminal
    g_terminal = term;
    if (term && term.terminal_count > 0) {
        g_term_write = term.write;
        klog("Limine terminal available\n");
        term_write("=== EpinAnonymOS Booting ===\n");
    } else {
        klog("No Limine terminal available!\n");
    }

    init_idt();
    klog("IDT initialized.\n");
    term_write("IDT initialized.\n");

    init_gdt();
    klog("GDT initialized.\n");
    term_write("GDT initialized.\n");

    init_mm(mmap);
    klog("MM initialized.\n");
    term_write("MM initialized.\n");

    // Still init VGA for backup
    vga_init(hhdm_offset);
    vga_puts("EpinAnonymOS booting...\n");
    klog("VGA initialized.\n");

    publishBootModules(mods);

    // Initialize Bundle
    if (mods && mods.module_count > 0) {
        // According to limine.cfg:
        // Module 0: hos.bundle
        // Module 1: storage.elf
        // Module 2: init.elf
        
        limine_file* bundleMod = mods.modules[0];
        if (bundleMod) {
             ulong bundlePhys = cast(ulong)bundleMod.address - hhdm_offset;
             initBundle(cast(void*)bundleMod.address, bundleMod.size);
             klog("Bundle module found at ");
             klog_hex(cast(ulong)bundleMod.address);
             klog("\n");
        }
    }

    if (mods && mods.module_count > 2) {
        klog("Mapping module 2 (init.elf) to 0x400000...\n");
        limine_file* mod = mods.modules[2];
        ulong phys = cast(ulong)mod.address - hhdm_offset;
        init_module_phys_base = phys;  // store module phys base
        ulong size = mod.size;
        ulong virt = 0x400000;
        ulong end = virt + size;
        while(virt < end) {
             map_page_hhdm(phys, virt, PTE_PRESENT | PTE_RW | PTE_USER, &alloc_phys_page);
             virt += 4096;
             phys += 4096;
        }
        klog("Mapped "); klog_hex((end - 0x400000) / 4096); klog(" pages\n");
    } else {
        klog("Module count < 3! mapping last available module to 0x400000...\n");
         if (mods && mods.module_count > 0) {
            auto fallbackIndex = mods.module_count - 1;
            limine_file* mod = mods.modules[fallbackIndex];
            klog("Mapping fallback module index ");
            klog_hex(fallbackIndex);
            klog(" to 0x400000...\n");
            ulong phys = cast(ulong)mod.address - hhdm_offset;
            init_module_phys_base = phys;  // store module phys base
            ulong size = mod.size;
            ulong virt = 0x400000;

            ulong end = virt + size;
            while(virt < end) {
                 map_page_hhdm(phys, virt, PTE_PRESENT | PTE_RW | PTE_USER, &alloc_phys_page);
                 virt += 4096;
                 phys += 4096;
            }
        } else {
            klog("No modules found!\n");
        }
    }

    
    klog("Calling D kernel main...\n");
    d_kernel_main();
    
    klog("Returned from d_kernel_main (Unexpected!)\n");
    term_write("Kernel returned from d_kernel_main (Unexpected!)\n");
    while(1) { asm @nogc nothrow { hlt; } }
}

void term_putchar(char c) {
    char[2] buf;
    buf[0] = c;
    buf[1] = 0;
    term_write(buf.ptr);
    // term_write already calls fb_write, so don't duplicate
}
