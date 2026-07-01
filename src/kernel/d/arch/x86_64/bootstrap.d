module arch.x86_64.bootstrap;

import arch.x86_64.limine;
import arch.x86_64.arch;
import memory.mm;
import arch.x86_64.gdt;
import arch.x86_64.interrupts;
import core.io;
import core.globals;
import core.bundle;
import core.exports : g_module_count, g_mboot_modules, multiboot_module_t, alloc_from_regions, phys_to_virt;

@nogc nothrow:

extern (C):

extern (C) void d_kernel_main();

__gshared limine_terminal_response* g_terminal = null;
__gshared limine_terminal_write g_term_write = null;
__gshared limine_framebuffer* g_fb = null;
__gshared uint fb_x = 0;
__gshared uint fb_y = 0;

align(8) struct boot_module_record_t {
    ulong mod_start;   // 64-bit physical base: Limine can place modules above 4 GiB
    ulong mod_end;     // on real hardware with lots of RAM (a 32-bit field truncated it)
    char[112] name;
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

// True iff `path` (a Limine module path, e.g. "/busybox" or "/hos.bundle") contains
// the substring "bundle".  Stops at the NUL terminator so it never reads past the
// string.  Used to decide whether module[0] is a real hos.bundle worth reading.
private bool cstrPathIsBundle(const(char)* path) {
    if (path is null) return false;
    static immutable string needle = "bundle";
    for (const(char)* p = path; *p != 0; ++p) {
        size_t i = 0;
        for (; i < needle.length; ++i)
            if (p[i] == 0 || p[i] != needle[i]) break;
        if (i == needle.length) return true;
    }
    return false;
}

private void publishBootModules(limine_module_response* mods) {
    g_module_count = 0;
    g_mboot_modules = null;
    if (mods is null || mods.module_count == 0 || mods.modules is null) {
        return;
    }

    klog("[pubmod] count="); klog_hex(mods.module_count);
    klog(" modules@"); klog_hex(cast(ulong)mods.modules); klog("\n");

    auto records = cast(boot_module_record_t*) alloc_from_regions(mods.module_count * boot_module_record_t.sizeof);
    if (records is null) {
        klog("[pubmod] records alloc FAILED\n");
        return;
    }
    klog("[pubmod] records@"); klog_hex(cast(ulong)records); klog("\n");

    g_module_count = cast(int) mods.module_count;
    g_mboot_modules = cast(multiboot_module_t*) records;

    foreach (i; 0 .. mods.module_count) {
        auto mod = mods.modules[i];
        if (mod is null) {
            continue;
        }
        const ulong phys = cast(ulong) mod.address - hhdm_offset;
        records[i].mod_start = phys;            // full 64-bit phys (no 32-bit truncation)
        records[i].mod_end = phys + mod.size;
        recordModuleName(records[i], mod.path);
    }
    klog("[pubmod] done\n");
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

// Fixed-position HUD: draw `s` on the top-left band (pixel rows 0..15) straight to
// g_fb, bypassing the scrolling text console AND the g_desktopClaimedFb gate.  For a
// small always-on-top diagnostic (raw mouse packets) that stays readable while the
// compositor owns the screen.  Clears its own band first; green on black.
void fb_draw_hud(const(char)* s) {
    if (!g_fb || s is null) return;
    uint* fb = cast(uint*)g_fb.address;
    ulong pd = g_fb.pitch / 4;
    uint bandW = 72 * 8;
    if (bandW > g_fb.width) bandW = cast(uint)g_fb.width;
    for (uint y = 0; y < 16 && y < g_fb.height; y++)
        for (uint x = 0; x < bandW; x++)
            fb[y * pd + x] = 0x00000000;
    uint cx = 0;
    for (const(char)* p = s; *p; ++p) {
        ubyte idx = cast(ubyte)*p;
        if (idx < 32 || idx >= 128) idx = 32;
        idx -= 32;
        immutable(ubyte)* glyph = font[idx].ptr;
        for (uint row = 0; row < 8; row++) {
            ubyte bits = glyph[row];
            for (uint col = 0; col < 8; col++)
                if (bits & (0x80 >> col)) {
                    fb_putpixel(cx * 8 + col, row * 2,     0x0000FF00);
                    fb_putpixel(cx * 8 + col, row * 2 + 1, 0x0000FF00);
                }
        }
        if (++cx >= g_fb.width / 8) break;
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
        klog(" pitch=");
        klog_hex(g_fb.pitch);
        klog(" bpp=");
        klog_hex(g_fb.bpp);
        klog(" model=");
        klog_hex(g_fb.memory_model);
        klog(" rgb=");
        klog_hex(g_fb.red_mask_size);
        klog("@");
        klog_hex(g_fb.red_mask_shift);
        klog(",");
        klog_hex(g_fb.green_mask_size);
        klog("@");
        klog_hex(g_fb.green_mask_shift);
        klog(",");
        klog_hex(g_fb.blue_mask_size);
        klog("@");
        klog_hex(g_fb.blue_mask_shift);
        klog(" edid=");
        klog_hex(g_fb.edid_size);
        klog(" modes=");
        klog_hex(g_fb.mode_count);
        klog("\n");

        if (g_fb.modes !is null && g_fb.mode_count > 0) {
            ulong maxModes = g_fb.mode_count;
            if (maxModes > 8) maxModes = 8;
            foreach (i; 0 .. cast(size_t)maxModes) {
                auto mode = g_fb.modes[i];
                if (mode is null) continue;
                klog("[display] mode ");
                klog_hex(i);
                klog(": ");
                klog_hex(mode.width);
                klog("x");
                klog_hex(mode.height);
                klog(" pitch=");
                klog_hex(mode.pitch);
                klog(" bpp=");
                klog_hex(mode.bpp);
                klog(" model=");
                klog_hex(mode.memory_model);
                klog("\n");
            }
        }

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
    //vga_init(hhdm_offset);
    //vga_puts("EpinAnonymOS booting...\n");
    //klog("VGA initialized.\n");
    term_write("skipping VGA initialization.\n");

    publishBootModules(mods);

    // Initialize Bundle
    if (mods && mods.module_count > 0) {
        // According to limine.cfg:
        // Module 0: hos.bundle
        // Module 1: storage.elf
        // Module 2: init.elf
        
        limine_file* bundleMod = mods.modules[0];
        // REAL-HARDWARE FIX: module[0] is NOT a real hos.bundle in this build (it is
        // busybox — the bundle is legacy and never functional; init is found by NAME
        // from the published modules).  Reading its bytes via the raw HHDM intermittently
        // page-faults on real HW: Limine places it at a high phys (~10.7 GiB) and the
        // HHDM page for that address is sometimes not present → "EARLY BOOT EXCEPTION
        // vector 0e, not-present read, CR2=<bundle hhdm>" → the whole boot halts before
        // the desktop.  Only touch the bundle when module[0]'s PATH (in Limine's
        // low-mapped response, always safe to read) actually names a ".bundle"; otherwise
        // skip — g_bundleBase stays null exactly as the magic-mismatch path left it.
        if (bundleMod && cstrPathIsBundle(bundleMod.path)) {
             ulong bundlePhys = cast(ulong)bundleMod.address - hhdm_offset;
             ulong bundleVirt = phys_to_virt(bundlePhys);
             klog("Bundle module phys=");
             klog_hex(bundlePhys);
             klog(" limine=");
             klog_hex(cast(ulong)bundleMod.address);
             klog(" hhdm=");
             klog_hex(bundleVirt);
             klog("\n");
             initBundle(cast(void*)bundleVirt, bundleMod.size);
             klog("Bundle module found at ");
             klog_hex(bundleVirt);
             klog("\n");
        } else {
             klog("Bundle: module[0] is not a .bundle; skipping legacy bundle read\n");
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
