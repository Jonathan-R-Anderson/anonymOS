// test-drm.c — minimal DRM/KMS smoke test for EpinAnonymOS
// Freestanding: uses raw x86_64 syscalls, no libc.

typedef __INT64_TYPE__   int64_t;
typedef __UINT64_TYPE__  uint64_t;
typedef __UINT32_TYPE__  uint32_t;
typedef __UINT16_TYPE__  uint16_t;
typedef __UINT8_TYPE__   uint8_t;
typedef __SIZE_TYPE__    size_t;
typedef long             ssize_t;

// ---------- syscall numbers ----------
#define SYS_write   1
#define SYS_open    2
#define SYS_close   3
#define SYS_mmap    9
#define SYS_ioctl   16
#define SYS_exit_group 231

// ---------- open flags ----------
#define O_RDWR      2

// ---------- mmap ----------
#define PROT_READ   1
#define PROT_WRITE  2
#define MAP_SHARED  1
#define MAP_FAILED  ((void*)-1LL)

// ---------- DRM ioctl numbers (x86_64 Linux) ----------
#define DRM_IOCTL_VERSION           0xC0406400UL
#define DRM_IOCTL_MODE_GETRESOURCES 0xC04064A0UL
#define DRM_IOCTL_MODE_GETCRTC      0xC06864A1UL
#define DRM_IOCTL_MODE_SETCRTC      0xC06864A2UL
#define DRM_IOCTL_MODE_ADDFB        0xC01C64AEUL
#define DRM_IOCTL_MODE_CREATE_DUMB  0xC02064B2UL
#define DRM_IOCTL_MODE_MAP_DUMB     0xC01064B3UL

// ---------- DRM structs ----------
struct drm_version {
    int version_major, version_minor, version_patchlevel;
    size_t name_len; char *name;
    size_t date_len; char *date;
    size_t desc_len; char *desc;
};

struct drm_mode_card_res {
    uint64_t fb_id_ptr, crtc_id_ptr, connector_id_ptr, encoder_id_ptr;
    uint32_t count_fbs, count_crtcs, count_connectors, count_encoders;
    uint32_t min_width, max_width, min_height, max_height;
};

struct drm_mode_create_dumb {
    uint32_t height, width, bpp, flags;
    uint32_t handle, pitch;
    uint64_t size;
};

struct drm_mode_map_dumb {
    uint32_t handle, pad;
    uint64_t offset;
};

struct drm_mode_fb_cmd {
    uint32_t fb_id, width, height, pitch, bpp, depth, handle;
};

struct drm_mode_modeinfo {
    uint32_t clock;
    uint16_t hdisplay, hsync_start, hsync_end, htotal, hskew;
    uint16_t vdisplay, vsync_start, vsync_end, vtotal, vscan;
    uint32_t vrefresh, flags, type;
    char name[32];
};

struct drm_mode_crtc {
    uint64_t set_connectors_ptr;
    uint32_t count_connectors;
    uint32_t crtc_id, fb_id, x, y, gamma_size, mode_valid;
    struct drm_mode_modeinfo mode;
};

// ---------- raw syscall helpers ----------
static inline long syscall1(long n, long a1) {
    long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(n),"D"(a1) : "rcx","r11","memory"); return r;
}
static inline long syscall3(long n, long a1, long a2, long a3) {
    long r; __asm__ volatile ("syscall" : "=a"(r) : "0"(n),"D"(a1),"S"(a2),"d"(a3) : "rcx","r11","memory"); return r;
}
static inline long syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    long r;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    register long r9  __asm__("r9")  = a6;
    __asm__ volatile ("syscall" : "=a"(r) : "0"(n),"D"(a1),"S"(a2),"d"(a3),"r"(r10),"r"(r8),"r"(r9) : "rcx","r11","memory");
    return r;
}

// Minimal C built-ins needed by compiler-generated code
size_t strlen(const char *s) { size_t n=0; while(s[n]) n++; return n; }
void *memset(void *d, int c, size_t n) { unsigned char *p=d; while(n--) *p++=(unsigned char)c; return d; }
void *memcpy(void *d, const void *s, size_t n) { unsigned char *p=d; const unsigned char *q=s; while(n--) *p++=*q++; return d; }

static void do_write(int fd, const char *s, size_t n) {
    syscall3(SYS_write, fd, (long)s, (long)n);
}

static size_t clen(const char *s) { size_t n=0; while(s[n]) n++; return n; }
static void puts_fd(int fd, const char *s) { do_write(fd, s, clen(s)); }
static void print(const char *s) { puts_fd(1, s); }
static void println(const char *s) { print(s); print("\n"); }

static void print_hex(uint64_t v) {
    char buf[17]; int i=16; buf[16]=0;
    while(i--) { int d=v&0xf; buf[i]=(char)(d<10?'0'+d:'a'+d-10); v>>=4; }
    print(buf);
}
static void print_int(int v) {
    char buf[12]; int i=11; buf[11]=0;
    if(v==0){print("0");return;}
    int neg=0; if(v<0){neg=1;v=-v;}
    while(v){ buf[--i]='0'+(v%10); v/=10; }
    if(neg) buf[--i]='-';
    print(buf+i);
}

// ---------- main logic ----------
static void fill_rect(uint32_t *fb, uint32_t pitch_px,
                      uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t color) {
    for (uint32_t row = y; row < y+h; row++)
        for (uint32_t col = x; col < x+w; col++)
            fb[row * pitch_px + col] = color;
}

void _start(void) {
    println("[test-drm] starting");

    int fd = (int)syscall3(SYS_open, (long)"/dev/dri/card0", O_RDWR, 0);
    if (fd < 0) {
        print("[test-drm] open /dev/dri/card0 failed: "); print_int(fd); print("\n");
        syscall1(SYS_exit_group, 1);
    }
    println("[test-drm] opened /dev/dri/card0");

    // Get DRM version
    char name_buf[64] = {0};
    char date_buf[32] = {0};
    char desc_buf[64] = {0};
    struct drm_version ver = {0};
    ver.name = name_buf; ver.name_len = 63;
    ver.date = date_buf; ver.date_len = 31;
    ver.desc = desc_buf; ver.desc_len = 63;
    long r = syscall3(SYS_ioctl, fd, (long)DRM_IOCTL_VERSION, (long)&ver);
    if (r == 0) {
        print("[test-drm] driver: "); println(name_buf);
        print("[test-drm] version: ");
        print_int(ver.version_major); print("."); print_int(ver.version_minor); print("\n");
    } else {
        print("[test-drm] DRM_IOCTL_VERSION failed: "); print_int((int)r); print("\n");
    }

    // Get display resources to find CRTC id
    uint32_t crtc_ids[4] = {0};
    struct drm_mode_card_res res = {0};
    res.crtc_id_ptr  = (uint64_t)crtc_ids;
    res.count_crtcs  = 4;
    r = syscall3(SYS_ioctl, fd, (long)DRM_IOCTL_MODE_GETRESOURCES, (long)&res);
    if (r != 0) {
        print("[test-drm] GETRESOURCES failed: "); print_int((int)r); print("\n");
        syscall3(SYS_close, fd, 0, 0);
        syscall1(SYS_exit_group, 1);
    }
    print("[test-drm] display "); print_int((int)res.max_width); print("x");
    print_int((int)res.max_height); print("\n");
    print("[test-drm] crtcs="); print_int((int)res.count_crtcs); print("\n");

    uint32_t crtc_id = (res.count_crtcs > 0) ? crtc_ids[0] : 50;
    print("[test-drm] using crtc_id="); print_int((int)crtc_id); print("\n");

    // Get current CRTC to find display dimensions
    struct drm_mode_crtc crtc = {0};
    crtc.crtc_id = crtc_id;
    r = syscall3(SYS_ioctl, fd, (long)DRM_IOCTL_MODE_GETCRTC, (long)&crtc);
    uint32_t width  = (r == 0 && crtc.mode.hdisplay > 0) ? crtc.mode.hdisplay : 1920;
    uint32_t height = (r == 0 && crtc.mode.vdisplay > 0) ? crtc.mode.vdisplay : 1080;
    print("[test-drm] mode "); print_int((int)width); print("x"); print_int((int)height); print("\n");

    // Create dumb buffer
    struct drm_mode_create_dumb dumb = {0};
    dumb.width  = width;
    dumb.height = height;
    dumb.bpp    = 32;
    r = syscall3(SYS_ioctl, fd, (long)DRM_IOCTL_MODE_CREATE_DUMB, (long)&dumb);
    if (r != 0) {
        print("[test-drm] CREATE_DUMB failed: "); print_int((int)r); print("\n");
        syscall3(SYS_close, fd, 0, 0);
        syscall1(SYS_exit_group, 1);
    }
    print("[test-drm] dumb handle="); print_int((int)dumb.handle);
    print(" pitch="); print_int((int)dumb.pitch); print("\n");

    // Get mmap offset for dumb buffer
    struct drm_mode_map_dumb map_dumb = {0};
    map_dumb.handle = dumb.handle;
    r = syscall3(SYS_ioctl, fd, (long)DRM_IOCTL_MODE_MAP_DUMB, (long)&map_dumb);
    if (r != 0) {
        print("[test-drm] MAP_DUMB failed: "); print_int((int)r); print("\n");
        syscall3(SYS_close, fd, 0, 0);
        syscall1(SYS_exit_group, 1);
    }
    print("[test-drm] mmap offset=0x"); print_hex(map_dumb.offset); print("\n");

    // mmap the framebuffer
    uint32_t *fb = (uint32_t *)syscall6(
        SYS_mmap, 0, (long)dumb.size,
        PROT_READ | PROT_WRITE, MAP_SHARED,
        fd, (long)map_dumb.offset);
    if ((void*)fb == MAP_FAILED) {
        print("[test-drm] mmap failed\n");
        syscall3(SYS_close, fd, 0, 0);
        syscall1(SYS_exit_group, 1);
    }
    println("[test-drm] framebuffer mapped");

    // Draw: red top-third, green middle-third, blue bottom-third
    uint32_t bw = dumb.pitch / 4; // pitch in pixels
    uint32_t third = height / 3;
    fill_rect(fb, bw, 0, 0,        width, third,        0x00FF0000);
    fill_rect(fb, bw, 0, third,    width, third,        0x0000FF00);
    fill_rect(fb, bw, 0, third*2,  width, height-third*2, 0x000000FF);

    // White banner in the center
    fill_rect(fb, bw, width/4, height/2 - 20, width/2, 40, 0x00FFFFFF);

    println("[test-drm] drew RGB bars");

    // Add framebuffer
    struct drm_mode_fb_cmd fb_cmd = {0};
    fb_cmd.width  = width;
    fb_cmd.height = height;
    fb_cmd.bpp    = 32;
    fb_cmd.depth  = 24;
    fb_cmd.pitch  = dumb.pitch;
    fb_cmd.handle = dumb.handle;
    r = syscall3(SYS_ioctl, fd, (long)DRM_IOCTL_MODE_ADDFB, (long)&fb_cmd);
    if (r != 0) {
        print("[test-drm] ADDFB failed: "); print_int((int)r); print("\n");
    } else {
        print("[test-drm] fb_id="); print_int((int)fb_cmd.fb_id); print("\n");
    }

    // Set CRTC
    uint32_t connector_id = 51; // from kernel drm.d defaults
    struct drm_mode_crtc set_crtc = {0};
    set_crtc.crtc_id              = crtc_id;
    set_crtc.fb_id                = fb_cmd.fb_id;
    set_crtc.x                    = 0;
    set_crtc.y                    = 0;
    set_crtc.set_connectors_ptr   = (uint64_t)&connector_id;
    set_crtc.count_connectors     = 1;
    set_crtc.mode_valid           = 1;
    set_crtc.mode.hdisplay        = (uint16_t)width;
    set_crtc.mode.vdisplay        = (uint16_t)height;
    set_crtc.mode.vrefresh        = 60;
    r = syscall3(SYS_ioctl, fd, (long)DRM_IOCTL_MODE_SETCRTC, (long)&set_crtc);
    if (r != 0) {
        print("[test-drm] SETCRTC failed: "); print_int((int)r); print("\n");
    } else {
        println("[test-drm] SETCRTC OK — display updated");
    }

    syscall3(SYS_close, fd, 0, 0);
    println("[test-drm] done");
    syscall1(SYS_exit_group, 0);
}
