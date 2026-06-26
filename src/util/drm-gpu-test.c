// drm-gpu-test.c — R2.4a userspace GPU smoke test for EpinAnonymOS.
//
// Drives the virtio-gpu / virgl render node (/dev/dri/renderD128) through the
// kernel's DRM_IOCTL_VIRTGPU_* uABI to clear a 32x32 texture RED on the host GPU
// and read it back — the userspace analogue of the kernel's R2.3b self-test.
// Proves that userspace (eventually Mesa's virgl driver) can drive the GPU.
//
// Freestanding: raw x86_64 syscalls, no libc.  Output goes to fd 1 (console ->
// serial).  Built like test-drm.c (static, -nostdlib, _start entry).

typedef __INT64_TYPE__   int64_t;
typedef __INT32_TYPE__   int32_t;
typedef __UINT64_TYPE__  uint64_t;
typedef __UINT32_TYPE__  uint32_t;
typedef __SIZE_TYPE__    size_t;

#define SYS_write       1
#define SYS_open        2
#define SYS_close       3
#define SYS_mmap        9
#define SYS_ioctl       16
#define SYS_exit_group  231

#define O_RDWR      2
#define PROT_READ   1
#define PROT_WRITE  2
#define MAP_SHARED  1
#define MAP_FAILED  ((void*)-1LL)

// virtgpu ioctl numbers: DRM_IOWR('d'=0x64, DRM_COMMAND_BASE 0x40 + nr, sizeof(struct)).
#define DRM_IOCTL_VIRTGPU_MAP                0xC0106441UL  // drm_virtgpu_map (16)
#define DRM_IOCTL_VIRTGPU_EXECBUFFER         0xC0406442UL  // drm_virtgpu_execbuffer (64)
#define DRM_IOCTL_VIRTGPU_GETPARAM           0xC0106443UL  // drm_virtgpu_getparam (16)
#define DRM_IOCTL_VIRTGPU_RESOURCE_CREATE    0xC0386444UL  // drm_virtgpu_resource_create (56)
#define DRM_IOCTL_VIRTGPU_TRANSFER_FROM_HOST 0xC02C6446UL  // (44)
#define DRM_IOCTL_VIRTGPU_WAIT               0xC0086448UL  // drm_virtgpu_3d_wait (8)
#define DRM_IOCTL_VIRTGPU_GET_CAPS           0xC0186449UL  // drm_virtgpu_get_caps (24)
#define DRM_IOCTL_GEM_CLOSE                   0xC0086409UL  // drm_gem_close (8)

struct drm_gem_close { uint32_t handle, pad; };

#define VIRTGPU_PARAM_3D_FEATURES 1

struct drm_virtgpu_get_caps { uint32_t cap_set_id, cap_set_ver; uint64_t addr; uint32_t size, pad; };

struct drm_virtgpu_getparam { uint64_t param; uint64_t value; };

struct drm_virtgpu_resource_create {
    uint32_t target, format, bind, width, height, depth, array_size, last_level;
    uint32_t nr_samples, flags, bo_handle, res_handle, size, stride;
};

struct drm_virtgpu_map { uint64_t offset; uint32_t handle, pad; };

struct drm_virtgpu_execbuffer {
    uint32_t flags, size;
    uint64_t command, bo_handles;
    uint32_t num_bo_handles; int32_t fence_fd; uint32_t ring_idx, syncobj_stride;
    uint32_t num_in_syncobjs, num_out_syncobjs;
    uint64_t in_syncobjs, out_syncobjs;
};

struct drm_virtgpu_3d_transfer_from_host {
    uint32_t bo_handle;
    uint32_t x, y, z, w, h, d;          // drm_virtgpu_3d_box
    uint32_t level, offset, stride, layer_stride;
};

struct drm_virtgpu_3d_wait { uint32_t handle, flags; };

// ---------- raw syscalls ----------
static inline long sc1(long n, long a) {
    long r; __asm__ volatile("syscall":"=a"(r):"0"(n),"D"(a):"rcx","r11","memory"); return r;
}
static inline long sc3(long n, long a, long b, long c) {
    long r; __asm__ volatile("syscall":"=a"(r):"0"(n),"D"(a),"S"(b),"d"(c):"rcx","r11","memory"); return r;
}
static inline long sc6(long n, long a, long b, long c, long d, long e, long f) {
    long r; register long r10 __asm__("r10")=d, r8 __asm__("r8")=e, r9 __asm__("r9")=f;
    __asm__ volatile("syscall":"=a"(r):"0"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");
    return r;
}

// minimal built-ins the compiler may emit (freestanding: no libc)
void *memset(void *dst, int c, size_t n) { unsigned char *p=dst; while(n--) *p++=(unsigned char)c; return dst; }
void *memcpy(void *dst, const void *src, size_t n) { unsigned char *p=dst; const unsigned char *q=src; while(n--) *p++=*q++; return dst; }
size_t strlen(const char *s) { size_t n=0; while(s[n]) n++; return n; }

static size_t clen(const char *s) { size_t n=0; while(s[n]) n++; return n; }
static void print(const char *s) { sc3(SYS_write, 1, (long)s, (long)clen(s)); }
static void print_hex(uint64_t v) {
    char b[19]; b[0]='0'; b[1]='x'; b[18]=0;
    for (int i=17;i>=2;i--){ int d=v&0xf; b[i]=(char)(d<10?'0'+d:'a'+d-10); v>>=4; }
    print(b);
}
static void print_int(long v) {
    char b[21]; int i=20; b[20]=0;
    if(v==0){print("0");return;}
    int neg=0; if(v<0){neg=1;v=-v;}
    while(v){ b[--i]=(char)('0'+(v%10)); v/=10; }
    if(neg) b[--i]='-';
    print(b+i);
}

static void die(const char *msg, long code) {
    print(msg); print(" ("); print_int(code); print(")\n");
    print("[drm-gpu-test] RESULT: FAIL\n");
    sc1(SYS_exit_group, 1);
}

void _start(void) {
    print("[drm-gpu-test] R2.4a/b: userspace virgl GET_CAPS + clear via /dev/dri/renderD128\n");

    int fd = (int)sc3(SYS_open, (long)"/dev/dri/renderD128", O_RDWR, 0);
    if (fd < 0) die("[drm-gpu-test] open renderD128 failed", fd);

    // 1) GETPARAM(3D_FEATURES) — confirm the device offers virgl 3D.
    // NB: drm_virtgpu_getparam.value is a USERSPACE POINTER where the kernel writes
    // the result (Linux uABI: copy_to_user(param->value, &val)), NOT a field to read
    // back. (Mesa's virgl winsys uses the same convention.)
    uint64_t feat = 0;
    struct drm_virtgpu_getparam gp = { VIRTGPU_PARAM_3D_FEATURES, (uint64_t)(unsigned long)&feat };
    if (sc3(SYS_ioctl, fd, (long)DRM_IOCTL_VIRTGPU_GETPARAM, (long)&gp) != 0)
        die("[drm-gpu-test] GETPARAM failed", -1);
    print("[drm-gpu-test] 3D_FEATURES="); print_int((long)feat); print("\n");
    if (feat != 1) die("[drm-gpu-test] no 3D features", (long)feat);

    // 1b) GET_CAPS — fetch the host virgl capset (the blob Mesa parses for GL features).
    //     Try VIRGL2 (capset 2) then fall back to VIRGL (capset 1).  caps[0] = max_version.
    static uint32_t caps[256];
    struct drm_virtgpu_get_caps gc;
    int capset = 2;
    memset(&gc, 0, sizeof(gc)); memset(caps, 0, sizeof(caps));
    gc.cap_set_id = 2; gc.cap_set_ver = 2;
    gc.addr = (uint64_t)(unsigned long)caps; gc.size = sizeof(caps);
    sc3(SYS_ioctl, fd, (long)DRM_IOCTL_VIRTGPU_GET_CAPS, (long)&gc);
    if (caps[0] == 0) {  // host may not offer VIRGL2; try VIRGL (capset 1)
        capset = 1;
        memset(&gc, 0, sizeof(gc)); memset(caps, 0, sizeof(caps));
        gc.cap_set_id = 1; gc.cap_set_ver = 1;
        gc.addr = (uint64_t)(unsigned long)caps; gc.size = sizeof(caps);
        sc3(SYS_ioctl, fd, (long)DRM_IOCTL_VIRTGPU_GET_CAPS, (long)&gc);
    }
    print("[drm-gpu-test] GET_CAPS capset="); print_int(capset);
    print(" max_version="); print_hex(caps[0]);
    print(" caps[1]="); print_hex(caps[1]); print("\n");
    if (caps[0] == 0) print("[drm-gpu-test] WARNING: empty capset (Mesa would have no GL caps)\n");

    // 2) RESOURCE_CREATE — 32x32 B8G8R8A8 render-target+sampleable texture.
    struct drm_virtgpu_resource_create rc; memset(&rc, 0, sizeof(rc));
    rc.target = 2;          // PIPE_TEXTURE_2D
    rc.format = 1;          // VIRGL_FORMAT_B8G8R8A8_UNORM
    rc.bind   = 2 | 8;      // RENDER_TARGET | SAMPLER_VIEW
    rc.width = 32; rc.height = 32; rc.depth = 1; rc.array_size = 1;
    if (sc3(SYS_ioctl, fd, (long)DRM_IOCTL_VIRTGPU_RESOURCE_CREATE, (long)&rc) != 0)
        die("[drm-gpu-test] RESOURCE_CREATE failed", -1);
    print("[drm-gpu-test] bo_handle="); print_int(rc.bo_handle);
    print(" res_handle="); print_int(rc.res_handle);
    print(" size="); print_int(rc.size); print("\n");

    // 3) MAP + mmap the backing so we can read the cleared pixels.
    struct drm_virtgpu_map mp; memset(&mp, 0, sizeof(mp));
    mp.handle = rc.bo_handle;
    if (sc3(SYS_ioctl, fd, (long)DRM_IOCTL_VIRTGPU_MAP, (long)&mp) != 0)
        die("[drm-gpu-test] MAP failed", -1);
    uint32_t *px = (uint32_t*)sc6(SYS_mmap, 0, (long)rc.size,
                                  PROT_READ | PROT_WRITE, MAP_SHARED, fd, (long)mp.offset);
    if ((void*)px == MAP_FAILED || (long)px < 0) die("[drm-gpu-test] mmap failed", (long)px);
    print("[drm-gpu-test] mapped backing at offset="); print_hex(mp.offset); print("\n");

    // 4) EXECBUFFER — a virgl stream that clears the texture RED.
    //    CREATE_OBJECT(SURFACE) wrapping res -> SET_FRAMEBUFFER_STATE -> CLEAR(red).
    static uint32_t s[700]; int i = 0;
    s[i++] = (5u<<16)|(8u<<8)|1u;  // CREATE_OBJECT, OBJ_SURFACE=8, len 5
    s[i++] = 1;                    // surface handle (ctx-local virgl object)
    s[i++] = rc.res_handle;        // resource handle
    s[i++] = 1;                    // format B8G8R8A8_UNORM
    s[i++] = 0;                    // level
    s[i++] = 0;                    // first|last layer
    // Pad with repeated SET_FRAMEBUFFER_STATE (re-binds the same cbuf, harmless) to push the stream
    // well past the old ~2KB control-buffer cap — proves the large chained-descriptor submit path.
    for (int k = 0; k < 150; k++) {
        s[i++] = (3u<<16)|5u;      // SET_FRAMEBUFFER_STATE, len 3
        s[i++] = 1;                // nr_cbufs
        s[i++] = 0;                // zsurf
        s[i++] = 1;                // cbuf[0] = surface handle 1
    }
    s[i++] = (8u<<16)|7u;          // CLEAR, len 8
    s[i++] = 4;                    // PIPE_CLEAR_COLOR0
    s[i++] = 0x3f800000u;          // r = 1.0f
    s[i++] = 0;                    // g
    s[i++] = 0;                    // b
    s[i++] = 0x3f800000u;          // a = 1.0f
    s[i++] = 0; s[i++] = 0;        // depth (double)
    s[i++] = 0;                    // stencil
    struct drm_virtgpu_execbuffer eb; memset(&eb, 0, sizeof(eb));
    eb.size = (uint32_t)(i * 4);   // ~2460 bytes (> old 2KB cap)
    eb.command = (uint64_t)(unsigned long)s;
    print("[drm-gpu-test] EXECBUFFER stream size="); print_int(eb.size); print(" bytes\n");
    if (sc3(SYS_ioctl, fd, (long)DRM_IOCTL_VIRTGPU_EXECBUFFER, (long)&eb) != 0)
        die("[drm-gpu-test] EXECBUFFER failed", -1);
    print("[drm-gpu-test] submitted clear stream\n");

    // 5) TRANSFER_FROM_HOST — copy the cleared texture back into the backing.
    struct drm_virtgpu_3d_transfer_from_host tf; memset(&tf, 0, sizeof(tf));
    tf.bo_handle = rc.bo_handle;
    tf.w = 32; tf.h = 32; tf.d = 1;
    tf.stride = 128; tf.layer_stride = 4096;
    if (sc3(SYS_ioctl, fd, (long)DRM_IOCTL_VIRTGPU_TRANSFER_FROM_HOST, (long)&tf) != 0)
        die("[drm-gpu-test] TRANSFER_FROM_HOST failed", -1);

    // 6) WAIT (synchronous transport — no-op, but exercise the ioctl).
    struct drm_virtgpu_3d_wait w; memset(&w, 0, sizeof(w));
    w.handle = rc.bo_handle;
    sc3(SYS_ioctl, fd, (long)DRM_IOCTL_VIRTGPU_WAIT, (long)&w);

    // 7) Read it back: red in B8G8R8A8 memory = 0xFFFF0000.
    uint32_t p0 = px[0], p1 = px[1], pmid = px[16*32 + 16], plast = px[32*32 - 1];
    print("[drm-gpu-test] pixels[0,1,mid,last]= ");
    print_hex(p0); print(" "); print_hex(p1); print(" ");
    print_hex(pmid); print(" "); print_hex(plast); print("\n");

    if (p0 == 0xFFFF0000u && plast == 0xFFFF0000u)
        print("[drm-gpu-test] RESULT: PASS -- GPU rendered RED through /dev/dri/renderD128\n");
    else
        print("[drm-gpu-test] RESULT: FAIL -- readback not red\n");

    // 8) Lifecycle: create + GEM_CLOSE 100 resources. Without resource freeing the 64-slot GEM table
    //    (+ host resources + backing pages) would exhaust; with GEM_CLOSE freeing, slots are reused.
    int made = 0, lifeok = 1;
    for (int k = 0; k < 100; k++) {
        struct drm_virtgpu_resource_create r2; memset(&r2, 0, sizeof(r2));
        r2.target = 2; r2.format = 1; r2.bind = 2 | 8;
        r2.width = 16; r2.height = 16; r2.depth = 1; r2.array_size = 1;
        if (sc3(SYS_ioctl, fd, (long)DRM_IOCTL_VIRTGPU_RESOURCE_CREATE, (long)&r2) != 0) { lifeok = 0; break; }
        made++;
        struct drm_gem_close gcl; gcl.handle = r2.bo_handle; gcl.pad = 0;
        sc3(SYS_ioctl, fd, (long)DRM_IOCTL_GEM_CLOSE, (long)&gcl);
    }
    print("[drm-gpu-test] lifecycle: "); print_int(made);
    print(lifeok ? "/100 create+close OK (no GEM exhaustion)\n"
                 : "/100 then RESOURCE_CREATE FAILED (resource leak)\n");

    sc3(SYS_close, fd, 0, 0);
    sc1(SYS_exit_group, 0);
}
