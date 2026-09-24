/* deps/veracrypt/efi — the pre-boot loader EFI application (roadmap/INSTALLER.md §E5b).
 *
 * A real UEFI app (PE32+): enumerate block devices via EFI_BLOCK_IO, find the install
 * disk (its decoy header opens), and route a password to DECOY | HIDDEN | REJECT using
 * the self-contained authenticator (efi_vc.c). For a headless OVMF proof it runs a
 * self-test of the four password cases and writes results to COM1 (so QEMU -serial
 * captures it). The interactive prompt + chain-load (LoadImage/StartImage of the matched
 * OS) is the production path; E5b proves prompt-less routing works in real firmware. */
#include "efi_vc.h"

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef u64  EFI_STATUS;
typedef void*EFI_HANDLE;

typedef struct { u32 a; u16 b, c; u8 d[8]; } EFI_GUID;
typedef struct {
    u32 MediaId; u8 RemovableMedia, MediaPresent, LogicalPartition, ReadOnly, WriteCaching;
    u32 BlockSize, IoAlign; u64 LastBlock;
} EFI_BLOCK_IO_MEDIA;
typedef struct EFI_BLOCK_IO {
    u64 Revision;
    EFI_BLOCK_IO_MEDIA *Media;
    EFI_STATUS (*Reset)(struct EFI_BLOCK_IO*, u8);
    EFI_STATUS (*ReadBlocks)(struct EFI_BLOCK_IO*, u32 MediaId, u64 LBA, u64 BufferSize, void *Buffer);
    void *WriteBlocks; void *FlushBlocks;
} EFI_BLOCK_IO;

/* EFI_BOOT_SERVICES — typed members at their spec field numbers; void* padding keeps the
 * offsets correct (AllocatePages #3, AllocatePool #6, FreePool #7, InstallProtocolInterface #14,
 * HandleProtocol #17, LoadImage #23, StartImage #24, ConnectController #31,
 * LocateHandleBuffer #37, InstallMultipleProtocolInterfaces #39). */
typedef struct {
    char hdr[24];
    void *p_1to2[2];                                                       /* #1..#2  */
    EFI_STATUS (*AllocatePages)(u32 Type, u32 MemoryType, u64 Pages, u64 *Memory); /* #3 */
    void *p_4to5[2];                                                       /* #4..#5  */
    EFI_STATUS (*AllocatePool)(u32 PoolType, u64 Size, void **Buffer);     /* #6      */
    EFI_STATUS (*FreePool)(void *Buffer);                                  /* #7      */
    void *p_8to13[6];                                                      /* #8..#13 */
    EFI_STATUS (*InstallProtocolInterface)(EFI_HANDLE*, EFI_GUID*, u32 InterfaceType, void*); /* #14 */
    void *p_15to16[2];                                                     /* #15..#16*/
    EFI_STATUS (*HandleProtocol)(EFI_HANDLE, EFI_GUID*, void**);           /* #17     */
    void *p_18to22[5];                                                     /* #18..#22*/
    EFI_STATUS (*LoadImage)(u8, EFI_HANDLE, void*, void*, u64, EFI_HANDLE*); /* #23   */
    EFI_STATUS (*StartImage)(EFI_HANDLE, u64*, u16**);                     /* #24     */
    void *p_25to30[6];                                                     /* #25..#30*/
    EFI_STATUS (*ConnectController)(EFI_HANDLE, EFI_HANDLE*, void*, u8 Recursive); /* #31 */
    void *p_32to36[5];                                                     /* #32..#36*/
    EFI_STATUS (*LocateHandleBuffer)(u32 SearchType, EFI_GUID*, void*, u64*, EFI_HANDLE**); /* #37 */
    void *p_38[1];                                                         /* #38     */
    EFI_STATUS (*InstallMultipleProtocolInterfaces)(EFI_HANDLE*, ...);     /* #39     */
} EFI_BOOT_SERVICES;

/* EFI_LOADED_IMAGE_PROTOCOL — fields to LoadOptions (offset 56), so we can hand the decoy master
 * key + on-disk rootfs geometry to the UKI as its kernel command line (systemd-stub reads
 * LoadOptions as CHAR16 cmdline). LoadOptionsSize is a u32 at 48, LoadOptions a ptr at 56. */
typedef struct {
    u64 Revision; EFI_HANDLE ParentHandle; void *SystemTable; EFI_HANDLE DeviceHandle; /* 0,8,16,24 */
    void *FilePath; void *Reserved;                                                    /* 32,40 */
    u32 LoadOptionsSize; u32 _pad;                                                      /* 48 */
    void *LoadOptions;                                                                  /* 56 */
    void *ImageBase; u64 ImageSize;                                                     /* 64,72 */
} EFI_LOADED_IMAGE;
typedef struct EFI_FILE {
    u64 Revision;
    EFI_STATUS (*Open)(struct EFI_FILE*, struct EFI_FILE**, u16*, u64, u64);
    void *Close; void *Delete;
    EFI_STATUS (*Read)(struct EFI_FILE*, u64*, void*);
} EFI_FILE;
typedef struct EFI_SIMPLE_FS { u64 Revision; EFI_STATUS (*OpenVolume)(struct EFI_SIMPLE_FS*, EFI_FILE**); } EFI_SIMPLE_FS;

typedef struct { u16 ScanCode; u16 UnicodeChar; } EFI_INPUT_KEY;
typedef struct EFI_SIMPLE_TEXT_INPUT {
    void *Reset;
    EFI_STATUS (*ReadKeyStroke)(struct EFI_SIMPLE_TEXT_INPUT*, EFI_INPUT_KEY*);
    void *WaitForKey;
} EFI_SIMPLE_TEXT_INPUT;

/* Field names/offsets per the UEFI spec; only ConIn and BS are used. */
typedef struct {
    char hdr[24];
    void *FirmwareVendor; u32 FirmwareRevision, _pad;     /* 24, 32 */
    EFI_HANDLE ConsoleInHandle;                            /* 40 */
    EFI_SIMPLE_TEXT_INPUT *ConIn;                          /* 48 */
    EFI_HANDLE ConsoleOutHandle; void *ConOut;             /* 56, 64 */
    EFI_HANDLE StdErrHandle; void *StdErr;                 /* 72, 80 */
    void *RuntimeServices;                                 /* 88 */
    EFI_BOOT_SERVICES *BS;                                 /* 96 */
} EFI_SYSTEM_TABLE;

static EFI_GUID BLOCK_IO_GUID    = {0x964e5b21,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static EFI_GUID LOADED_IMAGE_GUID= {0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static EFI_GUID SIMPLE_FS_GUID   = {0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static EFI_GUID DEVICE_PATH_GUID = {0x09576e91,0x6d3f,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
/* the vendor node that names our RAM-backed boot volume (any unique GUID) */
static EFI_GUID ANOS_RAMVOL_GUID = {0x4a6f5e21,0x3c1d,0x4f8b,{0x9a,0x2e,0x41,0x4e,0x4f,0x53,0x56,0x4f}};

/* EFI_DEVICE_PATH nodes: a vendor HARDWARE node (type 1, subtype 4) + optional FILE PATH media
 * node (type 4, subtype 4) + END (0x7F/0xFF).  Packed by hand; Length is little-endian u16. */
#define BOOTX64_PATH_CHARS 22                            /* "\EFI\BOOT\BOOTX64.EFI" + NUL */
typedef struct __attribute__((packed)) { u8 Type, SubType; u8 Len[2]; EFI_GUID Guid; u64 Tag; } DP_VENDOR;
typedef struct __attribute__((packed)) { u8 Type, SubType; u8 Len[2]; u16 Path[BOOTX64_PATH_CHARS]; } DP_FILE;
typedef struct __attribute__((packed)) { u8 Type, SubType; u8 Len[2]; } DP_END;
typedef struct __attribute__((packed)) { DP_VENDOR v; DP_END e; } DP_RAMVOL;
typedef struct __attribute__((packed)) { DP_VENDOR v; DP_FILE f; DP_END e; } DP_RAMVOL_FILE;

/* ── VGA text console (EFI ConOut) ──
 * The prompt was originally COM1-only, for the headless OVMF proof.  On a real display (a
 * VirtualBox/QEMU VGA window, or bare metal) COM1 is invisible, so the user faced a blank
 * screen with no prompt after the firmware's boot-order fall-through.  Mirror every character
 * to ConOut so the prompt, the '*' echo, and the status lines show on the actual screen too.
 * Only Reset..ClearScreen of EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL are needed; -fshort-wchar makes
 * string literals CHAR16, but we build the u16 buffers explicitly. */
typedef struct EFI_STO {
    EFI_STATUS (*Reset)(struct EFI_STO*, u8);
    EFI_STATUS (*OutputString)(struct EFI_STO*, u16*);
    void *TestString, *QueryMode, *SetMode, *SetAttribute;
    EFI_STATUS (*ClearScreen)(struct EFI_STO*);
} EFI_STO;
static EFI_STO *g_conout = 0;
static void vc(char c){                      /* echo one character to the VGA console */
#ifdef PREBOOT_PROOF
    /* OVMF routes ConOut to the serial terminal as well, so the mirror doubles every character
     * in serial.log ("EEnntteerr") and the proof harness can no longer match its markers.  The
     * proof build is headless; the production build keeps the VGA echo. */
    (void)c; return;
#endif
    if (!g_conout) return;
    u16 s[3];
    if (c=='\n'){ s[0]='\r'; s[1]='\n'; s[2]=0; } else { s[0]=(u16)(u8)c; s[1]=0; s[2]=0; }
    g_conout->OutputString(g_conout, s);
}

/* ── COM1 serial (headless OVMF capture) ── */
static void outb(u16 p, u8 v){ __asm__ __volatile__("outb %0,%1"::"a"(v),"Nd"(p)); }
static u8   inb(u16 p){ u8 v; __asm__ __volatile__("inb %1,%0":"=a"(v):"Nd"(p)); return v; }
static void su_init(void){ outb(0x3F9,0); outb(0x3FB,0x80); outb(0x3F8,1); outb(0x3F9,0); outb(0x3FB,0x03); outb(0x3FA,0xC7); outb(0x3FC,0x0B); }
static void sc(char c){ while(!(inb(0x3FD)&0x20)){} outb(0x3F8,(u8)c); if(c=='\n'){ while(!(inb(0x3FD)&0x20)){} outb(0x3F8,'\r'); } vc(c); }
static void ss(const char*s){ while(*s) sc(*s++); }

/* DENIABILITY: the production pre-boot loader must look like a generic full-disk-encryption
 * password prompt and behave IDENTICALLY for the decoy and the hidden OS — nothing on screen
 * OR on the serial line may reveal that a decoy/hidden scheme exists, or even name this OS.
 * PDBG() carries the diagnostic + routing markers that the §E5 OVMF proof (decrypt-boot-test.py)
 * greps for; it compiles to nothing unless PREBOOT_PROOF is defined, so the binary staged into
 * the real installer (built WITHOUT the flag) emits none of it. Build the proof variant with
 * -DPREBOOT_PROOF (deps/veracrypt/Makefile: preboot-proof.efi). */
#ifdef PREBOOT_PROOF
#define PDBG(s) ss(s)
#else
#define PDBG(s) ((void)0)
#endif

#define HIDDEN_HDR_OFFSET 128ULL

static u32 le32(const u8 *p){ return (u32)p[0] | ((u32)p[1]<<8) | ((u32)p[2]<<16) | ((u32)p[3]<<24); }
static u64 le64(const u8 *p){
    u64 v=0;
    for (int i=0;i<8;i++) v |= ((u64)p[i]) << (8*i);
    return v;
}
static int gpt_sig_ok(const u8 *p){
    static const u8 sig[8] = {'E','F','I',' ','P','A','R','T'};
    for (int i=0;i<8;i++) if (p[i]!=sig[i]) return 0;
    return 1;
}
static int read_lba(EFI_BLOCK_IO *bio, u64 lba, void *buf){
    if (!bio || !bio->Media || bio->Media->BlockSize!=512 || lba > bio->Media->LastBlock) return 0;
    return bio->ReadBlocks(bio, bio->Media->MediaId, lba, 512, buf)==0;
}
static int gpt_entry_range(EFI_BLOCK_IO *bio, u64 entry_lba, u32 entsz, u32 idx, u64 *first, u64 *last){
    u8 sec[512];
    u64 byte = (u64)idx * entsz;
    u64 lba = entry_lba + byte / 512;
    u32 off = (u32)(byte % 512);
    if (entsz < 128 || off + 48 > 512) return 0;
    if (!read_lba(bio, lba, sec)) return 0;
    int nonzero = 0;
    for (int i=0;i<16;i++) if (sec[off+i]) nonzero = 1;
    if (!nonzero) return 0;
    *first = le64(sec + off + 32);
    *last  = le64(sec + off + 40);
    return *first != 0 && *last >= *first;
}
/* The three-partition §E layout: [0] ESP, [1] system (decoy / full-disk), [2] outer volume. */
typedef struct { u64 sys_first, sys_last, outer_first, outer_last, hidden_lba; } INSTALL_LAYOUT;
static int find_install_layout(EFI_BLOCK_IO *bio, INSTALL_LAYOUT *L){
    u8 h[512];
    if (!bio || !bio->Media || bio->Media->LogicalPartition || bio->Media->BlockSize!=512) return 0;
    if (!read_lba(bio, 1, h) || !gpt_sig_ok(h)) return 0;
    u64 entry_lba = le64(h + 72);
    u32 num = le32(h + 80);
    u32 entsz = le32(h + 84);
    if (entry_lba == 0 || num < 3 || entsz < 128) return 0;
    if (!gpt_entry_range(bio, entry_lba, entsz, 1, &L->sys_first, &L->sys_last)) return 0;
    if (!gpt_entry_range(bio, entry_lba, entsz, 2, &L->outer_first, &L->outer_last)) return 0;
    if (L->sys_last > bio->Media->LastBlock || L->outer_last > bio->Media->LastBlock) return 0;
    if (L->outer_first + HIDDEN_HDR_OFFSET >= L->outer_last) return 0;
    L->hidden_lba = L->outer_first + HIDDEN_HDR_OFFSET;
    return 1;
}

#ifdef PREBOOT_PROOF
/* AES-NI XTS must be byte-identical to the software path: decrypt the same 3 units both ways. */
static void aesni_selftest(void){
    if (!aesni_available()){ ss("[preboot-efi] aesni: not available, software XTS only\n"); return; }
    static u8 a[1536], b[1536], k[64];
    for (int i = 0; i < 1536; i++){ a[i] = (u8)(i * 31 + 7); b[i] = a[i]; }
    for (int i = 0; i < 64; i++) k[i] = (u8)(0x5a ^ (i * 13));
    vc_xts_decrypt_units(a, 3, 0x1234567ULL, k, k + 32);
    aesni_xts_decrypt_units(b, 3, 0x1234567ULL, k, k + 32);
    int same = 1; for (int i = 0; i < 1536; i++) if (a[i] != b[i]) { same = 0; break; }
    ss(same ? "[preboot-efi] aesni XTS selftest PASS\n" : "[preboot-efi] aesni XTS selftest FAIL\n");
}
static void try_pw(const char*label,const char*pw,const u8*d,const u8*h){
    u8 key[256];
    int v = preboot_authenticate(pw,d,h,key);
    ss("  "); ss(label); ss(" -> ");
    ss(v==PREBOOT_DECOY?"DECOY":v==PREBOOT_HIDDEN?"HIDDEN":"REJECT");
    ss("\n");
}
#endif

/* Read a password from the EFI console keyboard (ConIn), echoing '*'. Returns length. */
static int read_password(EFI_SIMPLE_TEXT_INPUT *ci, char *buf, int max){
    int n=0;
    for(;;){
        EFI_INPUT_KEY k;
        while (ci->ReadKeyStroke(ci,&k)!=0){}        /* busy-poll until a key */
        u16 c=k.UnicodeChar;
        if (c==0x0D){ sc('\n'); break; }              /* Enter */
        if (c==0x08){ if(n>0){ n--; ss("\b \b"); } continue; }  /* Backspace */
        if (c>=0x20 && n<max-1){ buf[n++]=(char)c; sc('*'); }   /* printable → mask */
    }
    buf[n]=0; return n;
}

/* Build the CHAR16 kernel command line handed to the decoy UKI via LoadOptions: the decoy master
 * key (hex) plus the on-disk geometry init-crypt needs to dm-crypt-mount the rootfs. For the DECOY
 * only — the coercer already has the decoy password, so the decoy key is not secret from them; the
 * hidden OS never uses this path. */
static u16 g_cmd[600];
static int g_cmdn;
static void cmd_c(char c){ if (g_cmdn < (int)(sizeof g_cmd/2)-1) g_cmd[g_cmdn++] = (u16)(u8)c; }
static void cmd_s(const char *s){ while (*s) cmd_c(*s++); }
static void cmd_hex(const u8 *b, int n){ static const char H[]="0123456789abcdef"; for (int i=0;i<n;i++){ cmd_c(H[b[i]>>4]); cmd_c(H[b[i]&15]); } }
static void cmd_u64(u64 v){ char t[24]; int i=0; if (!v){ cmd_c('0'); return; } while (v){ t[i++]=(char)('0'+(v%10)); v/=10; } while (i) cmd_c(t[--i]); }

/* ── §E6: boot a DECRYPTED FAT VOLUME (payload kind 1) ─────────────────────────────────────
 *
 * A Full-disk or Hidden-OS EpinAnonymOS install stores its whole boot volume (the FAT32 ESP
 * image: Limine + kernel + modules) XTS-encrypted behind an ANOSBOOT descriptor, exactly like
 * the decoy's UKI -- but Limine is not a self-contained payload: it reads limine.conf, the
 * kernel and every module from the volume it was loaded from.  So the loader decrypts the
 * volume into RAM, publishes it to the firmware as a block device (BlockIo + a device path on
 * a fresh handle), lets the firmware's own FAT driver mount it, and chain-loads
 * \EFI\BOOT\BOOTX64.EFI from there with the image's DeviceHandle pointing at that volume.
 * Limine then resolves boot():/ on the RAM volume and boots EpinAnonymOS.  Nothing on disk is
 * ever in plaintext; the RAM copy lives only until the kernel reclaims the memory.
 *
 * The master key reaches the kernel through the volume itself: mk-install-iso.sh ships a
 * 512-byte /anos.key placeholder (module_path: boot():/anos.key) that starts with a fixed
 * ASCII marker.  The loader finds that marker in the decrypted RAM image and overwrites the
 * record IN RAM with the key + the LBA range the encrypted object store may use.  It is never
 * written back to the disk. */
typedef struct EFI_BLOCK_IO_RW {
    u64 Revision;
    EFI_BLOCK_IO_MEDIA *Media;
    EFI_STATUS (*Reset)(struct EFI_BLOCK_IO_RW*, u8);
    EFI_STATUS (*ReadBlocks)(struct EFI_BLOCK_IO_RW*, u32, u64, u64, void*);
    EFI_STATUS (*WriteBlocks)(struct EFI_BLOCK_IO_RW*, u32, u64, u64, const void*);
    EFI_STATUS (*FlushBlocks)(struct EFI_BLOCK_IO_RW*);
} EFI_BLOCK_IO_RW;
#define EFI_ERR(n) ((EFI_STATUS)(0x8000000000000000ULL | (n)))
#define RAMVOL_MEDIA_ID 0xA05B
static u8  *g_ram_base = 0;          /* the decrypted volume */
static u64  g_ram_len  = 0;          /* bytes (a multiple of 512) */
static EFI_BLOCK_IO_MEDIA g_ram_media;
static EFI_BLOCK_IO_RW    g_ram_bio;
static DP_RAMVOL          g_ram_dp;
static void mcpy(void *d, const void *s_, u64 n){ u8 *a=d; const u8 *b=s_; while (n--) *a++=*b++; }
static EFI_STATUS ram_reset(EFI_BLOCK_IO_RW *b, u8 ext){ (void)b; (void)ext; return 0; }
static EFI_STATUS ram_read(EFI_BLOCK_IO_RW *b, u32 media, u64 lba, u64 size, void *buf){
    (void)b;
    if (media != RAMVOL_MEDIA_ID) return EFI_ERR(13);                /* EFI_MEDIA_CHANGED */
    if (size % 512) return EFI_ERR(3);                                /* EFI_BAD_BUFFER_SIZE */
    if (!buf) return EFI_ERR(2);                                      /* EFI_INVALID_PARAMETER */
    if (lba * 512 + size > g_ram_len) return EFI_ERR(2);
    if (size) mcpy(buf, g_ram_base + lba * 512, size);
    return 0;
}
static EFI_STATUS ram_write(EFI_BLOCK_IO_RW *b, u32 media, u64 lba, u64 size, const void *buf){
    (void)b;
    if (media != RAMVOL_MEDIA_ID) return EFI_ERR(13);
    if (size % 512) return EFI_ERR(3);
    if (!buf) return EFI_ERR(2);
    if (lba * 512 + size > g_ram_len) return EFI_ERR(2);
    if (size) mcpy(g_ram_base + lba * 512, buf, size);               /* RAM only -- never the disk */
    return 0;
}
static EFI_STATUS ram_flush(EFI_BLOCK_IO_RW *b){ (void)b; return 0; }

/* The /anos.key record.  Layout (little-endian u64s), shared with the kernel's fde module:
 *   [0..8)    "ANOSKEY1"
 *   [8..72)   master key (64 bytes: data key || tweak key of the volume that booted)
 *   [72..80)  store_first_lba   [80..88) store_last_lba (inclusive)  -- the encrypted object store
 *   [88..96)  boot_region_lba   [96..104) flags: bit0 hidden-OS boot, bit1 full-disk boot
 *   [104..112) ram_base  [112..120) ram_len -- this decrypted volume, so the kernel can scrub it
 * The placeholder the ISO ships starts with the 32-byte marker below (a file of its own on the
 * volume, one FAT cluster, so the record is contiguous and a linear scan finds it). */
/* The marker is the 23-byte prefix scripts/mk-install-iso.sh writes (the rest of the sector is
 * zero); it is the LOADER<->ISO contract and must match byte for byte. */
#define ANOS_KEY_MARKER_LEN 23
static const char ANOS_KEY_MARKER[ANOS_KEY_MARKER_LEN + 1] = "ANOSKEY-PLACEHOLDER-v1-";
static int hand_off_key(const u8 *key, u64 store_first, u64 store_last, u64 region_lba, u64 flags){
    u64 hit = (u64)-1;
    for (u64 off = 0; off + 512 <= g_ram_len; off += 512){
        const u8 *p = g_ram_base + off;
        if (p[0] != 'A' || p[1] != 'N') continue;
        int ok = 1;
        for (int i = 0; i < ANOS_KEY_MARKER_LEN; i++) if (p[i] != (u8)ANOS_KEY_MARKER[i]) { ok = 0; break; }
        if (ok) { hit = off; break; }
    }
    if (hit == (u64)-1) return 0;
    u8 *r = g_ram_base + hit;
    for (int i = 0; i < 512; i++) r[i] = 0;
    mcpy(r, "ANOSKEY1", 8);
    mcpy(r + 8, key, 64);
    u64 f[6] = { store_first, store_last, region_lba, flags, (u64)(unsigned long long)g_ram_base, g_ram_len };
    for (int i = 0; i < 6; i++) for (int j = 0; j < 8; j++) r[72 + i*8 + j] = (u8)(f[i] >> (8*j));
    return 1;
}

static void scrub(void *p, u64 n){ volatile u8 *v = p; while (n--) *v++ = 0; }

/* Decrypt the FAT volume at region_lba+1 (plen bytes, units 1..) into RAM, hand the key over,
 * publish the volume, and chain-load Limine from it.  Returns only on failure. */
static void boot_fat_volume(EFI_HANDLE Image, EFI_SYSTEM_TABLE *ST, EFI_BLOCK_IO *bio, u64 region_lba,
                            u64 plen, u8 *key, u64 store_first, u64 store_last, u64 flags){
    EFI_BOOT_SERVICES *BS = ST->BS;
    u64 nsec = (plen + 511) / 512;
    u64 pages = (nsec * 512 + 4095) / 4096;
    u64 addr = 0;
    if (BS->AllocatePages(0 /*AnyPages*/, 2 /*LoaderData*/, pages, &addr) != 0 || !addr){
        PDBG("[preboot-efi] boot: volume alloc failed\n"); return; }
    u8 *p = (u8*)(unsigned long long)addr;
    /* read in 32 MiB slices (one ReadBlocks per sector was minutes; one for 512 MiB trips
     * some firmware DMA limits) and decrypt each slice as it lands */
    const u64 SLICE = (32ULL << 20) / 512;
    const int ni = aesni_available();
    for (u64 done = 0; done < nsec; ){
        u64 n = nsec - done < SLICE ? nsec - done : SLICE;
        if (bio->ReadBlocks(bio, bio->Media->MediaId, region_lba + 1 + done, n * 512, p + done * 512) != 0){
            PDBG("[preboot-efi] boot: volume read failed\n"); scrub(p, nsec * 512); return; }
        if (ni) aesni_xts_decrypt_units(p + done * 512, n, 1 + done, key, key + 32);
        else    vc_xts_decrypt_units(p + done * 512, n, 1 + done, key, key + 32);
        done += n;
    }
    /* a FAT32 volume starts with a jump + an OEM name and has 0x55AA at 510: a cheap sanity
     * check that the decryption produced a filesystem and not noise */
    if (!(p[0] == 0xEB || p[0] == 0xE9) || p[510] != 0x55 || p[511] != 0xAA){
        PDBG("[preboot-efi] boot: decrypted volume is not a FAT filesystem\n"); scrub(p, nsec * 512); return; }
    g_ram_base = p; g_ram_len = nsec * 512;
    PDBG("[preboot-efi] FAT payload decrypted into RAM\n");
    if (flags & 1){                                   /* hidden boot: the store follows the payload */
        store_first = region_lba + 1 + nsec + 2048;   /* + a 1 MiB guard, like the full-disk case */
        if (store_first >= store_last) store_first = store_last;   /* degenerate: no room, kernel will refuse */
    }

    if (!hand_off_key(key, store_first, store_last, region_lba, flags)){
        PDBG("[preboot-efi] boot: no /anos.key placeholder in the volume\n");
        /* an old image without the placeholder still boots -- its store stays where the
         * kernel puts it by default; only the key hand-off is lost */
    } else {
        PDBG("[preboot-efi] key handed to /anos.key\n");
    }
    scrub(key, 256);                                   /* the volume now carries the only copy */

    /* publish it: BlockIo + a vendor device path on a new handle, then let the firmware bind
     * its DiskIo/FAT drivers to it */
    g_ram_media.MediaId = RAMVOL_MEDIA_ID; g_ram_media.RemovableMedia = 0; g_ram_media.MediaPresent = 1;
    g_ram_media.LogicalPartition = 0; g_ram_media.ReadOnly = 0; g_ram_media.WriteCaching = 0;
    g_ram_media.BlockSize = 512; g_ram_media.IoAlign = 1; g_ram_media.LastBlock = nsec - 1;
    g_ram_bio.Revision = 0x00010000; g_ram_bio.Media = &g_ram_media;
    g_ram_bio.Reset = ram_reset; g_ram_bio.ReadBlocks = ram_read; g_ram_bio.WriteBlocks = ram_write; g_ram_bio.FlushBlocks = ram_flush;
    g_ram_dp.v.Type = 1; g_ram_dp.v.SubType = 4; g_ram_dp.v.Len[0] = (u8)sizeof(DP_VENDOR); g_ram_dp.v.Len[1] = 0;
    g_ram_dp.v.Guid = ANOS_RAMVOL_GUID; g_ram_dp.v.Tag = 0x414e4f53564f4c31ULL;
    g_ram_dp.e.Type = 0x7F; g_ram_dp.e.SubType = 0xFF; g_ram_dp.e.Len[0] = 4; g_ram_dp.e.Len[1] = 0;
    EFI_HANDLE vol = 0;
    if (BS->InstallMultipleProtocolInterfaces(&vol, &BLOCK_IO_GUID, &g_ram_bio, &DEVICE_PATH_GUID, &g_ram_dp, (void*)0) != 0 || !vol){
        PDBG("[preboot-efi] boot: could not publish the RAM volume\n"); return; }
    BS->ConnectController(vol, 0, 0, 1);

    /* find the filesystem the firmware mounted on it: normally on our own handle (a raw FAT
     * volume has no partition children); otherwise on whichever SFS handle sits under our
     * vendor node (some firmware interposes a child handle) */
    EFI_SIMPLE_FS *sfs = 0;
    EFI_HANDLE fs_handle = vol;
    if (BS->HandleProtocol(vol, &SIMPLE_FS_GUID, (void**)&sfs) != 0 || !sfs){
        sfs = 0;
        u64 n = 0; EFI_HANDLE *hs = 0;
        if (BS->LocateHandleBuffer(2, &SIMPLE_FS_GUID, 0, &n, &hs) == 0){
            for (u64 i = 0; i < n && !sfs; i++){
                DP_VENDOR *dp = 0;
                if (BS->HandleProtocol(hs[i], &DEVICE_PATH_GUID, (void**)&dp) != 0 || !dp) continue;
                if (dp->Type != 1 || dp->SubType != 4) continue;
                const u8 *a = (const u8*)&dp->Guid, *b = (const u8*)&ANOS_RAMVOL_GUID;
                int same = 1; for (int k = 0; k < 16; k++) if (a[k] != b[k]) { same = 0; break; }
                if (!same) continue;
                if (BS->HandleProtocol(hs[i], &SIMPLE_FS_GUID, (void**)&sfs) == 0 && sfs) fs_handle = hs[i];
                else sfs = 0;
            }
            BS->FreePool(hs);
        }
    }
    if (!sfs){ PDBG("[preboot-efi] boot: firmware did not mount the RAM volume\n"); return; }
    PDBG("[preboot-efi] RAM volume mounted by the firmware FAT driver\n");

    EFI_FILE *root = 0, *file = 0;
    if (sfs->OpenVolume(sfs, &root) != 0 || !root){ PDBG("[preboot-efi] boot: OpenVolume failed\n"); return; }
    static u16 path[BOOTX64_PATH_CHARS];
    { const char *a = "\\EFI\\BOOT\\BOOTX64.EFI"; int i = 0; for (; a[i]; i++) path[i] = (u16)(u8)a[i]; path[i] = 0; }
    if (root->Open(root, &file, path, 1 /*READ*/, 0) != 0 || !file){ PDBG("[preboot-efi] boot: no \\EFI\\BOOT\\BOOTX64.EFI on the volume\n"); return; }
    u64 cap = 16ULL << 20;                              /* Limine's BOOTX64.EFI is ~150 KiB */
    void *img = 0;
    if (BS->AllocatePool(2, cap, &img) != 0 || !img){ PDBG("[preboot-efi] boot: loader alloc failed\n"); return; }
    u64 got = cap;
    if (file->Read(file, &got, img) != 0 || got == 0 || got == cap){ PDBG("[preboot-efi] boot: loader read failed\n"); return; }

    /* the full device path of the file, so LoadImage records where it came from */
    static DP_RAMVOL_FILE fdp;
    fdp.v = g_ram_dp.v;
    fdp.f.Type = 4; fdp.f.SubType = 4; fdp.f.Len[0] = (u8)sizeof(DP_FILE); fdp.f.Len[1] = 0;
    for (int i = 0; i < BOOTX64_PATH_CHARS; i++) fdp.f.Path[i] = path[i];
    fdp.e.Type = 0x7F; fdp.e.SubType = 0xFF; fdp.e.Len[0] = 4; fdp.e.Len[1] = 0;
    EFI_HANDLE limine = 0;
    if (BS->LoadImage(0, Image, &fdp, img, got, &limine) != 0 || !limine){ PDBG("[preboot-efi] boot: LoadImage(BOOTX64.EFI) failed\n"); return; }
    /* Limine finds boot():/ through its LoadedImage.DeviceHandle: point it at the RAM volume */
    EFI_LOADED_IMAGE *li = 0;
    if (BS->HandleProtocol(limine, &LOADED_IMAGE_GUID, (void**)&li) == 0 && li) li->DeviceHandle = fs_handle;
    PDBG("[preboot-efi] booting BOOTX64.EFI from the decrypted volume\n");
    PDBG("[preboot-efi] decrypted the OS bootloader; starting it...\n");
    BS->StartImage(limine, 0, 0);
    PDBG("[preboot-efi] boot: the volume's bootloader returned\n");
}

/* §E5d — decrypt the matched OS's bootloader off the RAW install disk and start it.
 *
 * This is the real hand-off the stage2.efi stub stood in for. The bootloader payload is
 * XTS-encrypted on disk with the volume's master key (the same key preboot_authenticate just
 * returned), so nothing bootable is readable without the password and a wrong password reaches
 * this path with no key at all. The payload region begins at `region_lba`:
 *   sector 0            — a boot descriptor: magic "ANOSBOOT" + u64 LE payload byte-length,
 *                         XTS data unit 0;
 *   sectors 1..ceil(n)  — the PE bootloader itself, XTS data units 1.. .
 * The installer (deps/veracrypt/test/mkinstall.c, and the in-kernel veracrypt_impl.d) writes
 * exactly this shape; unit numbers and key halves must stay in lock-step with it. */
static void decrypt_and_boot(EFI_HANDLE Image, EFI_SYSTEM_TABLE *ST, EFI_BLOCK_IO *bio,
                             u64 region_lba, u8 *key, u64 store_first, u64 store_last, u64 flags){
    EFI_BOOT_SERVICES *BS = ST->BS;
    static const u8 MAGIC[8] = {'A','N','O','S','B','O','O','T'};
    u8 desc[512];
    if (!read_lba(bio, region_lba, desc)){ PDBG("[preboot-efi] boot: descriptor read failed\n"); return; }
    vc_xts_decrypt(desc, 512, 0, key, key+32);
    for (int i=0;i<8;i++) if (desc[i]!=MAGIC[i]){ PDBG("[preboot-efi] boot: no bootable payload here\n"); return; }
    u64 plen = le64(desc+8);
    /* descriptor v2: sectors [16..24) = length of the encrypted rootfs that FOLLOWS the UKI in
     * this region (0 = self-contained payload, no on-disk root). The rootfs starts right after the
     * UKI, so its first disk LBA and XTS data unit are both (region_lba + 1 + uki_sectors). */
    u64 rootfs_sectors = le64(desc+16);
    /* descriptor v3: [24..32) = payload kind.  0 = a PE image (the decoy's UKI: LoadImage it
     * directly, below); 1 = a whole FAT32 boot VOLUME (EpinAnonymOS: publish it as a RAM block
     * device and chain-load its \EFI\BOOT\BOOTX64.EFI -- see boot_fat_volume). */
    u64 kind = le64(desc+24);
    if (kind == 1){
        if (plen < 512 || plen > (1ULL<<30)){ PDBG("[preboot-efi] boot: bad volume size\n"); return; }
        PDBG("[preboot-efi] FAT payload: booting a decrypted volume\n");
        boot_fat_volume(Image, ST, bio, region_lba, plen, key, store_first, store_last, flags);
        return;
    }
    if (kind != 0){ PDBG("[preboot-efi] boot: unknown payload kind\n"); return; }
    /* upper bound is a sanity cap, not a design limit — the payload here is only the UKI (kernel +
     * a small crypt initramfs); the big rootfs stays on disk. 512 MiB is generous. */
    if (plen < 512 || plen > (512ULL<<20)){ PDBG("[preboot-efi] boot: bad payload size\n"); return; }
    u64 nsec = (plen + 511)/512;
    void *buf=0;
    if (BS->AllocatePool(2 /*LoaderData*/, nsec*512, &buf)!=0){ PDBG("[preboot-efi] boot: alloc failed\n"); return; }
    u8 *p = (u8*)buf;
    /* Read the WHOLE payload in one ReadBlocks — a multi-MB kernel is tens of thousands of
     * sectors, and one firmware round-trip per sector is minutes of latency. Then XTS-decrypt
     * each 512-byte data unit (unit = its offset within the region, matching the installer). */
    if (bio->ReadBlocks(bio, bio->Media->MediaId, region_lba+1, nsec*512, p)!=0){
        PDBG("[preboot-efi] boot: payload read failed\n"); return; }
    /* AES-NI when the CPU has it, exactly as the kind-1 volume path does.  This used to be the
     * software cipher, one call per sector: the decoy's UKI is a 14 MB Linux kernel + initramfs,
     * ~29000 sectors, which took MINUTES in firmware with no output on screen -- indistinguishable
     * from a machine that simply refuses to boot the decoy (the hidden OS, decrypted through the
     * accelerated path, came up fine).  Same key, same units, same result -- just not by hand. */
    if (aesni_available()) aesni_xts_decrypt_units(p, nsec, 1, key, key+32);
    else                   vc_xts_decrypt_units(p, nsec, 1, key, key+32);
    PDBG("[preboot-efi] payload decrypted\n");
    EFI_HANDLE img=0;
    if (BS->LoadImage(0, Image, 0, buf, plen, &img)!=0){ PDBG("[preboot-efi] boot: LoadImage failed\n"); return; }
    /* Hand the decoy key + rootfs geometry to the UKI on its kernel command line (LoadOptions).
     * init-crypt reads decoykey/decoyrl/decoyiv/decoysz to dm-crypt-mount the on-disk rootfs that
     * follows the UKI in this region. Only when a rootfs is present (decoy desktop). */
    if (rootfs_sectors){
        u64 rootfs_lba = region_lba + 1 + nsec;   /* first disk LBA of the encrypted rootfs   */
        u64 rootfs_iv  = 1 + nsec;                /* its first XTS data unit = dm-crypt iv_off */
        g_cmdn = 0;
        /* systemd-stub REPLACES the UKI's built-in cmdline with LoadOptions (non-secure-boot), so
         * pass the WHOLE command line — the base (must match deps/decoy-os UKI_CMDLINE, incl.
         * rdinit=/init) plus the decoy key + on-disk geometry init-crypt needs. */
        cmd_s("console=tty0 console=ttyS0,115200 rw rdinit=/init loglevel=4 decoykey=");
        cmd_hex(key, 64);
        cmd_s(" decoyrl=");  cmd_u64(rootfs_lba);
        cmd_s(" decoyiv=");  cmd_u64(rootfs_iv);
        cmd_s(" decoysz=");  cmd_u64(rootfs_sectors);
        /* §G2.1 honey seed of the typed (typo-corrected) password — set only after a decoy
         * match, so it is 0 (and omitted) for a hidden-OS boot. init-crypt reads it and hands
         * it to userspace; the synthetic-log generators seed the universe the password implies. */
        { u64 ds = preboot_last_decoy_seed(); if (ds){ cmd_s(" decoyseed="); cmd_u64(ds); } }
        g_cmd[g_cmdn] = 0;
        EFI_LOADED_IMAGE *li = 0;
        if (BS->HandleProtocol(img, &LOADED_IMAGE_GUID, (void**)&li) == 0 && li){
            li->LoadOptions = g_cmd;
            li->LoadOptionsSize = (u32)((g_cmdn + 1) * 2);   /* bytes, incl. the CHAR16 NUL */
        }
    }
    PDBG("[preboot-efi] decrypted the OS bootloader; starting it...\n");
    BS->StartImage(img, 0, 0);
}

/* Interactive pre-boot authentication: prompt, route, retry. The prompt and the wrong-
 * password message are identical regardless of whether a hidden OS exists. A match decrypts
 * that OS's bootloader payload (DECOY at sys_first+1, HIDDEN at hidden_lba+1) and starts it. */
static void interactive(EFI_HANDLE Image, EFI_SYSTEM_TABLE *ST, EFI_BLOCK_IO *bio,
                        const u8*decoy, const u8*hidden, const INSTALL_LAYOUT *L){
    EFI_SIMPLE_TEXT_INPUT *ci = ST->ConIn;
    static char pw[128]; static u8 key[256];    /* static: scrubbed explicitly, never left on a dead stack */
    const u64 sys_first = L->sys_first, hidden_lba = L->hidden_lba;
    for (int attempt=0; attempt<3; attempt++){
        /* One neutral prompt. In PROOF builds it carries the "[preboot-efi] Enter password:"
         * string the OVMF test waits for; in production it is a bare FDE-style prompt. */
#ifdef PREBOOT_PROOF
        ss("[preboot-efi] Enter password: ");
#else
        ss("Enter passphrase: ");
#endif
        read_password(ci, pw, sizeof pw);
        u64 volsize = 0;
        int v = preboot_authenticate_ex(pw, decoy, hidden, key, &volsize);
        scrub(pw, sizeof pw);
        /* DENIABILITY: decoy and hidden take the SAME visible path — no word betrays which,
         * or that a second OS could exist. Only the region and PROOF-only marker differ.
         *
         * Object-store bounds handed to a kind-1 (EpinAnonymOS) payload: a system-partition boot
         * (Full disk) owns the outer partition past a 1 MiB guard; a hidden boot owns the rest of
         * its own volume after the payload (the loader fills in the payload length itself, so the
         * store starts right after it).  decrypt_and_boot ignores them for a kind-0 decoy. */
        if (v==PREBOOT_DECOY){
            PDBG("[preboot-efi] unlocked; BOOTING DECOY OS\n");
            decrypt_and_boot(Image, ST, bio, sys_first + 1, key, L->outer_first + 2048, L->outer_last, 2 /*full-disk*/);
            return;
        }
        if (v==PREBOOT_HIDDEN){
            PDBG("[preboot-efi] unlocked; BOOTING HIDDEN OS\n");
            /* volume size counts the data area after the header at hidden_lba; clamp to the
             * partition so a malformed header can never point the store past it */
            u64 last = hidden_lba + (volsize / 512);
            if (last > L->outer_last || volsize == 0) last = L->outer_last;
            /* store_first is provisional: boot_fat_volume advances it past the payload */
            decrypt_and_boot(Image, ST, bio, hidden_lba + 1, key, hidden_lba + 2, last, 1 /*hidden*/);
            return;
        }
#ifdef PREBOOT_PROOF
        ss("[preboot-efi] access denied\n");
#else
        ss("\r\nIncorrect passphrase.\r\n\r\n");
#endif
    }
    PDBG("[preboot-efi] too many attempts\n");
}

EFI_STATUS efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *ST){
    su_init();
    /* Route output to the VGA console too, and wipe the firmware's boot-order chatter
     * (e.g. "failed to load Boot0002 … Not Found") so the prompt starts on a clean screen. */
    g_conout = (EFI_STO*)ST->ConOut;
    if (g_conout) g_conout->ClearScreen(g_conout);
    /* No banner in production: naming "EpinAnonymOS pre-boot authenticator" would itself out the
     * deniable system. The proof build keeps it (harmless to the OVMF test). */
    PDBG("\n[preboot-efi] EpinAnonymOS pre-boot authenticator (E5b)\n");
#ifdef PREBOOT_PROOF
    aesni_selftest();
#endif
    EFI_BOOT_SERVICES *BS = ST->BS;

    u64 n=0; EFI_HANDLE *handles=0;
    if (BS->LocateHandleBuffer(2 /*ByProtocol*/, &BLOCK_IO_GUID, 0, &n, &handles) != 0 || n==0){
        PDBG("[preboot-efi] no block devices\n"); goto done;
    }
    for (u64 i=0;i<n;i++){
        EFI_BLOCK_IO *bio=0;
        if (BS->HandleProtocol(handles[i], &BLOCK_IO_GUID, (void**)&bio)!=0 || !bio || !bio->Media) continue;
        INSTALL_LAYOUT L;
        if (!find_install_layout(bio, &L)) continue;
        const u64 sys_first = L.sys_first, hidden_lba = L.hidden_lba;
        u8 decoy[512], hidden[512], key[256];
        if (!read_lba(bio, sys_first, decoy)) continue;
        if (!read_lba(bio, hidden_lba, hidden)) continue;

        PDBG("[preboot-efi] install layout found\n");
#ifdef PREBOOT_PROOF
        /* Routing self-test — a decoy/hidden truth table. PROOF-ONLY: it would be a catastrophic
         * deniability leak in production (and it hard-codes the test passwords). */
        if (preboot_authenticate("decoy-password", decoy, hidden, key) == PREBOOT_DECOY) {
            ss("[preboot-efi] routing self-test:\n");
            try_pw("decoy-password ", "decoy-password",  decoy, hidden);
            try_pw("hidden-password", "hidden-password", decoy, hidden);
            try_pw("wrong-password ", "not-a-password",  decoy, hidden);
            ss("[preboot-efi] SELFTEST DONE\n");
        }
#endif
        interactive(ImageHandle, ST, bio, decoy, hidden, &L);   /* §E5c prompt + §E5d decrypt-and-boot */
        goto done;
    }
    PDBG("[preboot-efi] install layout not found on any block device\n");
done:
    for(;;) __asm__ __volatile__("hlt");
    return 0;
}
