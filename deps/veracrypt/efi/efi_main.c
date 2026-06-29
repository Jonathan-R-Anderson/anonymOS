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
 * offsets correct (AllocatePool #6, HandleProtocol #17, LoadImage #23, StartImage #24,
 * LocateHandleBuffer #37). */
typedef struct {
    char hdr[24];
    void *p_1to5[5];                                                       /* #1..#5  */
    EFI_STATUS (*AllocatePool)(u32 PoolType, u64 Size, void **Buffer);     /* #6      */
    void *p_7to16[10];                                                     /* #7..#16 */
    EFI_STATUS (*HandleProtocol)(EFI_HANDLE, EFI_GUID*, void**);           /* #17     */
    void *p_18to22[5];                                                     /* #18..#22*/
    EFI_STATUS (*LoadImage)(u8, EFI_HANDLE, void*, void*, u64, EFI_HANDLE*); /* #23   */
    EFI_STATUS (*StartImage)(EFI_HANDLE, u64*, u16**);                     /* #24     */
    void *p_25to36[12];                                                    /* #25..#36*/
    EFI_STATUS (*LocateHandleBuffer)(u32 SearchType, EFI_GUID*, void*, u64*, EFI_HANDLE**); /* #37 */
} EFI_BOOT_SERVICES;

typedef struct { u64 Revision; EFI_HANDLE ParentHandle; void *SystemTable; EFI_HANDLE DeviceHandle; } EFI_LOADED_IMAGE;
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

/* ── COM1 serial (headless OVMF capture) ── */
static void outb(u16 p, u8 v){ __asm__ __volatile__("outb %0,%1"::"a"(v),"Nd"(p)); }
static u8   inb(u16 p){ u8 v; __asm__ __volatile__("inb %1,%0":"=a"(v):"Nd"(p)); return v; }
static void su_init(void){ outb(0x3F9,0); outb(0x3FB,0x80); outb(0x3F8,1); outb(0x3F9,0); outb(0x3FB,0x03); outb(0x3FA,0xC7); outb(0x3FC,0x0B); }
static void sc(char c){ while(!(inb(0x3FD)&0x20)){} outb(0x3F8,(u8)c); if(c=='\n'){ while(!(inb(0x3FD)&0x20)){} outb(0x3F8,'\r'); } }
static void ss(const char*s){ while(*s) sc(*s++); }

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
static int gpt_entry_first(EFI_BLOCK_IO *bio, u64 entry_lba, u32 entsz, u32 idx, u64 *first){
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
    return *first != 0;
}
static int find_install_layout(EFI_BLOCK_IO *bio, u64 *sys_first, u64 *hidden_lba){
    u8 h[512];
    if (!bio || !bio->Media || bio->Media->LogicalPartition || bio->Media->BlockSize!=512) return 0;
    if (!read_lba(bio, 1, h) || !gpt_sig_ok(h)) return 0;
    u64 entry_lba = le64(h + 72);
    u32 num = le32(h + 80);
    u32 entsz = le32(h + 84);
    if (entry_lba == 0 || num < 3 || entsz < 128) return 0;
    u64 sys = 0, outer = 0;
    if (!gpt_entry_first(bio, entry_lba, entsz, 1, &sys)) return 0;
    if (!gpt_entry_first(bio, entry_lba, entsz, 2, &outer)) return 0;
    if (sys > bio->Media->LastBlock || outer + HIDDEN_HDR_OFFSET > bio->Media->LastBlock) return 0;
    *sys_first = sys;
    *hidden_lba = outer + HIDDEN_HDR_OFFSET;
    return 1;
}

static void try_pw(const char*label,const char*pw,const u8*d,const u8*h){
    u8 key[256];
    int v = preboot_authenticate(pw,d,h,key);
    ss("  "); ss(label); ss(" -> ");
    ss(v==PREBOOT_DECOY?"DECOY":v==PREBOOT_HIDDEN?"HIDDEN":"REJECT");
    ss("\n");
}

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

/* Chain-load the matched OS's next stage: read its loader image off the boot volume and
 * LoadImage/StartImage it. Here it loads \EFI\anonymos\stage2.efi (the stand-in for the
 * decrypted decoy/hidden bootloader — §H1 supplies the real one). */
static u16 STAGE2_PATH[] = L"\\EFI\\anonymos\\stage2.efi";
static void chainload(EFI_HANDLE Image, EFI_SYSTEM_TABLE *ST){
    EFI_BOOT_SERVICES *BS = ST->BS;
    EFI_LOADED_IMAGE *li=0; EFI_SIMPLE_FS *fs=0; EFI_FILE *root=0, *file=0; void *buf=0; EFI_HANDLE img=0;
    if (BS->HandleProtocol(Image, &LOADED_IMAGE_GUID, (void**)&li)!=0){ ss("[preboot-efi] chainload: no loaded-image\n"); return; }
    if (BS->HandleProtocol(li->DeviceHandle, &SIMPLE_FS_GUID, (void**)&fs)!=0){ ss("[preboot-efi] chainload: no filesystem\n"); return; }
    if (fs->OpenVolume(fs,&root)!=0 || root->Open(root,&file,STAGE2_PATH,1,0)!=0){ ss("[preboot-efi] chainload: stage2 not found\n"); return; }
    u64 cap = 1u<<20;
    if (BS->AllocatePool(2 /*LoaderData*/, cap, &buf)!=0){ ss("[preboot-efi] chainload: alloc failed\n"); return; }
    u64 size = cap;
    if (file->Read(file,&size,buf)!=0){ ss("[preboot-efi] chainload: read failed\n"); return; }
    if (BS->LoadImage(0, Image, 0, buf, size, &img)!=0){ ss("[preboot-efi] chainload: LoadImage failed\n"); return; }
    ss("[preboot-efi] chain-loading the OS bootloader...\n");
    BS->StartImage(img, 0, 0);
}

/* Interactive pre-boot authentication: prompt, route, retry. The prompt and the wrong-
 * password message are identical regardless of whether a hidden OS exists. */
static void interactive(EFI_HANDLE Image, EFI_SYSTEM_TABLE *ST, const u8*decoy, const u8*hidden){
    EFI_SIMPLE_TEXT_INPUT *ci = ST->ConIn;
    char pw[128]; u8 key[256];
    for (int attempt=0; attempt<3; attempt++){
        ss("[preboot-efi] Enter password: ");
        read_password(ci, pw, sizeof pw);
        int v = preboot_authenticate(pw, decoy, hidden, key);
        if (v==PREBOOT_DECOY){  ss("[preboot-efi] unlocked; BOOTING DECOY OS\n");  chainload(Image, ST); return; }
        if (v==PREBOOT_HIDDEN){ ss("[preboot-efi] unlocked; BOOTING HIDDEN OS\n"); chainload(Image, ST); return; }
        ss("[preboot-efi] access denied\n");
    }
    ss("[preboot-efi] too many attempts\n");
}

EFI_STATUS efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *ST){
    su_init();
    ss("\n[preboot-efi] EpinAnonymOS pre-boot authenticator (E5b)\n");
    EFI_BOOT_SERVICES *BS = ST->BS;

    u64 n=0; EFI_HANDLE *handles=0;
    if (BS->LocateHandleBuffer(2 /*ByProtocol*/, &BLOCK_IO_GUID, 0, &n, &handles) != 0 || n==0){
        ss("[preboot-efi] no block devices\n"); goto done;
    }
    for (u64 i=0;i<n;i++){
        EFI_BLOCK_IO *bio=0;
        if (BS->HandleProtocol(handles[i], &BLOCK_IO_GUID, (void**)&bio)!=0 || !bio || !bio->Media) continue;
        u64 sys_first=0, hidden_lba=0;
        if (!find_install_layout(bio, &sys_first, &hidden_lba)) continue;
        u8 decoy[512], hidden[512], key[256];
        if (!read_lba(bio, sys_first, decoy)) continue;
        if (!read_lba(bio, hidden_lba, hidden)) continue;

        ss("[preboot-efi] install layout found\n");
        if (preboot_authenticate("decoy-password", decoy, hidden, key) == PREBOOT_DECOY) {
            ss("[preboot-efi] routing self-test:\n");
            try_pw("decoy-password ", "decoy-password",  decoy, hidden);
            try_pw("hidden-password", "hidden-password", decoy, hidden);
            try_pw("wrong-password ", "not-a-password",  decoy, hidden);
            ss("[preboot-efi] SELFTEST DONE\n");
        }
        interactive(ImageHandle, ST, decoy, hidden);    /* §E5c prompt + §E5d chain-load */
        goto done;
    }
    ss("[preboot-efi] install layout not found on any block device\n");
done:
    for(;;) __asm__ __volatile__("hlt");
    return 0;
}
