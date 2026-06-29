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

/* EFI_BOOT_SERVICES — only HandleProtocol (#17) and LocateHandleBuffer (#37) are typed;
 * the rest are placeholders to keep the field offsets correct per the UEFI spec. */
typedef struct {
    char hdr[24];
    void *p1[16];                                     /* RaiseTPL .. UninstallProtocolInterface */
    EFI_STATUS (*HandleProtocol)(EFI_HANDLE, EFI_GUID*, void**);   /* #17 */
    void *p2[19];                                     /* Reserved .. ProtocolsPerHandle (#18..#36) */
    EFI_STATUS (*LocateHandleBuffer)(u32 SearchType, EFI_GUID*, void*, u64*, EFI_HANDLE**); /* #37 */
} EFI_BOOT_SERVICES;
typedef struct { char hdr[24]; void *fw1[2]; void *ConIn; void *ConOutH; void *ConOut;
    void *se1[3]; void *RT; EFI_BOOT_SERVICES *BS; } EFI_SYSTEM_TABLE;

static EFI_GUID BLOCK_IO_GUID = {0x964e5b21,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};

/* ── COM1 serial (headless OVMF capture) ── */
static void outb(u16 p, u8 v){ __asm__ __volatile__("outb %0,%1"::"a"(v),"Nd"(p)); }
static u8   inb(u16 p){ u8 v; __asm__ __volatile__("inb %1,%0":"=a"(v):"Nd"(p)); return v; }
static void su_init(void){ outb(0x3F9,0); outb(0x3FB,0x80); outb(0x3F8,1); outb(0x3F9,0); outb(0x3FB,0x03); outb(0x3FA,0xC7); outb(0x3FC,0x0B); }
static void sc(char c){ while(!(inb(0x3FD)&0x20)){} outb(0x3F8,(u8)c); if(c=='\n'){ while(!(inb(0x3FD)&0x20)){} outb(0x3F8,'\r'); } }
static void ss(const char*s){ while(*s) sc(*s++); }

/* §E4b geometry */
#define SYS_FIRST   (34ULL + 0x20000ULL)
#define HIDDEN_LBA  (SYS_FIRST + 0x20000ULL + 128ULL)

static void try_pw(const char*label,const char*pw,const u8*d,const u8*h){
    u8 key[256];
    int v = preboot_authenticate(pw,d,h,key);
    ss("  "); ss(label); ss(" -> ");
    ss(v==PREBOOT_DECOY?"DECOY":v==PREBOOT_HIDDEN?"HIDDEN":"REJECT");
    ss("\n");
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
        if (bio->Media->BlockSize!=512 || bio->Media->LastBlock < HIDDEN_LBA) continue;
        u8 decoy[512], hidden[512], key[256];
        if (bio->ReadBlocks(bio, bio->Media->MediaId, SYS_FIRST, 512, decoy)!=0) continue;
        if (bio->ReadBlocks(bio, bio->Media->MediaId, HIDDEN_LBA, 512, hidden)!=0) continue;
        if (preboot_authenticate("decoy-password", decoy, hidden, key) != PREBOOT_DECOY) continue;

        ss("[preboot-efi] install disk found; routing self-test:\n");
        try_pw("decoy-password ", "decoy-password",  decoy, hidden);
        try_pw("hidden-password", "hidden-password", decoy, hidden);
        try_pw("wrong-password ", "not-a-password",  decoy, hidden);
        ss("[preboot-efi] SELFTEST DONE\n");
        goto done;
    }
    ss("[preboot-efi] install layout not found on any block device\n");
done:
    for(;;) __asm__ __volatile__("hlt");
    return 0;
}
