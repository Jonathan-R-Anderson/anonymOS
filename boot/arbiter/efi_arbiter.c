/* boot/arbiter/efi_arbiter.c — EpinAnonymOS A/B slot-arbiter UEFI app (SYSTEM_UPDATE U1-C).
 *
 * Firmware boots THIS (the only ESP-typed partition, \EFI\BOOT\BOOTX64.EFI). It:
 *   1. finds the install disk (whole-disk BLOCK_IO whose primary GPT + boot-state @ LBA 34
 *      validate), reads the boot-state sector and the GPT slot-A/slot-B partition starts;
 *   2. decides which slot to boot: normally trySlot; if the retry budget is exhausted and
 *      trySlot != bootOkSlot, ROLLS BACK to bootOkSlot; consumes one attempt; writes the
 *      boot-state back (atomic single sector);
 *   3. chainloads the chosen slot partition's \EFI\BOOT\BOOTX64.EFI (limine) via the
 *      SIMPLE_FS whose device-path PartitionStart matches the chosen slot.
 *
 * Self-contained PE32+ (clang -target x86_64-unknown-windows + lld-link), no libc/gnu-efi.
 * The boot-state on-disk layout MUST match src/kernel/d/core/bootstate.d. */

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
    EFI_STATUS (*WriteBlocks)(struct EFI_BLOCK_IO*, u32 MediaId, u64 LBA, u64 BufferSize, void *Buffer);
    void *FlushBlocks;
} EFI_BLOCK_IO;

/* Boot services: typed members at their spec field numbers, void* padding elsewhere. */
typedef struct {
    char hdr[24];
    void *p_1to5[5];                                                        /* #1..#5  */
    EFI_STATUS (*AllocatePool)(u32 PoolType, u64 Size, void **Buffer);      /* #6      */
    void *p_7to16[10];                                                      /* #7..#16 */
    EFI_STATUS (*HandleProtocol)(EFI_HANDLE, EFI_GUID*, void**);            /* #17     */
    void *p_18to22[5];                                                      /* #18..#22*/
    EFI_STATUS (*LoadImage)(u8, EFI_HANDLE, void*, void*, u64, EFI_HANDLE*);/* #23     */
    EFI_STATUS (*StartImage)(EFI_HANDLE, u64*, u16**);                      /* #24     */
    void *p_25to36[12];                                                     /* #25..#36*/
    EFI_STATUS (*LocateHandleBuffer)(u32 SearchType, EFI_GUID*, void*, u64*, EFI_HANDLE**); /* #37 */
} EFI_BOOT_SERVICES;

typedef struct EFI_FILE {
    u64 Revision;
    EFI_STATUS (*Open)(struct EFI_FILE*, struct EFI_FILE**, u16*, u64, u64);
    void *Close; void *Delete;
    EFI_STATUS (*Read)(struct EFI_FILE*, u64*, void*);
} EFI_FILE;
typedef struct EFI_SIMPLE_FS { u64 Revision; EFI_STATUS (*OpenVolume)(struct EFI_SIMPLE_FS*, EFI_FILE**); } EFI_SIMPLE_FS;

typedef struct {
    char hdr[24];
    void *FirmwareVendor; u32 FirmwareRevision, _pad;
    EFI_HANDLE ConsoleInHandle; void *ConIn;
    EFI_HANDLE ConsoleOutHandle; void *ConOut;
    EFI_HANDLE StdErrHandle; void *StdErr;
    void *RuntimeServices;
    EFI_BOOT_SERVICES *BS;
} EFI_SYSTEM_TABLE;

static EFI_GUID BLOCK_IO_GUID    = {0x964e5b21,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static EFI_GUID SIMPLE_FS_GUID   = {0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};
static EFI_GUID DEVICE_PATH_GUID = {0x09576e91,0x6d3f,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}};

/* ── COM1 serial (headless OVMF capture) ── */
static void outb(u16 p, u8 v){ __asm__ __volatile__("outb %0,%1"::"a"(v),"Nd"(p)); }
static u8   inb(u16 p){ u8 v; __asm__ __volatile__("inb %1,%0":"=a"(v):"Nd"(p)); return v; }
static void su_init(void){ outb(0x3F9,0); outb(0x3FB,0x80); outb(0x3F8,1); outb(0x3F9,0); outb(0x3FB,0x03); outb(0x3FA,0xC7); outb(0x3FC,0x0B); }
static void sc(char c){ while(!(inb(0x3FD)&0x20)){} outb(0x3F8,(u8)c); if(c=='\n'){ while(!(inb(0x3FD)&0x20)){} outb(0x3F8,'\r'); } }
static void ss(const char*s){ while(*s) sc(*s++); }
static void sx(u64 v){ sc('0'); sc('x'); for(int i=60;i>=0;i-=4){ u8 nib=(v>>i)&0xF; sc(nib<10?'0'+nib:'a'+nib-10); } }

static u32 le32(const u8 *p){ return (u32)p[0]|((u32)p[1]<<8)|((u32)p[2]<<16)|((u32)p[3]<<24); }
static u64 le64(const u8 *p){ u64 v=0; for(int i=0;i<8;i++) v|=((u64)p[i])<<(8*i); return v; }

/* CRC32 (IEEE reflected, poly 0xEDB88320) — MUST match core.diskpart.crc32 / bootstate.d. */
static u32 crc32(const u8 *d, u64 n){
    u32 c=0xFFFFFFFFu;
    for(u64 i=0;i<n;i++){ c^=d[i]; for(int k=0;k<8;k++) c=(c&1)?(c>>1)^0xEDB88320u:(c>>1); }
    return c^0xFFFFFFFFu;
}

static int read_lba(EFI_BLOCK_IO *bio, u64 lba, void *buf){
    if(!bio||!bio->Media||bio->Media->BlockSize!=512||lba>bio->Media->LastBlock) return 0;
    return bio->ReadBlocks(bio,bio->Media->MediaId,lba,512,buf)==0;
}
static int write_lba(EFI_BLOCK_IO *bio, u64 lba, void *buf){
    if(!bio||!bio->Media||bio->Media->BlockSize!=512||bio->Media->ReadOnly||lba>bio->Media->LastBlock) return 0;
    return bio->WriteBlocks(bio,bio->Media->MediaId,lba,512,buf)==0;
}

/* boot-state on-disk layout — mirrors src/kernel/d/core/bootstate.d */
#define BS_LBA      34ULL
#define BS_MAGIC    0x53425545u        /* 'E','U','B','S' LE */
#define BS_VERSION  1
#define SLOT_A      0
#define SLOT_B      1
#define SLOT_NONE   0xFF
#define DEFAULT_TRIES 3

typedef struct { u8 trySlot, bootOkSlot, triesLeft, activeSlot; u32 seq; } BootState;

static int bs_decode(const u8 *b, BootState *s){
    if(le32(b)!=BS_MAGIC) return 0;
    if((b[4]|(b[5]<<8))!=BS_VERSION) return 0;
    if(crc32(b,508)!=le32(b+508)) return 0;
    s->trySlot=b[6]; s->bootOkSlot=b[7]; s->triesLeft=b[8]; s->activeSlot=b[9]; s->seq=le32(b+12);
    return 1;
}
static void bs_encode(const BootState *s, u8 *b){
    for(int i=0;i<512;i++) b[i]=0;
    b[0]=0x45;b[1]=0x55;b[2]=0x42;b[3]=0x53;      /* 'E','U','B','S' */
    b[4]=BS_VERSION; b[5]=0;
    b[6]=s->trySlot; b[7]=s->bootOkSlot; b[8]=s->triesLeft; b[9]=s->activeSlot;
    b[12]=s->seq&0xFF; b[13]=(s->seq>>8)&0xFF; b[14]=(s->seq>>16)&0xFF; b[15]=(s->seq>>24)&0xFF;
    u32 c=crc32(b,508); b[508]=c&0xFF; b[509]=(c>>8)&0xFF; b[510]=(c>>16)&0xFF; b[511]=(c>>24)&0xFF;
}

static int gpt_sig_ok(const u8 *p){ static const u8 s[8]={'E','F','I',' ','P','A','R','T'}; for(int i=0;i<8;i++) if(p[i]!=s[i]) return 0; return 1; }

/* First-LBA of GPT partition entry `idx` (0-based) on this whole-disk bio, or 0. */
static u64 gpt_part_first(EFI_BLOCK_IO *bio, u64 entry_lba, u32 entsz, u32 idx){
    u8 sec[512];
    u64 byte=(u64)idx*entsz, lba=entry_lba+byte/512; u32 off=(u32)(byte%512);
    if(entsz<128||off+48>512) return 0;
    if(!read_lba(bio,lba,sec)) return 0;
    int nz=0; for(int i=0;i<16;i++) if(sec[off+i]) nz=1;   /* type GUID non-zero => used */
    if(!nz) return 0;
    return le64(sec+off+32);
}

/* Walk a device-path, return the MEDIA_HARDDRIVE PartitionStart LBA (0 if none). */
static u64 devpath_part_start(const u8 *dp){
    if(!dp) return 0;
    for(;;){
        u8 type=dp[0], sub=dp[1]; u16 len=(u16)(dp[2]|(dp[3]<<8));
        if(type==0x7F) return 0;                 /* end-of-path */
        if(len<4) return 0;
        if(type==0x04 && sub==0x01 && len>=42)   /* MEDIA_DEVICE_PATH / HARDDRIVE */
            return le64(dp+8);                    /* PartitionStart (after Type,Sub,Len,PartNum) */
        dp += len;
    }
}

static u16 LIMINE_PATH[] = L"\\EFI\\BOOT\\BOOTX64.EFI";

/* LoadImage+StartImage the given SIMPLE_FS's limine. Returns only on failure. */
static void chainload_fs(EFI_HANDLE Image, EFI_BOOT_SERVICES *BS, EFI_SIMPLE_FS *fs){
    EFI_FILE *root=0,*file=0; void *buf=0; EFI_HANDLE img=0;
    if(fs->OpenVolume(fs,&root)!=0){ ss("[arbiter] OpenVolume failed\n"); return; }
    if(root->Open(root,&file,LIMINE_PATH,1,0)!=0){ ss("[arbiter] slot has no \\EFI\\BOOT\\BOOTX64.EFI\n"); return; }
    u64 cap=8u<<20;                              /* limine is small; 8 MiB is ample */
    if(BS->AllocatePool(2,cap,&buf)!=0){ ss("[arbiter] alloc failed\n"); return; }
    u64 size=cap;
    if(file->Read(file,&size,buf)!=0){ ss("[arbiter] read failed\n"); return; }
    if(BS->LoadImage(0,Image,0,buf,size,&img)!=0){ ss("[arbiter] LoadImage failed\n"); return; }
    ss("[arbiter] starting slot bootloader...\n");
    BS->StartImage(img,0,0);                     /* returns only if the slot loader returns */
}

EFI_STATUS efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *ST){
    su_init();
    ss("\n[arbiter] EpinAnonymOS A/B slot arbiter (U1-C)\n");
    EFI_BOOT_SERVICES *BS = ST->BS;

    u64 n=0; EFI_HANDLE *handles=0;
    if(BS->LocateHandleBuffer(2,&BLOCK_IO_GUID,0,&n,&handles)!=0 || n==0){ ss("[arbiter] no block devices\n"); goto halt; }

    /* 1) find the install whole-disk: primary GPT + a valid boot-state @ LBA 34. */
    EFI_BLOCK_IO *disk=0; BootState st; u64 slotA=0, slotB=0;
    for(u64 i=0;i<n;i++){
        EFI_BLOCK_IO *bio=0;
        if(BS->HandleProtocol(handles[i],&BLOCK_IO_GUID,(void**)&bio)!=0||!bio||!bio->Media) continue;
        if(bio->Media->LogicalPartition||bio->Media->BlockSize!=512) continue;   /* whole disk only */
        u8 h[512], bs[512];
        if(!read_lba(bio,1,h)||!gpt_sig_ok(h)) continue;
        if(!read_lba(bio,BS_LBA,bs)||!bs_decode(bs,&st)) continue;
        u64 entry_lba=le64(h+72); u32 num=le32(h+80), entsz=le32(h+84);
        if(entry_lba==0||num<3||entsz<128) continue;
        slotA=gpt_part_first(bio,entry_lba,entsz,1);   /* entry 1 = slot-A */
        slotB=gpt_part_first(bio,entry_lba,entsz,2);   /* entry 2 = slot-B */
        if(!slotA||!slotB) continue;
        disk=bio; break;
    }
    if(!disk){ ss("[arbiter] no A/B install disk found\n"); goto halt; }

    ss("[arbiter] state: try="); sx(st.trySlot); ss(" ok="); sx(st.bootOkSlot);
    ss(" tries="); sx(st.triesLeft); ss(" slotA@"); sx(slotA); ss(" slotB@"); sx(slotB); ss("\n");

    /* 2) choose slot; roll back to known-good when the retry budget is spent. */
    u8 chosen = st.trySlot;
    if(st.triesLeft==0){
        if(st.bootOkSlot!=SLOT_NONE && st.bootOkSlot!=st.trySlot){
            chosen = st.bootOkSlot;
            st.trySlot = st.bootOkSlot;
            ss("[arbiter] retry budget exhausted -> AUTO-ROLLBACK to slot "); sx(chosen); ss("\n");
        }
        st.triesLeft = DEFAULT_TRIES;              /* fresh budget for whatever we now boot */
    }
    if(st.triesLeft>0) st.triesLeft--;             /* consume this attempt */
    { u8 bs[512]; bs_encode(&st,bs);
      if(!write_lba(disk,BS_LBA,bs)) ss("[arbiter] WARN: boot-state write failed (continuing)\n"); }
    ss("[arbiter] booting slot "); sx(chosen); ss(" (triesLeft now "); sx(st.triesLeft); ss(")\n");

    /* 3) chainload the chosen slot's limine: the SIMPLE_FS whose partition start matches. */
    u64 want = (chosen==SLOT_B) ? slotB : slotA;
    u64 fn=0; EFI_HANDLE *fsh=0;
    if(BS->LocateHandleBuffer(2,&SIMPLE_FS_GUID,0,&fn,&fsh)==0 && fn){
        for(u64 i=0;i<fn;i++){
            u8 *dp=0;
            if(BS->HandleProtocol(fsh[i],&DEVICE_PATH_GUID,(void**)&dp)!=0||!dp) continue;
            if(devpath_part_start(dp)!=want) continue;
            EFI_SIMPLE_FS *fs=0;
            if(BS->HandleProtocol(fsh[i],&SIMPLE_FS_GUID,(void**)&fs)!=0||!fs) continue;
            chainload_fs(ImageHandle, BS, fs);     /* returns only on failure */
            break;
        }
    }
    ss("[arbiter] could not chainload chosen slot\n");
halt:
    for(;;) __asm__ __volatile__("hlt");
    return 0;
}
