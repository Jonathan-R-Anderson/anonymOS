/* deps/veracrypt/efi — stage2 stub (roadmap/INSTALLER.md §E5d). Stands in for the
 * decrypted decoy/hidden OS bootloader that the pre-boot loader chain-loads after unlock;
 * it just announces itself over COM1 so the OVMF test can confirm the hand-off. */
typedef unsigned char u8;
typedef unsigned short u16;
static void outb(u16 p, u8 v){ __asm__ __volatile__("outb %0,%1"::"a"(v),"Nd"(p)); }
static u8   inb(u16 p){ u8 v; __asm__ __volatile__("inb %1,%0":"=a"(v):"Nd"(p)); return v; }
static void sc(char c){ while(!(inb(0x3FD)&0x20)){} outb(0x3F8,(u8)c); }
static void ss(const char*s){ while(*s) sc(*s++); }

unsigned long long efi_main(void *ImageHandle, void *SystemTable){
    ss("\r\n[stage2] decoy OS bootloader handed off — STAGE2 RUNNING\r\n");
    for(;;) __asm__ __volatile__("hlt");
    return 0;
}
