/* deps/veracrypt §E2b — cross-validate the KERNEL's VeraCrypt header against the host
 * reference. The kernel (veracrypt_impl.d) writes a header built from fixed inputs to a
 * spare disk; this reads that sector and (1) rebuilds the same header with vcheader.c and
 * byte-compares, and (2) opens it with the independent C crypto. Identical bytes + a
 * clean open prove the kernel's AES/SHA/XTS/PBKDF2 + format match byte-for-byte.
 *
 *   usage: parity_check <disk-image> [lba]     (default lba 600000) */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "vcheader.h"

int main(int argc, char **argv){
    if(argc < 2){ fprintf(stderr,"usage: %s <disk-image> [lba]\n", argv[0]); return 2; }
    unsigned long lba = (argc>=3)? strtoul(argv[2],0,0) : 600000;

    /* the same fixed inputs the kernel's vcHeaderProof uses (decoy header) */
    uint8_t salt[64], mk[256];
    for(int i=0;i<64;i++)  salt[i]=(uint8_t)(0x11*i+1);
    for(int i=0;i<256;i++) mk[i]=(uint8_t)(0xA5^i);
    const char *pw="decoy-password";

    /* read the kernel-written header sector */
    FILE *f=fopen(argv[1],"rb");
    if(!f){ perror("open image"); return 2; }
    if(fseek(f,(long)(lba*512),SEEK_SET)!=0){ perror("seek"); return 2; }
    uint8_t disk[512];
    if(fread(disk,1,512,f)!=512){ fprintf(stderr,"short read at lba %lu\n",lba); return 2; }
    fclose(f);

    int ok=1;

    /* (1) byte-for-byte parity vs the host reference header */
    uint8_t ref[512];
    vc_create_header(pw, salt, mk, 0, 1u<<30, 0x20000, 0x40000000, ref);
    int bytediff = memcmp(disk, ref, 512);
    printf("  [%s] kernel header is byte-identical to vcheader.c reference\n", bytediff?"FAIL":"PASS");
    if(bytediff){
        ok=0;
        for(int i=0;i<512;i++) if(disk[i]!=ref[i]){ printf("    first diff at byte %d: disk=%02x ref=%02x\n",i,disk[i],ref[i]); break; }
    }

    /* (2) independent open recovers the master key */
    uint8_t rec[256];
    int r = vc_open_header(pw, disk, rec);
    int keyok = (r==0) && (memcmp(rec, mk, 256)==0);
    printf("  [%s] vc_open_header opens the kernel header + recovers the master key (r=%d)\n", keyok?"PASS":"FAIL", r);
    if(!keyok) ok=0;

    printf("VC-PARITY: %s\n", ok?"PASS — kernel/host header parity proven":"FAIL");
    return ok?0:1;
}
