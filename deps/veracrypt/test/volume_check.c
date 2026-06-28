/* deps/veracrypt §E4a — validate the kernel's volume DATA-encryption engine.
 * The kernel (vcVolumeDataProof) XTS-encrypts a multi-sector "rootfs" (each sector its
 * own data unit) under the decoy master key + random-fills a free region. This decrypts
 * every rootfs sector back to its known plaintext (proving correct per-sector indexing
 * across many sectors) and measures the free-fill Shannon entropy (proving it's
 * indistinguishable-from-ciphertext, so a hidden volume can hide in it).
 *
 *   usage: volume_check <disk-image> */
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "vcheader.h"

#define ROOTFS_LBA      900000UL
#define ROOTFS_SECTORS  16
#define FREEFILL_LBA    950000UL
#define FREEFILL_SECTORS 16

static int pass=0, fail=0;
static void ok(const char *w,int c){ printf("  [%s] %s\n",c?"PASS":"FAIL",w); if(c)pass++; else fail++; }
static int rd(FILE *f, unsigned long lba, uint8_t *b){ return fseek(f,(long)(lba*512),SEEK_SET)==0 && fread(b,1,512,f)==512; }

int main(int argc, char **argv){
    if(argc<2){ fprintf(stderr,"usage: %s <disk-image>\n",argv[0]); return 2; }
    uint8_t mkD[256]; for(int i=0;i<256;i++) mkD[i]=(uint8_t)(0xA5^i);

    FILE *f=fopen(argv[1],"rb"); if(!f){ perror("open"); return 2; }

    /* (1) every rootfs sector decrypts at its own data unit to the known pattern */
    int allsec=1;
    for(unsigned s=0;s<ROOTFS_SECTORS;s++){
        uint8_t sec[512];
        if(!rd(f,ROOTFS_LBA+s,sec)){ fprintf(stderr,"read rootfs %u\n",s); return 2; }
        vc_xts_decrypt(sec,512,s,mkD,mkD+32);          /* unit = sector index */
        for(int j=0;j<512;j++) if(sec[j]!=(uint8_t)(s*13 + j*7 + 0x42)){ allsec=0; break; }
    }
    ok("all 16 rootfs sectors decrypt with per-sector XTS units", allsec);

    /* (2) the free-fill is high-entropy (looks like ciphertext, not zeros/patterns) */
    long hist[256]={0}; long n=0; int nonzero=0;
    for(unsigned s=0;s<FREEFILL_SECTORS;s++){
        uint8_t sec[512];
        if(!rd(f,FREEFILL_LBA+s,sec)){ fprintf(stderr,"read fill %u\n",s); return 2; }
        for(int j=0;j<512;j++){ hist[sec[j]]++; n++; if(sec[j]) nonzero=1; }
    }
    double H=0; for(int i=0;i<256;i++) if(hist[i]){ double p=(double)hist[i]/n; H-=p*log2(p); }
    printf("    free-fill Shannon entropy = %.3f bits/byte (%ld bytes)\n", H, n);
    ok("free-fill is high-entropy (>7.5 bits/byte) and non-zero", nonzero && H>7.5);

    fclose(f);
    printf("VC-VOLUME: %d passed, %d failed -> %s\n", pass, fail, fail?"FAIL":"PASS");
    return fail?1:0;
}
