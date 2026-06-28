/* deps/veracrypt §E3 — validate the KERNEL-written decoy/hidden encrypted layout.
 * The kernel (vcEncryptedLayoutProof) writes three VeraCrypt headers (decoy-system,
 * outer, hidden) + one XTS-encrypted decoy-OS data block to a spare disk. This reads
 * them and proves: each header opens with ONLY its own password (deniability), the
 * decoy data decrypts with the recovered decoy master key, and no cross-opens succeed.
 *
 *   usage: layout_check <disk-image> */
#include <stdio.h>
#include <string.h>
#include "vcheader.h"

/* LBAs — must match veracrypt_impl.d (VC_SYS_HDR_LBA etc.) */
#define SYS_HDR_LBA    700000UL
#define SYS_DATA_LBA   700008UL
#define OUTER_HDR_LBA  800000UL
#define HIDDEN_HDR_LBA 800128UL

static int pass=0, fail=0;
static void ok(const char *w,int c){ printf("  [%s] %s\n",c?"PASS":"FAIL",w); if(c)pass++; else fail++; }

static int rd(FILE *f, unsigned long lba, uint8_t *buf){
    return fseek(f,(long)(lba*512),SEEK_SET)==0 && fread(buf,1,512,f)==512;
}

int main(int argc, char **argv){
    if(argc<2){ fprintf(stderr,"usage: %s <disk-image>\n",argv[0]); return 2; }

    uint8_t mkD[256], mkO[256], mkH[256];
    for(int i=0;i<256;i++){ mkD[i]=(uint8_t)(0xA5^i); mkO[i]=(uint8_t)(0x5A^i); mkH[i]=(uint8_t)(0x3C+i); }
    const char *pwD="decoy-password", *pwO="outer-password", *pwH="hidden-password";

    FILE *f=fopen(argv[1],"rb"); if(!f){ perror("open"); return 2; }
    uint8_t sysH[512], outH[512], hidH[512], data[512];
    if(!rd(f,SYS_HDR_LBA,sysH) || !rd(f,OUTER_HDR_LBA,outH) ||
       !rd(f,HIDDEN_HDR_LBA,hidH) || !rd(f,SYS_DATA_LBA,data)){ fprintf(stderr,"read failed\n"); return 2; }
    fclose(f);

    uint8_t rec[256];

    /* each header opens with its own password and recovers the right master key */
    ok("decoy-system header opens with decoy password",
       vc_open_header(pwD,sysH,rec)==0 && memcmp(rec,mkD,256)==0);
    ok("outer header opens with outer password",
       vc_open_header(pwO,outH,rec)==0 && memcmp(rec,mkO,256)==0);
    ok("hidden header opens with hidden password",
       vc_open_header(pwH,hidH,rec)==0 && memcmp(rec,mkH,256)==0);

    /* deniability: no password opens another volume's header */
    ok("decoy password does NOT open outer or hidden",
       vc_open_header(pwD,outH,rec)!=0 && vc_open_header(pwD,hidH,rec)!=0);
    ok("outer password does NOT open the hidden header",
       vc_open_header(pwO,hidH,rec)!=0);
    ok("hidden password does NOT open the decoy or outer header",
       vc_open_header(pwH,sysH,rec)!=0 && vc_open_header(pwH,outH,rec)!=0);

    /* the decoy-OS data block decrypts with the recovered decoy master key */
    vc_open_header(pwD,sysH,rec);                  /* rec = decoy master keydata */
    vc_xts_decrypt(data, 512, 0, rec, rec+32);
    int dataok=1; for(int i=0;i<512;i++) if(data[i]!=(uint8_t)('A'+(i%26))) dataok=0;
    ok("decoy-OS data block decrypts with the decoy master key", dataok);

    /* the hidden header is entropy-indistinguishable: no plaintext magic on disk */
    ok("hidden header has no plaintext VERA magic", memcmp(hidH+64,"VERA",4)!=0);

    printf("VC-LAYOUT: %d passed, %d failed -> %s\n", pass, fail, fail?"FAIL":"PASS");
    return fail?1:0;
}
