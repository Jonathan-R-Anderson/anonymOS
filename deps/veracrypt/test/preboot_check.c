/* deps/veracrypt §E5 — validate the pre-boot authenticator against the REAL install
 * layout written by vcEncryptedInstallProof: decoy header at the system-partition start,
 * hidden header inside the outer partition. Proves the decoy password boots the decoy,
 * the hidden password boots the hidden, and any other password is rejected (revealing
 * nothing). LBAs derive from the fixed §E4b ESP/system sizes.
 *
 *   usage: preboot_check <disk-image> */
#include <stdio.h>
#include <string.h>
#include "preboot_auth.h"

/* §E4b geometry: FIRST_USABLE=34, ESP=0x20000, SYS=0x20000, hidden offset 128 */
#define SYS_FIRST     (34UL + 0x20000UL)             /* 131106 — decoy header  */
#define OUTER_FIRST   (SYS_FIRST + 0x20000UL)        /* 262178 — outer start   */
#define HIDDEN_LBA    (OUTER_FIRST + 128UL)          /* 262306 — hidden header */

static int pass=0, fail=0;
static void ok(const char *w,int c){ printf("  [%s] %s\n",c?"PASS":"FAIL",w); if(c)pass++; else fail++; }
static int rd(FILE *f, unsigned long lba, uint8_t *b){ return fseek(f,(long)(lba*512),SEEK_SET)==0 && fread(b,1,512,f)==512; }

int main(int argc, char **argv){
    if(argc<2){ fprintf(stderr,"usage: %s <disk-image>\n",argv[0]); return 2; }
    FILE *f=fopen(argv[1],"rb"); if(!f){ perror("open"); return 2; }
    uint8_t decoyH[512], hiddenH[512];
    if(!rd(f,SYS_FIRST,decoyH) || !rd(f,HIDDEN_LBA,hiddenH)){ fprintf(stderr,"read failed\n"); return 2; }
    fclose(f);

    /* expected master keys from the install's fixed inputs */
    uint8_t mkD[256], mkH[256];
    for(int i=0;i<256;i++){ mkD[i]=(uint8_t)(0xA5^i); mkH[i]=(uint8_t)(0x3C+i); }
    uint8_t key[256];

    preboot_verdict vD = preboot_authenticate("decoy-password",  decoyH, hiddenH, key);
    ok("decoy password -> boot DECOY, recovers decoy master key",
       vD==PREBOOT_DECOY && memcmp(key,mkD,256)==0);

    preboot_verdict vH = preboot_authenticate("hidden-password", decoyH, hiddenH, key);
    ok("hidden password -> boot HIDDEN, recovers hidden master key",
       vH==PREBOOT_HIDDEN && memcmp(key,mkH,256)==0);

    preboot_verdict vW = preboot_authenticate("not-a-password",  decoyH, hiddenH, key);
    ok("wrong password -> REJECT (reveals nothing)", vW==PREBOOT_REJECT);

    /* the outer-volume password is not a bootable system → also rejected by the loader */
    preboot_verdict vO = preboot_authenticate("outer-password",  decoyH, hiddenH, key);
    ok("outer-volume password -> REJECT for boot (it's a data volume, not an OS)", vO==PREBOOT_REJECT);

    printf("VC-PREBOOT: %d passed, %d failed -> %s\n", pass, fail, fail?"FAIL":"PASS");
    return fail?1:0;
}
