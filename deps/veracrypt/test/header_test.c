/* deps/veracrypt §E2 — validate the VeraCrypt header engine on the KAT'd crypto core.
 * Proves: the format round-trips (create→open recovers the master key), wrong passwords
 * are rejected, the magic is encrypted (no plaintext tell), and the hidden-volume
 * mechanism gives deniability — each password opens ONLY its own header. */
#include <stdio.h>
#include <string.h>
#include "vcheader.h"

static int pass=0, fail=0;
static void ok(const char *what, int cond){
    printf("  [%s] %s\n", cond?"PASS":"FAIL", what); if(cond) pass++; else fail++;
}

int main(void){
    /* distinct salts + master keys for the decoy and hidden volumes */
    uint8_t saltD[64], saltH[64], mkD[256], mkH[256];
    for(int i=0;i<64;i++){ saltD[i]=(uint8_t)(0x11*i+1); saltH[i]=(uint8_t)(0x07*i+0x80); }
    for(int i=0;i<256;i++){ mkD[i]=(uint8_t)(0xA5^i); mkH[i]=(uint8_t)(0x3C+i); }

    const char *pwDecoy="decoy-password", *pwHidden="hidden-password", *pwWrong="not-the-password";

    uint8_t hdrDecoy[512], hdrHidden[512];
    vc_create_header(pwDecoy,  saltD, mkD, 0,          1u<<30, 0x20000, 0x40000000, hdrDecoy);
    vc_create_header(pwHidden, saltH, mkH, 256u<<20,   1u<<30, 0x20000, 0x10000000, hdrHidden);

    uint8_t rec[256];

    /* 1. correct passwords recover the right master keys */
    ok("decoy opens with decoy password",
       vc_open_header(pwDecoy, hdrDecoy, rec)==0 && memcmp(rec, mkD, 256)==0);
    ok("hidden opens with hidden password",
       vc_open_header(pwHidden, hdrHidden, rec)==0 && memcmp(rec, mkH, 256)==0);

    /* 2. wrong password is rejected (VERA/CRC mismatch) */
    ok("decoy rejects a wrong password",  vc_open_header(pwWrong, hdrDecoy, rec)!=0);

    /* 3. deniability: each password opens ONLY its own header */
    ok("decoy password does NOT open the hidden header",
       vc_open_header(pwDecoy, hdrHidden, rec)!=0);
    ok("hidden password does NOT open the decoy header",
       vc_open_header(pwHidden, hdrDecoy, rec)!=0);

    /* 4. the magic is encrypted — no "VERA" plaintext tell in the on-disk header */
    ok("decoy header has no plaintext VERA magic", memcmp(hdrDecoy+64, "VERA", 4)!=0);
    ok("hidden header has no plaintext VERA magic", memcmp(hdrHidden+64, "VERA", 4)!=0);

    /* 5. the two headers' ciphertext differ (distinct salts/keys → indistinguishable) */
    ok("decoy and hidden headers are distinct", memcmp(hdrDecoy, hdrHidden, 512)!=0);

    printf("VC-HEADER: %d passed, %d failed -> %s\n", pass, fail, fail?"FAIL":"ALL PASS");
    return fail?1:0;
}
