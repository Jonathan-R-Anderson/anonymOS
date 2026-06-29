/* deps/veracrypt — pre-boot authentication decision core (§E5). See preboot_auth.h. */
#include "preboot_auth.h"
#include "vcheader.h"
#include <string.h>

/* §G2.2 typo tolerance — fuzz the INPUT (the bounded model from deps/decoy/g2/dm.c); the
 * VeraCrypt header is the exact verifier. Mirrors deps/veracrypt/efi/efi_vc.c. */
static char swapcase(char c){ if(c>='a'&&c<='z')return c-32; if(c>='A'&&c<='Z')return c+32; return c; }
static int typo_candidates(const char *in, char out[][128], int max){
    int n=0, L=0; while(in[L]) L++;
    if (L>=128){ if(max>0){ memcpy(out[0],in,L+1); return 1; } return 0; }
    memcpy(out[n++], in, L+1);                                                          /* as-is */
    if(n<max){ for(int i=0;i<L;i++) out[n][i]=swapcase(in[i]); out[n][L]=0; n++; }       /* caps lock */
    if(L>0 && n<max){ memcpy(out[n],in,L+1); out[n][0]=swapcase(out[n][0]); n++; }       /* first char */
    for(int i=0;i+1<L && n<max;i++){ memcpy(out[n],in,L+1); char t=out[n][i]; out[n][i]=out[n][i+1]; out[n][i+1]=t; n++; } /* transpose */
    for(int i=0;i<L && n<max;i++){ int k=0; for(int j=0;j<L;j++) if(j!=i) out[n][k++]=in[j]; out[n][k]=0; n++; } /* delete */
    return n;
}

preboot_verdict preboot_authenticate(const char *password,
                                     const uint8_t decoyHeader[512],
                                     const uint8_t hiddenHeader[512],
                                     uint8_t outMasterKey[256]){
    char cand[64][128];
    int nc = typo_candidates(password, cand, 64);
    preboot_verdict v = PREBOOT_REJECT;
    /* No early-out: try every candidate against BOTH headers, so the work — and thus the
     * timing — is the same shape whether the password is decoy, hidden, a typo, or wrong:
     * a wrong password must be indistinguishable from "there is no hidden OS here". */
    for (int c=0;c<nc;c++){
        uint8_t kd[256], kh[256];
        int okd = (vc_open_header(cand[c], decoyHeader,  kd) == 0);
        int okh = (vc_open_header(cand[c], hiddenHeader, kh) == 0);
        if (okd && v==PREBOOT_REJECT){ memcpy(outMasterKey, kd, 256); v=PREBOOT_DECOY;  }
        if (okh && v==PREBOOT_REJECT){ memcpy(outMasterKey, kh, 256); v=PREBOOT_HIDDEN; }
    }
    return v;
}
