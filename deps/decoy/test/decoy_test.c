/* deps/decoy §G — validate the deterministic decoy generator: same password -> identical
 * universe, different password -> different universe, naturally bursty (not uniform),
 * subsystems correlate, and years-of-history stays cheap. */
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "decoy.h"

static int pass=0, fail=0;
static void ok(const char *w,int c){ printf("  [%s] %s\n",c?"PASS":"FAIL",w); if(c)pass++; else fail++; }

/* per-hour event count for a subsystem */
static int bin_count(uint64_t seed,int sub,uint64_t bin){ DecoyEvent e[64]; return decoy_events(seed,sub,bin,1,e,64); }

int main(void){
    uint64_t sD = decoy_seed("decoy-password");
    uint64_t sH = decoy_seed("hidden-password");
    uint64_t sD2= decoy_seed("decoy-password");        /* re-derive */
    uint64_t sTypo = decoy_seed("decoy-passwerd");      /* 1-char change */
    const uint64_t N = 24*365;                          /* one year of hours */

    /* 1. determinism: same password -> identical seed + identical event stream */
    DecoyEvent a[4096], b[4096];
    int na = decoy_events(sD, DECOY_LOG, 1000, 200, a, 4096);
    int nb = decoy_events(sD2,DECOY_LOG, 1000, 200, b, 4096);
    ok("same password -> identical universe",
       sD==sD2 && na==nb && memcmp(a,b,(size_t)na*sizeof(DecoyEvent))==0);

    /* 2. password-sensitivity: different (and 1-char-different) passwords diverge */
    int nh = decoy_events(sH, DECOY_LOG, 1000, 200, b, 4096);
    ok("different password -> different universe", sD!=sH && !(na==nh && memcmp(a,b,(size_t)na*sizeof(DecoyEvent))==0));
    ok("a 1-char typo yields a totally different seed", sD!=sTypo && sH!=sTypo);

    /* 3. burstiness: per-hour counts are overdispersed (Fano = var/mean > 1), not uniform */
    double sum=0, sumsq=0; long total=0;
    for(uint64_t i=0;i<N;i++){ int c=bin_count(sD,DECOY_LOG,i); sum+=c; sumsq+=(double)c*c; total+=c; }
    double mean=sum/N, var=sumsq/N-mean*mean, fano=var/mean;
    printf("    LOG: %ld events/yr, mean=%.2f/hr, Fano=%.2f\n", total, mean, fano);
    ok("activity is bursty (Fano factor > 1.2)", fano>1.2 && total>1000);

    /* 4. correlation: subsystems share the intensity field -> counts rise/fall together */
    double sl=0,sn=0,sll=0,snn=0,sln=0; uint64_t M=24*30;
    for(uint64_t i=0;i<M;i++){ double l=bin_count(sD,DECOY_LOG,i), n=bin_count(sD,DECOY_NET,i);
        sl+=l; sn+=n; sll+=l*l; snn+=n*n; sln+=l*n; }
    double cov=sln/M-(sl/M)*(sn/M), vl=sll/M-(sl/M)*(sl/M), vn=snn/M-(sn/M)*(sn/M);
    double r=cov/sqrt(vl*vn);
    printf("    LOG vs NET hourly-count correlation r=%.2f\n", r);
    ok("subsystems are correlated (r > 0.3)", r>0.3);

    /* 5. scale: a window 10 years out is cheap + still deterministic */
    DecoyEvent f1[256], f2[256];
    uint64_t far = 24ULL*365*10;
    int nf1 = decoy_events(sD, DECOY_PROC, far, 24, f1, 256);
    int nf2 = decoy_events(sD, DECOY_PROC, far, 24, f2, 256);
    ok("history 10 years out is deterministic + O(window)", nf1==nf2 && memcmp(f1,f2,(size_t)nf1*sizeof(DecoyEvent))==0);

    printf("DECOY-ENGINE: %d passed, %d failed -> %s\n", pass, fail, fail?"FAIL":"PASS");
    return fail?1:0;
}
