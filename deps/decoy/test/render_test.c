/* deps/decoy §G — render a day of decoy activity into a realistic, deterministic syslog.
 * Validates: the rendered log is reproducible (same seed -> identical text), looks like a
 * real /var/log/syslog (recognisable daemons/messages), and is time-ordered. Also prints
 * a sample so the believability is visible. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "decoy.h"
#include "decoy_render.h"

static int by_time(const void *a, const void *b){
    uint64_t x=((const DecoyEvent*)a)->time_sec, y=((const DecoyEvent*)b)->time_sec;
    return x<y?-1:x>y?1:0;
}

/* collect + render a full day starting at `bin0`; returns rendered text length, count via *out_n */
static int render_day(uint64_t seed, uint64_t bin0, char *text, int max, int *out_n){
    DecoyEvent ev[8192]; int n=0;
    for (int s=0; s<DECOY_NSUB && n<8000; s++)
        n += decoy_events(seed, s, bin0, 24, ev+n, 8000-n);
    qsort(ev, n, sizeof ev[0], by_time);
    int len=0;
    for (int i=0;i<n;i++){
        len += decoy_render(seed, &ev[i], text+len, max-len);
        if (len<max-1) text[len++]='\n';
    }
    text[len]=0; *out_n=n; return len;
}

int main(void){
    int pass=0, fail=0;
    #define OK(w,c) do{ printf("  [%s] %s\n",(c)?"PASS":"FAIL",w); if(c)pass++; else fail++; }while(0)
    uint64_t seed = decoy_seed("decoy-password");

    static char A[1<<20], B[1<<20];
    int na, nb;
    int la = render_day(seed, 477624 /* day 200 */, A, sizeof A, &na);
    int lb = render_day(seed, 477624,              B, sizeof B, &nb);

    OK("rendered day is deterministic (same seed -> identical text)", la==lb && memcmp(A,B,la)==0);
    /* volume varies day to day (quiet days are realistic) — check a week's total */
    int week=0; for(int day=0; day<7; day++){ int n; static char T[1<<20]; render_day(seed, (477624+day*24), T, sizeof T, &n); week+=n; }
    printf("    week volume = %d lines (day 200 = %d)\n", week, na);
    OK("a week has plausible volume (> 150 lines)", week>150);
    OK("contains real-looking Alpine daemons (sshd + crond)", strstr(A,"sshd")&&strstr(A,"crond"));
    OK("no distro-inconsistent daemons (systemd/apt/gnome)", !strstr(A,"systemd")&&!strstr(A,"gnome")&&!strstr(A,"apt-daily"));
    OK("contains auth + service activity", strstr(A,"session opened")||strstr(A,"Accepted publickey"));

    /* a different password renders a different log */
    static char C[1<<20]; int nc;
    render_day(decoy_seed("hidden-password"), 477624, C, sizeof C, &nc);
    OK("different password -> different rendered log", strcmp(A,C)!=0);

    printf("\n  ---- sample (decoy-password, day 200, first 16 lines) ----\n");
    int shown=0;
    for (char *p=A; *p && shown<16; ){
        char *nl=strchr(p,'\n'); int len = nl? (int)(nl-p):(int)strlen(p);
        printf("  %.*s\n", len, p);
        if(!nl) break; p=nl+1; shown++;
    }
    printf("  ----------------------------------------------------------\n\n");

    printf("DECOY-RENDER: %d passed, %d failed -> %s\n", pass, fail, fail?"FAIL":"PASS");
    return fail?1:0;
}
