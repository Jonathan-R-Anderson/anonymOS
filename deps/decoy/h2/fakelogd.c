/* deps/decoy/h2 — the Linux fake-log generator (roadmap/INSTALLER.md §H2).
 *
 * Runs inside the decoy Linux: drives the §G engine+renderer and writes deterministic,
 * password-keyed fake history into /var/log, routing each subsystem to the right file
 * (auth events -> auth.log, audit -> audit.log, the rest -> syslog), time-ordered. This
 * is the "backfill" pass (write years of history on first boot); a real install also runs
 * it as a low-rate daemon to keep the live tail moving. §H4 conceals this program; §H3
 * hides the hidden volume's space from the decoy.
 *
 *   usage: fakelogd [password] [--root DIR] [--start-day N] [--days D]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <utime.h>
#include "decoy.h"
#include "decoy_render.h"

static int by_time(const void *a, const void *b){
    uint64_t x=((const DecoyEvent*)a)->time_sec, y=((const DecoyEvent*)b)->time_sec;
    return x<y?-1:x>y?1:0;
}

int main(int argc, char **argv){
    const char *pw="decoy-password", *root=".";
    unsigned long days=0;            /* 0 -> seed-derived age (6–18 months) */
    long now=0;                      /* 0 -> real time */
    for (int i=1;i<argc;i++){
        if      (!strcmp(argv[i],"--root") && i+1<argc) root=argv[++i];
        else if (!strcmp(argv[i],"--now")  && i+1<argc) now=strtol(argv[++i],0,10);
        else if (!strcmp(argv[i],"--days") && i+1<argc) days=strtoul(argv[++i],0,10);
        else if (argv[i][0] != '-')                     pw=argv[i];
    }
    uint64_t seed = decoy_seed(pw);
    if (now == 0) now = (long)time(0);
    /* §G1.1/F3 seed-anchored virtual clock: the decoy was "installed" a seed-derived
     * 6–18 months ago and has been running since; history runs up to `now`. */
    if (days == 0) days = 180 + (unsigned long)(seed % 360);
    uint64_t now_bin   = (uint64_t)now / 3600;
    uint64_t start_bin = now_bin - days * 24;

    char dir[1024], path[1024];
    snprintf(dir,sizeof dir,"%s/var",root);     mkdir(dir,0755);
    snprintf(dir,sizeof dir,"%s/var/log",root); mkdir(dir,0755);
    /* truncate-and-write so re-running reproduces byte-identical files (determinism) */
    /* Alpine has no auditd, so no audit.log (its presence would be a tell, §E7/F1) —
     * audit/su events route to auth.log alongside ssh/sudo. */
    snprintf(path,sizeof path,"%s/var/log/messages",  root); FILE *fsys =fopen(path,"wb");
    snprintf(path,sizeof path,"%s/var/log/auth.log",   root); FILE *fauth=fopen(path,"wb");
    if (!fsys||!fauth){ fprintf(stderr,"fakelogd: cannot open log files under %s\n",root); return 2; }

    long total=0, na=0, ns=0;
    static DecoyEvent ev[1<<16];
    char line[512];
    for (uint64_t b0=start_bin; b0<now_bin; b0+=24){
        int n=0;
        for (int s=0;s<DECOY_NSUB && n<(1<<16)-64;s++) n += decoy_events(seed,s,b0,24,ev+n,(1<<16)-64-n);
        qsort(ev,n,sizeof ev[0],by_time);
        for (int i=0;i<n;i++){
            if (ev[i].time_sec > (uint64_t)now) continue;     /* never log into the future */
            int len=decoy_render(seed,&ev[i],line,sizeof line-2);
            line[len++]='\n'; line[len]=0;
            int sub=ev[i].subsys;
            FILE *f = (sub==DECOY_USER||sub==DECOY_SEC||sub==DECOY_AUDIT)?fauth : fsys;
            fputs(line,f); total++;
            if (f==fauth) na++; else ns++;
        }
    }
    fclose(fsys); fclose(fauth);
    /* coherent mtimes: the logs were last written ~now (consistent with the timeline) */
    struct utimbuf ut = { .actime = now, .modtime = now };
    snprintf(path,sizeof path,"%s/var/log/messages",root); utime(path,&ut);
    snprintf(path,sizeof path,"%s/var/log/auth.log",root);  utime(path,&ut);
    printf("[fakelogd] backfilled %ld lines, %lu days ending %ld -> %s/var/log/"
           " (messages=%ld auth.log=%ld)\n", total, days, now, root, ns, na);
    return 0;
}
