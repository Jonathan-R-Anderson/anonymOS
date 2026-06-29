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
#include "decoy.h"
#include "decoy_render.h"

static int by_time(const void *a, const void *b){
    uint64_t x=((const DecoyEvent*)a)->time_sec, y=((const DecoyEvent*)b)->time_sec;
    return x<y?-1:x>y?1:0;
}

int main(int argc, char **argv){
    const char *pw="decoy-password", *root=".";
    unsigned long start_day=0, days=30;
    for (int i=1;i<argc;i++){
        if      (!strcmp(argv[i],"--root")      && i+1<argc) root=argv[++i];
        else if (!strcmp(argv[i],"--start-day") && i+1<argc) start_day=strtoul(argv[++i],0,10);
        else if (!strcmp(argv[i],"--days")      && i+1<argc) days=strtoul(argv[++i],0,10);
        else if (argv[i][0] != '-')                          pw=argv[i];
    }
    uint64_t seed = decoy_seed(pw);

    char dir[1024], path[1024];
    snprintf(dir,sizeof dir,"%s/var",root);     mkdir(dir,0755);
    snprintf(dir,sizeof dir,"%s/var/log",root); mkdir(dir,0755);
    /* truncate-and-write so re-running reproduces byte-identical files (determinism) */
    snprintf(path,sizeof path,"%s/var/log/syslog",   root); FILE *fsys =fopen(path,"wb");
    snprintf(path,sizeof path,"%s/var/log/auth.log", root); FILE *fauth=fopen(path,"wb");
    snprintf(path,sizeof path,"%s/var/log/audit.log",root); FILE *faud =fopen(path,"wb");
    if (!fsys||!fauth||!faud){ fprintf(stderr,"fakelogd: cannot open log files under %s\n",root); return 2; }

    long total=0, na=0, ns=0;
    static DecoyEvent ev[1<<16];
    char line[512];
    for (unsigned long d=0; d<days; d++){
        uint64_t bin0=(start_day+d)*24;
        int n=0;
        for (int s=0;s<DECOY_NSUB && n<(1<<16)-64;s++) n += decoy_events(seed,s,bin0,24,ev+n,(1<<16)-64-n);
        qsort(ev,n,sizeof ev[0],by_time);
        for (int i=0;i<n;i++){
            int len=decoy_render(seed,&ev[i],line,sizeof line-2);
            line[len++]='\n'; line[len]=0;
            int sub=ev[i].subsys;
            FILE *f = (sub==DECOY_USER||sub==DECOY_SEC)?fauth : (sub==DECOY_AUDIT)?faud : fsys;
            fputs(line,f); total++;
            if (f==fauth) na++; else if (f==fsys) ns++;
        }
    }
    fclose(fsys); fclose(fauth); fclose(faud);
    printf("[fakelogd] backfilled %ld lines over %lu days (start day %lu) -> %s/var/log/"
           " (syslog=%ld auth.log=%ld)\n", total, days, start_day, root, ns, na);
    return 0;
}
