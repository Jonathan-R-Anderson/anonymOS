/* deps/decoy — realistic log-line renderer (§G G3.3). See decoy_render.h. */
#include "decoy_render.h"

/* universe epoch: 2024-01-01 00:00:00 UTC (Unix seconds). The decoy's history is anchored
 * here; a real install offsets this per-seed (the seed-anchored virtual clock, §G1.1). */
#define EPOCH_BASE 1704067200ULL

/* ── tiny self-contained string builder (no libc) ── */
typedef struct { char *p; int n, max; } SB;
static void sc(SB *b, char c){ if(b->n < b->max-1) b->p[b->n++] = c; }
static void ss(SB *b, const char *s){ while(*s) sc(b,*s++); }
static void su(SB *b, uint64_t v){ char t[20]; int i=0; if(!v){sc(b,'0');return;} while(v){t[i++]='0'+v%10; v/=10;} while(i) sc(b,t[--i]); }
static void s2(SB *b, uint32_t v){ sc(b,'0'+(v/10)%10); sc(b,'0'+v%10); }

static const char *MON[12]={"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
/* civil date from days-since-1970 (Hinnant) */
static void civil(int64_t z, int *y, int *m, int *d){
    z += 719468;
    int64_t era = (z>=0?z:z-146096)/146097;
    uint64_t doe = (uint64_t)(z - era*146097);
    uint64_t yoe = (doe - doe/1460 + doe/36524 - doe/146096)/365;
    uint64_t doy = doe - (365*yoe + yoe/4 - yoe/100);
    uint64_t mp = (5*doy+2)/153;
    *d = (int)(doy - (153*mp+2)/5 + 1);
    *m = (int)(mp<10?mp+3:mp-9);
    *y = (int)(yoe + (uint64_t)era*400 + (mp>=10));
}
static void stamp(SB *b, uint64_t time_sec){
    uint64_t u = EPOCH_BASE + time_sec;
    int y,mo,d; civil((int64_t)(u/86400), &y,&mo,&d);
    uint32_t s = (uint32_t)(u%86400);
    ss(b, MON[mo-1]); sc(b,' ');
    if(d<10) sc(b,' '); su(b,(uint64_t)d); sc(b,' ');
    s2(b, s/3600); sc(b,':'); s2(b,(s/60)%60); sc(b,':'); s2(b, s%60);
}

/* deterministic pools — keep small + plausible */
static const char *USERS[] = {"root","alice","bob","www-data","postfix","backup","deploy","carol"};
static const char *HOSTS[] = {"workstation","nimbus","orion","helix"};
static const char *PROCS[] = {"systemd","cron","sshd","CRON","kernel","dbus-daemon","NetworkManager","gnome-shell"};
static const char *SVCS[]  = {"ssh.service","cron.service","nginx.service","systemd-logind.service","NetworkManager.service","apt-daily.service"};
#define PICK(arr, h) arr[(h) % (sizeof(arr)/sizeof(arr[0]))]

int decoy_render(uint64_t seed, const DecoyEvent *e, char *out, int max){
    SB b = { out, 0, max };
    uint32_t h = e->detail;
    uint32_t pid = 300 + (h % 32000);
    const char *host = PICK(HOSTS, (uint32_t)seed);

    stamp(&b, e->time_sec); sc(&b,' '); ss(&b,host); sc(&b,' ');

    switch (e->subsys){
    case DECOY_USER: {
        const char *u = PICK(USERS, h);
        ss(&b,"sshd["); su(&b,pid); ss(&b,"]: ");
        if (h & 1){ ss(&b,"Accepted publickey for "); ss(&b,u); ss(&b," from 10.0."); su(&b,h%6); sc(&b,'.'); su(&b,(h>>4)%254+1); ss(&b," port "); su(&b,40000+(h%20000)); ss(&b," ssh2"); }
        else      { ss(&b,"pam_unix(sshd:session): session opened for user "); ss(&b,u); ss(&b," by (uid=0)"); }
        break; }
    case DECOY_PROC: {
        const char *p = PICK(PROCS, h);
        ss(&b,p); sc(&b,'['); su(&b,pid); ss(&b,"]: ");
        ss(&b,"("); ss(&b,PICK(USERS,h>>3)); ss(&b,") CMD (run-parts /etc/cron."); ss(&b, (h&2)?"hourly":"daily"); sc(&b,')');
        break; }
    case DECOY_SVC: {
        ss(&b,"systemd[1]: ");
        ss(&b,(h&1)?"Started ":"Stopped "); ss(&b,PICK(SVCS,h));
        break; }
    case DECOY_NET: {
        ss(&b,"NetworkManager["); su(&b,pid); ss(&b,"]: ");
        ss(&b,"<info> dhcp4: address 192.168."); su(&b,h%4); sc(&b,'.'); su(&b,(h>>3)%254+1);
        break; }
    case DECOY_SEC: {
        const char *u = PICK(USERS, h);
        ss(&b,"sudo["); su(&b,pid); ss(&b,"]: ");
        if (h & 3){ ss(&b,u); ss(&b," : TTY=pts/0 ; PWD=/home/"); ss(&b,u); ss(&b," ; USER=root ; COMMAND=/usr/bin/apt update"); }
        else      { ss(&b,"pam_unix(sudo:auth): authentication failure; logname="); ss(&b,u); ss(&b," uid=1000"); }
        break; }
    case DECOY_FS: {
        ss(&b,"kernel: ["); su(&b, e->time_sec); ss(&b,".0] EXT4-fs (sda"); su(&b,2+(h%2)); ss(&b,"): mounted filesystem with ordered data mode");
        break; }
    case DECOY_AUDIT: {
        ss(&b,"audit["); su(&b,pid); ss(&b,"]: USER_ACCT pid="); su(&b,pid); ss(&b," uid=1000 msg='op=PAM:accounting acct=\""); ss(&b,PICK(USERS,h)); ss(&b,"\" res=success'");
        break; }
    default: { /* DECOY_LOG */
        ss(&b,PICK(PROCS,h)); sc(&b,'['); su(&b,pid); ss(&b,"]: ");
        static const char *MSG[] = {"Reloaded configuration","Time has been changed","Reached target Multi-User System","Starting Daily apt upgrade","gc: reclaimed 128 objects","cleaned up 3 stale sockets"};
        ss(&b,PICK(MSG,h));
        break; }
    }
    out[b.n] = 0;
    return b.n;
}
