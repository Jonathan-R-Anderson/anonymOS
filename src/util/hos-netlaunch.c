/*
 * hos-netlaunch.c — H1b.3 LD_PRELOAD verification launcher (static-musl).
 *
 * Kernel-spawned processes get a fixed env (no LD_PRELOAD).  This tiny static wrapper is spawned
 * by the kernel, then execve()s the dynamic target with an envp that sets LD_PRELOAD=/libnshim.so
 * (execveTask snapshots a non-zero caller envp), so ld-musl injects the interposer.  It reports
 * before exec so we can tell it ran even if the exec/preload path fails.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "hos-net-proto.h"

static int wrf(int fd, const void *b, unsigned n){ unsigned p=0; while(p<n){ long r=write(fd,(const char*)b+p,n-p); if(r>0){p+=r;continue;} struct timespec t={0,2000000L}; nanosleep(&t,0);} return 1; }
static int rdf(int fd, void *b, unsigned n){ unsigned g=0; while(g<n){ long r=read(fd,(char*)b+g,n-g); if(r>0){g+=r;continue;} struct timespec t={0,2000000L}; nanosleep(&t,0);} return 1; }

static void report(const char *msg)
{
    int s = -1;
    for (int i = 0; i < 100; i++) {
        s = socket(AF_UNIX, SOCK_STREAM, 0);
        if (s >= 0) {
            struct sockaddr_un sa; memset(&sa,0,sizeof sa);
            sa.sun_family = AF_UNIX; strncpy(sa.sun_path, NSP_PATH, sizeof(sa.sun_path)-1);
            if (connect(s, (struct sockaddr*)&sa, sizeof sa) == 0) break;
            close(s);
        }
        s = -1;
        struct timespec t = {0, 100000000L}; nanosleep(&t, 0);
    }
    if (s < 0) return;
    nsp_req rq; memset(&rq,0,sizeof rq); rq.op = NSP_LOG; rq.buflen = (unsigned)strlen(msg);
    nsp_resp rs;
    if (wrf(s,&rq,sizeof rq) && (rq.buflen==0||wrf(s,msg,rq.buflen))) rdf(s,&rs,sizeof rs);
    close(s);
}

int main(void)
{
    /* H3: launch UNMODIFIED wpa_supplicant under the transparent shim.  Its nl80211/packet/inet
     * socket calls are routed by libnshim.so to the cap-gated provider -> the LKL's wlan0.
     * -dd = very verbose (goes to stderr -> console -> serial.log under QEMU).  In QEMU there is
     * no wlan0 (LKL drives the bochs GPU), so wpa inits the nl80211 driver via the shim and then
     * fails to find the interface — which still proves the shim carries wpa's full syscall
     * surface.  On the laptop (real AX210) this associates. */
    /* wpa needs a config file to add the interface.  Write a minimal one to the (writable) ramfs;
     * it survives our execve (it's a kernel fs object, not our process).  ctrl_interface lets NM
     * talk to wpa later.  A real network{} block (SSID/psk) is added for the laptop association. */
    int cf = open("/tmp/wpa.conf", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (cf >= 0) {
        const char *conf = "ctrl_interface=/run/wpa_supplicant\nupdate_config=1\n";
        (void)!write(cf, conf, strlen(conf));
        close(cf);
    }
    report("H3 launcher: exec /wpa_supplicant -i wlan0 -D nl80211 -c /tmp/wpa.conf -dd under LD_PRELOAD");
    char *argv[] = { "/wpa_supplicant", "-i", "wlan0", "-D", "nl80211", "-c", "/tmp/wpa.conf", "-dd", 0 };
    /* HOS_SHIM_LOG=1 makes libnshim report wpa's milestones via the provider (visible on the
     * laptop framebuffer, where wpa's own stderr is not mirrored). */
    char *envp[] = { "LD_PRELOAD=/libnshim.so", "HOS_SHIM_LOG=1", "PATH=/", "HOME=/", 0 };
    execve("/wpa_supplicant", argv, envp);
    report("H3 launcher: execve(/wpa_supplicant) FAILED (missing binary/interp/lib?)");
    return 1;
}
