/* deps/veracrypt §E7/F2 — assemble a FULL deniable install image: encrypt the entire
 * system partition (decoy rootfs + random pad to fill) and random-fill EVERY sector of the
 * outer partition (CSPRNG), with the decoy/outer/hidden headers overlaid. The point is an
 * entropy map with no tells: the encrypted partitions are uniformly high-entropy — no zeros
 * betraying "no real data", no discontinuity at the hidden-volume boundary.
 *
 *   usage: mkinstall <disk.img> <rootfs> <decoy-pw> <sysLBA> <sysSectors> <outerLBA> <outerSectors>
 *   (the GPT + ESP are laid down by the Makefile; this fills the two encrypted partitions)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vcheader.h"
#define SEC 512

static FILE *g_urand;
static void fill_random(FILE *d, long lba, long nsec){
    unsigned char buf[1<<16];
    long left = nsec*SEC;
    fseek(d, lba*SEC, SEEK_SET);
    while (left > 0){
        long c = left < (long)sizeof buf ? left : (long)sizeof buf;
        if (fread(buf,1,c,g_urand)!=(size_t)c){ perror("urandom"); exit(2); }
        fwrite(buf,1,c,d); left -= c;
    }
}
static void rnd(void *p, int n){ if(fread(p,1,n,g_urand)!=(size_t)n){ perror("urandom"); exit(2); } }

/* write a header built from random salt+masterkey at `lba`; return the master key */
static void put_header(FILE *d, long lba, const char *pw, uint64_t hiddenSz, uint64_t volSz, uint8_t mkOut[256]){
    uint8_t mk[256], salt[64], hdr[512];
    rnd(mk,256); rnd(salt,64);
    vc_create_header(pw, salt, mk, hiddenSz, volSz, 512, volSz, hdr);
    fseek(d, lba*SEC, SEEK_SET); fwrite(hdr,1,SEC,d);
    if (mkOut) memcpy(mkOut, mk, 256);
}

int main(int argc, char **argv){
    if (argc < 8){ fprintf(stderr,"usage: %s disk rootfs decoy-pw sysLBA sysSec outerLBA outerSec\n",argv[0]); return 2; }
    const char *disk=argv[1], *rootfs=argv[2], *pw=argv[3];
    long sysLBA=atol(argv[4]), sysSec=atol(argv[5]), outerLBA=atol(argv[6]), outerSec=atol(argv[7]);

    FILE *d=fopen(disk,"r+b"); if(!d){ perror("disk"); return 2; }
    g_urand=fopen("/dev/urandom","rb"); if(!g_urand){ perror("urandom"); return 2; }

    /* 1. random-fill BOTH encrypted partitions entirely (CSPRNG) — no zeros anywhere */
    fill_random(d, sysLBA, sysSec);
    fill_random(d, outerLBA, outerSec);

    /* 2. decoy system header + the rootfs XTS-encrypted over the front (tail stays random) */
    uint8_t mk[256];
    put_header(d, sysLBA, pw, 0, (uint64_t)sysSec*SEC, mk);
    FILE *r=fopen(rootfs,"rb"); if(!r){ perror("rootfs"); return 2; }
    fseek(r,0,SEEK_END); long rsz=ftell(r); fseek(r,0,SEEK_SET);
    long rsec=(rsz+SEC-1)/SEC;
    if (rsec > sysSec-1){ fprintf(stderr,"rootfs too big for system partition\n"); return 2; }
    uint8_t sec[SEC];
    for (long i=0;i<rsec;i++){
        memset(sec,0,SEC);
        fread(sec,1,(i==rsec-1 && rsz%SEC)? (rsz%SEC):SEC, r);
        vc_xts_encrypt(sec, SEC, (uint64_t)i, mk, mk+32);
        fseek(d,(sysLBA+1+i)*SEC,SEEK_SET); fwrite(sec,1,SEC,d);
    }
    fclose(r);

    /* 3. outer + hidden headers overlaid on the random outer partition */
    put_header(d, outerLBA,       "outer-password",  (uint64_t)256<<20, (uint64_t)outerSec*SEC, 0);
    put_header(d, outerLBA + 128, "hidden-password", 0,                 (uint64_t)256<<20,       0);

    fclose(d); fclose(g_urand);
    printf("[mkinstall] filled system(%ld sec, rootfs=%ld) + outer(%ld sec) with ciphertext/random; headers written\n",
           sysSec, rsec, outerSec);
    return 0;
}
