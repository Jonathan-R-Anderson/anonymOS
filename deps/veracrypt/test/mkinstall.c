/* deps/veracrypt §E7/F2 + §E5d — assemble a FULL deniable install image: encrypt the entire
 * system partition and random-fill EVERY sector of the outer partition (CSPRNG), with the
 * decoy/outer/hidden headers overlaid, AND write each OS's XTS-encrypted bootloader payload so
 * the §E5 pre-boot loader can decrypt-and-boot it. The point is an entropy map with no tells:
 * the encrypted partitions are uniformly high-entropy — no zeros betraying "no real data", no
 * discontinuity at the hidden-volume boundary — while a correct password still yields a bootable
 * OS.
 *
 *   usage: mkinstall <disk.img> <payload.efi> <decoy-pw> <sysLBA> <sysSectors> <outerLBA> <outerSectors>
 *   (the GPT + ESP are laid down by the Makefile; this fills the two encrypted partitions.
 *    <payload.efi> is the PE bootloader booted for BOTH the decoy and the hidden OS in this
 *    proof — in production the two differ, e.g. an Alpine EFI-stub kernel vs the EpinAnonymOS
 *    loader; the mechanism this validates is identical either way.)
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
static void put_le64(uint8_t *p, uint64_t v){ for(int i=0;i<8;i++) p[i]=(uint8_t)(v>>(8*i)); }

/* write a header built from random salt+masterkey at `lba`; return the master key */
static void put_header(FILE *d, long lba, const char *pw, uint64_t hiddenSz, uint64_t volSz, uint8_t mkOut[256]){
    uint8_t mk[256], salt[64], hdr[512];
    rnd(mk,256); rnd(salt,64);
    vc_create_header(pw, salt, mk, hiddenSz, volSz, 512, volSz, hdr);
    fseek(d, lba*SEC, SEEK_SET); fwrite(hdr,1,SEC,d);
    if (mkOut) memcpy(mkOut, mk, 256);
}

/* §E5d — write one OS's bootable payload as the pre-boot loader expects to decrypt it:
 *   region_lba+0            : boot descriptor  (magic "ANOSBOOT" + u64 LE byte-length), unit 0
 *   region_lba+1 .. +nsec   : the PE payload,  units 1.. .
 * Every sector is XTS-encrypted with the volume master key `mk` (data=mk[0..32), tweak=mk[32..64)).
 * Unit numbers and key halves MUST match deps/veracrypt/efi/efi_main.c:decrypt_and_boot(). */
static long write_bootloader(FILE *d, long region_lba, long region_cap_sec, const uint8_t *payload, long plen, const uint8_t *mk){
    long psec = (plen + SEC - 1)/SEC;
    if (1 + psec > region_cap_sec){ fprintf(stderr,"payload too big for region (%ld > %ld sectors)\n", 1+psec, region_cap_sec); exit(2); }
    uint8_t sec[SEC];
    /* descriptor at unit 0 */
    memset(sec,0,SEC);
    memcpy(sec, "ANOSBOOT", 8);
    put_le64(sec+8, (uint64_t)plen);
    vc_xts_encrypt(sec, SEC, 0, mk, mk+32);
    fseek(d, region_lba*SEC, SEEK_SET); fwrite(sec,1,SEC,d);
    /* payload at units 1.. */
    for (long i=0;i<psec;i++){
        long chunk = (i==psec-1 && plen%SEC)? plen%SEC : SEC;
        memset(sec,0,SEC);
        memcpy(sec, payload + i*SEC, chunk);
        vc_xts_encrypt(sec, SEC, (uint64_t)(1+i), mk, mk+32);
        fseek(d, (region_lba+1+i)*SEC, SEEK_SET); fwrite(sec,1,SEC,d);
    }
    return psec;
}

/* §E5d/§H1 Level 2 — write an ALREADY-WRAPPED decoy region ([descriptor-v2][UKI][squashfs], from
 * wrap-decoy-payload.py) as the loader/init-crypt expect: byte 0 of the file lands at region_lba
 * (XTS unit 0), so each sector's unit = its offset from region_lba. Unlike write_bootloader this
 * adds NO descriptor of its own — the file already carries "ANOSBOOT"+uki_bytes+rootfs_sectors. */
static long write_wrapped(FILE *d, long region_lba, long region_cap_sec, const uint8_t *payload, long plen, const uint8_t *mk){
    long psec = (plen + SEC - 1)/SEC;
    if (psec > region_cap_sec){ fprintf(stderr,"wrapped payload too big (%ld > %ld sectors)\n", psec, region_cap_sec); exit(2); }
    uint8_t sec[SEC];
    for (long i=0;i<psec;i++){
        long chunk = (i==psec-1 && plen%SEC)? plen%SEC : SEC;
        memset(sec,0,SEC);
        memcpy(sec, payload + i*SEC, chunk);
        vc_xts_encrypt(sec, SEC, (uint64_t)i, mk, mk+32);   /* unit = offset from region_lba */
        fseek(d, (region_lba+i)*SEC, SEEK_SET); fwrite(sec,1,SEC,d);
    }
    return psec;
}

int main(int argc, char **argv){
    if (argc < 8){ fprintf(stderr,"usage: %s disk payload.efi decoy-pw sysLBA sysSec outerLBA outerSec [wrapped]\n",argv[0]); return 2; }
    /* "wrapped" mode: <payload.efi> is a pre-wrapped decoy region (descriptor+UKI+squashfs); write
     * it raw-XTS at sysLBA+1 for the DECOY and lay only the headers for outer/hidden (enough for
     * the loader's layout probe) — this proves the loader→UKI→init-crypt→dm-crypt→squashfs chain. */
    int wrapped = (argc >= 9 && strcmp(argv[8], "wrapped") == 0);
    const char *disk=argv[1], *payloadPath=argv[2], *pw=argv[3];
    long sysLBA=atol(argv[4]), sysSec=atol(argv[5]), outerLBA=atol(argv[6]), outerSec=atol(argv[7]);

    FILE *d=fopen(disk,"r+b"); if(!d){ perror("disk"); return 2; }
    g_urand=fopen("/dev/urandom","rb"); if(!g_urand){ perror("urandom"); return 2; }

    /* slurp the PE payload once (booted for both the decoy and the hidden OS in this proof) */
    FILE *pf=fopen(payloadPath,"rb"); if(!pf){ perror("payload"); return 2; }
    fseek(pf,0,SEEK_END); long plen=ftell(pf); fseek(pf,0,SEEK_SET);
    if (plen<=0){ fprintf(stderr,"empty payload\n"); return 2; }
    uint8_t *payload=malloc(plen);
    if (!payload || fread(payload,1,plen,pf)!=(size_t)plen){ perror("payload read"); return 2; }
    fclose(pf);

    /* 1. random-fill BOTH encrypted partitions entirely (CSPRNG) — no zeros anywhere */
    fill_random(d, sysLBA, sysSec);
    fill_random(d, outerLBA, outerSec);

    /* 2. decoy: system header @sysLBA + the decoy bootloader XTS-encrypted @sysLBA+1 (front),
     *    with the tail of the partition staying random. */
    uint8_t mkD[256];
    put_header(d, sysLBA, pw, 0, (uint64_t)sysSec*SEC, mkD);
    long dsec = wrapped ? write_wrapped   (d, sysLBA+1, sysSec-1, payload, plen, mkD)
                        : write_bootloader(d, sysLBA+1, sysSec-1, payload, plen, mkD);

    /* 3. outer + hidden headers overlaid on the random outer partition, then the hidden
     *    bootloader XTS-encrypted with the HIDDEN master key at hidden_lba+1 (= outerLBA+129),
     *    matching efi_main.c's HIDDEN route. (In wrapped mode we lay only the headers — the loader
     *    just needs them for its layout probe; the decoy chain is what this test exercises.) */
    put_header(d, outerLBA, "outer-password", (uint64_t)256<<20, (uint64_t)outerSec*SEC, 0);
    uint8_t mkH[256];
    put_header(d, outerLBA + 128, "hidden-password", 0, (uint64_t)256<<20, mkH);
    long hsec = wrapped ? 0 : write_bootloader(d, outerLBA+129, outerSec-129, payload, plen, mkH);

    fclose(d); fclose(g_urand); free(payload);
    printf("[mkinstall] system(%ld sec) + outer(%ld sec) filled with ciphertext/random; headers written; "
           "decoy bootloader=%ld sec @%ld, hidden bootloader=%ld sec @%ld (payload %ld bytes)\n",
           sysSec, outerSec, dsec, sysLBA+1, hsec, outerLBA+129, plen);
    return 0;
}
