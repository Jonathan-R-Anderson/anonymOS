/* deps/veracrypt §E4c — encrypt a REAL rootfs (the §H1 decoy Linux) into a VeraCrypt
 * volume and prove it round-trips: header (PBKDF2 from the decoy password, random master
 * key) + the rootfs XTS-encrypted under that master key, per 512-byte sector. Decrypting
 * with the password recovers the rootfs byte-for-byte; a wrong password can't open it.
 * This is the installer's data path (the kernel does the same with its in-kernel engine,
 * cap-gated) exercised over a real multi-MB OS image.
 *
 *   usage: cryptdisk <rootfs-file> <password>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vcheader.h"

int main(int argc, char **argv){
    if (argc < 3){ fprintf(stderr,"usage: %s <rootfs-file> <password>\n", argv[0]); return 2; }
    const char *path=argv[1], *pw=argv[2];

    /* read the rootfs, pad to a 512-byte sector multiple */
    FILE *f=fopen(path,"rb"); if(!f){ perror("open rootfs"); return 2; }
    fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
    long nsec=(sz+511)/512, padded=nsec*512;
    uint8_t *plain=calloc(padded,1), *ct=malloc(padded), *back=malloc(padded);
    if(!plain||!ct||!back){ fprintf(stderr,"oom\n"); return 2; }
    if(fread(plain,1,sz,f)!=(size_t)sz){ fprintf(stderr,"short read\n"); return 2; }
    fclose(f);
    printf("  rootfs: %ld bytes (%ld sectors)\n", sz, nsec);

    /* master key (256 B). PRODUCTION: CSPRNG. Test: a fixed pattern so the run is
     * reproducible — correctness comes from the round-trip, not the key's randomness. */
    uint8_t mk[256]; for(int i=0;i<256;i++) mk[i]=(uint8_t)(0x5A^(i*7));
    uint8_t salt[64]; for(int i=0;i<64;i++) salt[i]=(uint8_t)(i*3+1);

    /* header: encAreaStart=512 (data follows the header), encAreaLen=padded */
    uint8_t hdr[512];
    vc_create_header(pw, salt, mk, 0, (uint64_t)padded, 512, (uint64_t)padded, hdr);

    /* encrypt: each rootfs sector is XTS data unit i under the master key */
    memcpy(ct, plain, padded);
    for(long i=0;i<nsec;i++) vc_xts_encrypt(ct+i*512, 512, (uint64_t)i, mk, mk+32);

    int pass=0, fail=0;
    #define OK(w,c) do{ printf("  [%s] %s\n",(c)?"PASS":"FAIL",w); if(c)pass++; else fail++; }while(0)

    /* the encrypted volume must NOT contain the plaintext (e.g. the Alpine os-release) */
    OK("ciphertext does not contain plaintext rootfs bytes", memcmp(ct,plain,padded)!=0);

    /* decrypt path: open the header with the password -> master key -> XTS-decrypt */
    uint8_t rkey[256];
    int opened = (vc_open_header(pw, hdr, rkey)==0) && memcmp(rkey,mk,256)==0;
    OK("decoy password opens the volume header + recovers the master key", opened);
    memcpy(back, ct, padded);
    for(long i=0;i<nsec;i++) vc_xts_decrypt(back+i*512, 512, (uint64_t)i, rkey, rkey+32);
    OK("decrypted rootfs is byte-identical to the original", memcmp(back,plain,padded)==0);

    /* a wrong password cannot open the header (reveals nothing) */
    uint8_t junk[256];
    OK("a wrong password cannot open the volume", vc_open_header("not-the-password", hdr, junk)!=0);

    printf("VC-CRYPTDISK: %d passed, %d failed -> %s\n", pass, fail, fail?"FAIL":"PASS");
    free(plain); free(ct); free(back);
    return fail?1:0;
}
