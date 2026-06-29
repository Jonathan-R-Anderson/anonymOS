/* deps/decoy §H3 — validate the "protect hidden volume" filter: a coerced examiner inside
 * the decoy, using the outer volume's free space, can neither corrupt nor detect the hidden
 * volume living in it. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hidden_protect.h"
#define SEC 512

static int pass=0, fail=0;
static void ok(const char *w,int c){ printf("  [%s] %s\n",c?"PASS":"FAIL",w); if(c)pass++; else fail++; }

int main(int argc, char **argv){
    const char *path = argc>1?argv[1]:"h3disk.img";
    const uint64_t DISK=8192, HSTART=2000, HSEC=1000;   /* hidden volume at sectors 2000..3000 */

    FILE *u=fopen("/dev/urandom","rb"); FILE *d=fopen(path,"w+b");
    if(!u||!d){ perror("open"); return 2; }
    uint8_t sec[SEC];
    for(uint64_t i=0;i<DISK;i++){ if(fread(sec,1,SEC,u)!=SEC){return 2;} fwrite(sec,1,SEC,d); }

    /* lay the hidden volume's data (in reality XTS ciphertext; here a pattern to detect corruption) */
    uint8_t *horig=malloc(HSEC*SEC), *hnow=malloc(HSEC*SEC);
    for(uint64_t i=0;i<HSEC;i++) for(int j=0;j<SEC;j++) horig[i*SEC+j]=(uint8_t)(0x5A ^ (i*7+j));
    fseek(d,HSTART*SEC,SEEK_SET); fwrite(horig,1,HSEC*SEC,d); fflush(d);

    HiddenProtect hp; hp_init(&hp,HSTART,HSEC);

    /* simulate a busy decoy: write decoy data across the WHOLE outer volume in 256-sec chunks */
    static uint8_t chunk[256*SEC]; memset(chunk,0xCC,sizeof chunk);
    int applied=0, refused=0, expect_refused=0;
    for(uint64_t lba=0; lba+256<=DISK; lba+=256){
        if (lba < HSTART+HSEC && HSTART < lba+256) expect_refused++;   /* overlaps hidden */
        if (hp_write(&hp,d,lba,256,chunk)==0) applied++; else refused++;
    }
    fflush(d);

    /* 1. the hidden volume is byte-intact after all the decoy activity */
    fseek(d,HSTART*SEC,SEEK_SET); fread(hnow,1,HSEC*SEC,d);
    ok("decoy activity did NOT corrupt the hidden volume", memcmp(horig,hnow,HSEC*SEC)==0);

    /* 2. exactly the writes overlapping the hidden region were refused (the rest applied) */
    ok("the protect filter refused exactly the hidden-overlapping writes",
       refused==expect_refused && refused>0 && hp.writes_refused==refused && applied>0);

    /* 3. decoy writes fully OUTSIDE the hidden region landed (the decoy really uses its disk) */
    uint8_t g[SEC]; fseek(d,100*SEC,SEEK_SET); fread(g,1,SEC,d);
    ok("decoy writes outside the hidden region are applied (usable disk)", g[0]==0xCC);

    /* 4. reads pass through — the hidden OS (no protection) accesses its volume normally;
     *    to the decoy the same bytes are just random/ciphertext (indistinguishable, see F2) */
    uint8_t rd[SEC]; hp_read(&hp,d,HSTART,1,rd);
    ok("reads of the hidden region pass through (random to the decoy, real to the hidden OS)",
       memcmp(rd,horig,SEC)==0);

    fclose(d); fclose(u); remove(path);
    printf("VC-H3: %d passed, %d failed -> %s\n", pass, fail, fail?"FAIL":"PASS");
    return fail?1:0;
}
