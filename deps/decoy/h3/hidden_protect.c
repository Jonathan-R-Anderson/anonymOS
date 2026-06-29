/* deps/decoy/h3 — "protect hidden volume" block filter (§H3). See hidden_protect.h. */
#include "hidden_protect.h"
#define SEC 512

void hp_init(HiddenProtect *hp, uint64_t hidden_lba, uint64_t hidden_sectors){
    hp->hidden_lba = hidden_lba; hp->hidden_sectors = hidden_sectors; hp->writes_refused = 0;
}

static int overlaps(const HiddenProtect *hp, uint64_t lba, uint64_t nsec){
    uint64_t a0=lba, a1=lba+nsec, h0=hp->hidden_lba, h1=hp->hidden_lba+hp->hidden_sectors;
    return a0 < h1 && h0 < a1;            /* [lba,lba+nsec) intersects [h0,h1) */
}

int hp_read(HiddenProtect *hp, FILE *dev, uint64_t lba, uint64_t nsec, void *buf){
    (void)hp;                             /* reads always pass through (random ⇒ deniable) */
    if (fseek(dev, (long)(lba*SEC), SEEK_SET)!=0) return -1;
    return fread(buf,1,nsec*SEC,dev)==nsec*SEC ? 0 : -1;
}

int hp_write(HiddenProtect *hp, FILE *dev, uint64_t lba, uint64_t nsec, const void *buf){
    if (overlaps(hp, lba, nsec)){ hp->writes_refused++; return -1; }   /* protect the hidden OS */
    if (fseek(dev, (long)(lba*SEC), SEEK_SET)!=0) return -1;
    return fwrite(buf,1,nsec*SEC,dev)==nsec*SEC ? 0 : -1;
}
