/* deps/decoy/h3 — full-disk illusion + "protect hidden volume" filter (§H3). See the header. */
#include "hidden_protect.h"
#define SEC 512

void hp_init(HiddenProtect *hp, uint64_t disk_sectors, uint64_t hidden_lba, uint64_t hidden_sectors){
    hp->disk_sectors = disk_sectors;
    hp->hidden_lba = hidden_lba; hp->hidden_sectors = hidden_sectors; hp->writes_refused = 0;
}

/* ── (a) the disk illusion ─────────────────────────────────────────────────── */
uint64_t hp_reported_sectors(const HiddenProtect *hp){
    return hp->disk_sectors;                     /* the WHOLE disk — never shrunk, no gap */
}
uint64_t hp_used_sectors(const HiddenProtect *hp, uint64_t decoy_used){
    uint64_t used = decoy_used + hp->hidden_sectors;   /* hidden reserve shown as USED */
    return used > hp->disk_sectors ? hp->disk_sectors : used;
}
uint64_t hp_free_sectors(const HiddenProtect *hp, uint64_t decoy_used){
    uint64_t used = hp_used_sectors(hp, decoy_used);
    return hp->disk_sectors > used ? hp->disk_sectors - used : 0;
}

/* ── (b) the protect filter ───────────────────────────────────────────────── */
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
