/* deps/decoy/h3 — full-disk illusion + "protect hidden volume" block filter
 * (roadmap/INSTALLER.md §H3).
 *
 * The logic of the Linux device-mapper target that fronts the disk while the DECOY OS is
 * running. Two jobs, so a coerced examiner booted into the decoy sees a completely ordinary,
 * FULLY-USED disk with nothing to explain:
 *
 *   (a) DISK ILLUSION — report the WHOLE physical disk as the decoy's, and account the hidden
 *       volume's reserved sectors as USED space. A too-small "disk", a partition-sized gap, or
 *       a big unexplained free region is the single biggest tell that a hidden OS exists, so the
 *       decoy must believe every sector is its own and spoken for:
 *         - hp_reported_sectors() -> the full disk (what blockdev/fdisk should show),
 *         - hp_used_sectors()     -> decoy-used + hidden-reserved (what df's "used" should show),
 *         - hp_free_sectors()     -> only the genuinely-free remainder, never the hidden space.
 *
 *   (b) PROTECT — the decoy may use the outer volume's real free space, but must never
 *       read-DETECT or write-CORRUPT the hidden volume living in it:
 *         - reads pass through (the hidden region is on-disk random/ciphertext →
 *           indistinguishable from outer-volume free space; the decoy cannot tell),
 *         - writes overlapping the hidden region are REFUSED (VeraCrypt "protect hidden volume"),
 *           so decoy/outer filesystem activity can't clobber the hidden OS.
 *
 * Booting the HIDDEN OS uses a different mapping (no illusion, no protection) and accesses the
 * disk normally. This is the portable core the dm-target Linux kernel module / init hook enforces
 * once the decoy boots. */
#ifndef HIDDEN_PROTECT_H
#define HIDDEN_PROTECT_H
#include <stdint.h>
#include <stdio.h>

typedef struct {
    uint64_t disk_sectors;      /* the FULL physical disk the decoy must believe it owns   */
    uint64_t hidden_lba;        /* first sector of the protected hidden region             */
    uint64_t hidden_sectors;    /* length of the protected hidden region                   */
    int      writes_refused;    /* count of writes refused for overlapping the hidden vol  */
} HiddenProtect;

void hp_init(HiddenProtect *hp, uint64_t disk_sectors, uint64_t hidden_lba, uint64_t hidden_sectors);

/* ── (a) the disk illusion the decoy sees ─────────────────────────────────── */
/* The full physical disk — never shrunk, so there is no unaccounted space or too-small disk. */
uint64_t hp_reported_sectors(const HiddenProtect *hp);
/* "Used" as the decoy should see it: its own used sectors PLUS the hidden reserve counted used,
 * so free space never reveals a hidden-volume-sized hole. `decoy_used` is what the decoy's own
 * filesystem actually occupies. */
uint64_t hp_used_sectors(const HiddenProtect *hp, uint64_t decoy_used);
/* The free remainder the decoy may believe it has — the disk minus (decoy-used + hidden). */
uint64_t hp_free_sectors(const HiddenProtect *hp, uint64_t decoy_used);

/* ── (b) the protect filter ───────────────────────────────────────────────── */
/* Read `nsec` sectors at `lba` from `dev` into `buf` — always passes through. */
int hp_read (HiddenProtect *hp, FILE *dev, uint64_t lba, uint64_t nsec, void *buf);
/* Write `nsec` sectors at `lba`. Refused (returns -1, nothing written, counts the refusal)
 * if the range overlaps the protected hidden region; otherwise written (returns 0). */
int hp_write(HiddenProtect *hp, FILE *dev, uint64_t lba, uint64_t nsec, const void *buf);

#endif
