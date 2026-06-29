/* deps/decoy/h3 — "protect hidden volume" block filter (roadmap/INSTALLER.md §H3).
 *
 * The logic of the Linux device-mapper target that fronts the OUTER partition while the
 * DECOY OS is running. The decoy may mount the outer volume (with the outer password) and
 * use its free space — but it must never read-detect or write-corrupt the hidden volume
 * that lives in that free space:
 *   - reads pass through (the hidden region is on-disk random/ciphertext → indistinguishable
 *     from outer-volume free space; the decoy has no way to tell it's a hidden volume);
 *   - writes that would touch the hidden region are REFUSED (VeraCrypt "protect hidden
 *     volume" mode), so decoy/outer filesystem activity can't clobber the hidden OS.
 * Booting the HIDDEN OS uses a different mapping (no protection) and accesses it normally.
 *
 * This is the portable core; the real driver is a dm-target Linux kernel module. */
#ifndef HIDDEN_PROTECT_H
#define HIDDEN_PROTECT_H
#include <stdint.h>
#include <stdio.h>

typedef struct { uint64_t hidden_lba, hidden_sectors; int writes_refused; } HiddenProtect;

void hp_init(HiddenProtect *hp, uint64_t hidden_lba, uint64_t hidden_sectors);

/* Read `nsec` sectors at `lba` from `dev` into `buf` — always passes through. */
int hp_read (HiddenProtect *hp, FILE *dev, uint64_t lba, uint64_t nsec, void *buf);

/* Write `nsec` sectors at `lba`. Refused (returns -1, nothing written, counts the refusal)
 * if the range overlaps the protected hidden region; otherwise written (returns 0). */
int hp_write(HiddenProtect *hp, FILE *dev, uint64_t lba, uint64_t nsec, const void *buf);

#endif
