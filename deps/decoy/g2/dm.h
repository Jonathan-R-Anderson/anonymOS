/* deps/decoy/g2 — honey-hashed, typo-tolerant decoy boot matcher (roadmap/INSTALLER.md
 * §G2.2; the boot-required gate that ties §G to §E).
 *
 * Decides what a typed password boots: a registered decoy (exactly, or via a bounded set
 * of typo corrections of the INPUT) -> that decoy's universe (seed snapped to the canonical
 * password); anything else -> REJECT. Security shape: the verifiers are exact salted
 * hashes (no fuzzy/similarity data about the secret on disk); typo tolerance comes from
 * fuzzing the *input*, not the storage. A pool of honey/chaff verifiers pads the real
 * decoys so the stored count never reveals how many decoys exist — the real/chaff flag is
 * a system secret (a honeychecker / separate-secret bit in production), never in the bytes
 * an attacker can read.
 *
 * NOTE: the test uses a fast salted hash for speed; production uses the §E slow KDF
 * (PBKDF2) so stolen storage is hard to crack — applied to the bounded candidate set. */
#ifndef DECOY_DM_H
#define DECOY_DM_H
#include <stdint.h>

typedef struct { uint64_t salt, hash; int is_real; } DecoyVerifier;  /* is_real = system secret */
typedef struct { DecoyVerifier v[64]; int n; } DecoyMatcher;

void dm_init(DecoyMatcher *m);
int  dm_register_decoy(DecoyMatcher *m, const char *password);  /* -> decoy index */
void dm_register_chaff(DecoyMatcher *m, int count);             /* honeyword padding */

/* On match: returns 1, sets *idx (decoy index) and *seed (decoy_seed of the canonical,
 * so a typo and the exact password yield the IDENTICAL universe). Else returns 0 (reject). */
int  dm_match(const DecoyMatcher *m, const char *typed, int *idx, uint64_t *seed);

#endif
