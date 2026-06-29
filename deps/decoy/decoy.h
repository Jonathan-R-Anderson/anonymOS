/* deps/decoy — deterministic decoy activity generator engine (roadmap/INSTALLER.md §G).
 *
 * The fake universe as a PURE function: U(seed, subsystem, time-window) -> events, never
 * stored, regenerated identically every call. Integer/fixed-point coherent noise (no
 * float -> cross-arch deterministic), a shared "activity intensity" field that drives all
 * subsystems (so they correlate), and bursty event placement (a rate-modulated process,
 * not uniform). Portable C with no libc -> reused by the kernel decoy view (§G) and the
 * Linux fake-log program (§H2). Validated by tests/decoy (determinism / password-
 * sensitivity / burstiness / correlation / scale). */
#ifndef DECOY_H
#define DECOY_H
#include <stdint.h>

enum {                          /* subsystems (G phases 4–5) */
    DECOY_LOG = 0, DECOY_PROC, DECOY_USER, DECOY_SVC,
    DECOY_NET, DECOY_SEC, DECOY_FS, DECOY_AUDIT, DECOY_NSUB
};

typedef struct { uint64_t time_sec; uint8_t subsys; uint32_t detail; } DecoyEvent;

/* Derive the universe seed from the boot password. (Production routes the password through
 * the §E slow KDF first; this maps a password/KDF-output to the 64-bit universe key.) */
uint64_t decoy_seed(const char *password);

/* The shared activity-intensity field at hour `bin`, fixed-point in [0,65536). */
uint32_t decoy_intensity(uint64_t seed, uint64_t bin);

/* Generate the events for `subsys` over hours [bin0, bin0+nbins). Writes up to `max`
 * events to `out` and returns the count produced (events are time-ordered). */
int decoy_events(uint64_t seed, int subsys, uint64_t bin0, uint64_t nbins,
                 DecoyEvent *out, int max);

#endif
