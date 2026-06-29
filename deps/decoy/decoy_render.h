/* deps/decoy — render decoy events into realistic log lines (roadmap/INSTALLER.md §G,
 * G3.3 realism). Turns the abstract DecoyEvent stream into believable syslog/auth.log/
 * journal-style text, deterministically (every token derives from the event), so the
 * §H2 Linux program can write it to /var/log and the native decoy view can serve it.
 * Self-contained (no libc) — portable to the kernel and to Linux. */
#ifndef DECOY_RENDER_H
#define DECOY_RENDER_H
#include <stdint.h>
#include "decoy.h"

/* Render one event as a single syslog-style line (no trailing newline) into `out`
 * (size `max`); returns the line length. `seed` lets a line pull stable cross-event
 * facts (e.g. a consistent hostname). */
int decoy_render(uint64_t seed, const DecoyEvent *e, char *out, int max);

/* Installer-configurable identity (so the logs reference the decoy's REAL account/host,
 * not a hardcoded one). Set before rendering; both default sensibly if unset. */
void decoy_set_user(const char *username);   /* the decoy's primary user account */
void decoy_set_host(const char *hostname);   /* the decoy's hostname */

#endif
