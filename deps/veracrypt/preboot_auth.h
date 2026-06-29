/* deps/veracrypt — pre-boot authentication decision core (roadmap/INSTALLER.md §E5)
 *
 * The security-critical heart of the EFI pre-boot loader, factored out so it is testable
 * on the host and reused verbatim in the .efi: given the typed password and the two
 * candidate header sectors (decoy at the system-partition start, hidden inside the outer
 * partition), decide what to boot. A wrong password takes the identical path and reveals
 * nothing — there is no branch or message that hints a hidden OS could exist. */
#ifndef PREBOOT_AUTH_H
#define PREBOOT_AUTH_H
#include <stdint.h>

typedef enum {
    PREBOOT_REJECT = 0,   /* password opens neither header → reveal nothing, refuse */
    PREBOOT_DECOY  = 1,   /* opens the decoy system header → boot the decoy OS */
    PREBOOT_HIDDEN = 2,   /* opens the hidden header → boot the hidden OS */
} preboot_verdict;

/* Try `password` against the decoy header then the hidden header; on the first that
 * opens, return its verdict and fill outMasterKey (256 bytes). Both attempts always run
 * the same work (constant-shape) so timing doesn't betray which header matched. */
preboot_verdict preboot_authenticate(const char *password,
                                     const uint8_t decoyHeader[512],
                                     const uint8_t hiddenHeader[512],
                                     uint8_t outMasterKey[256]);

#endif
