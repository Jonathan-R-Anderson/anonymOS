/* deps/veracrypt — pre-boot authentication decision core (§E5). See preboot_auth.h. */
#include "preboot_auth.h"
#include "vcheader.h"
#include <string.h>

preboot_verdict preboot_authenticate(const char *password,
                                     const uint8_t decoyHeader[512],
                                     const uint8_t hiddenHeader[512],
                                     uint8_t outMasterKey[256]){
    uint8_t kd[256], kh[256];
    /* Always attempt BOTH headers (no early-out), so the work — and thus the timing — is
     * the same shape whether the password is decoy, hidden, or wrong: a wrong password
     * must be indistinguishable from "there is no hidden OS here". */
    int okd = (vc_open_header(password, decoyHeader,  kd) == 0);
    int okh = (vc_open_header(password, hiddenHeader, kh) == 0);

    if (okd){ memcpy(outMasterKey, kd, 256); return PREBOOT_DECOY;  }
    if (okh){ memcpy(outMasterKey, kh, 256); return PREBOOT_HIDDEN; }
    return PREBOOT_REJECT;
}
