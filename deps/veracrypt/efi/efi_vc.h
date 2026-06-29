/* deps/veracrypt/efi — self-contained header-open for the EFI pre-boot loader (§E5b). */
#ifndef EFI_VC_H
#define EFI_VC_H

#define VC_HEADER_ITERATIONS 1000   /* must match vcheader.h / veracrypt_impl.d */

enum { PREBOOT_REJECT = 0, PREBOOT_DECOY = 1, PREBOOT_HIDDEN = 2 };

int vc_open_header(const char *password, const unsigned char header[512],
                   unsigned char outMasterKey[256]);
int preboot_authenticate(const char *password, const unsigned char decoy[512],
                         const unsigned char hidden[512], unsigned char outMasterKey[256]);

#endif
