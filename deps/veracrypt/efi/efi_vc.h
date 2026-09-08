/* deps/veracrypt/efi — self-contained header-open for the EFI pre-boot loader (§E5b). */
#ifndef EFI_VC_H
#define EFI_VC_H

#define VC_HEADER_ITERATIONS 1000   /* must match vcheader.h / veracrypt_impl.d */

enum { PREBOOT_REJECT = 0, PREBOOT_DECOY = 1, PREBOOT_HIDDEN = 2 };

int vc_open_header(const char *password, const unsigned char header[512],
                   unsigned char outMasterKey[256]);
int preboot_authenticate(const char *password, const unsigned char decoy[512],
                         const unsigned char hidden[512], unsigned char outMasterKey[256]);

/* §E5d — XTS-decrypt one 512-byte data unit in place, for the pre-boot loader to decrypt the
 * matched OS's on-disk encrypted bootloader payload after unlock. `k1`/`k2` are the data/tweak
 * halves of the master key `preboot_authenticate` returns (outMasterKey[0..32) / [32..64)),
 * `unit` is the sector's index within the payload region (matching how the installer encrypts). */
void vc_xts_decrypt(unsigned char *buf, unsigned long long len, unsigned long long unit,
                    const unsigned char *k1, const unsigned char *k2);

#endif
