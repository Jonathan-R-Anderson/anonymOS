/* deps/veracrypt/efi — self-contained header-open for the EFI pre-boot loader (§E5b). */
#ifndef EFI_VC_H
#define EFI_VC_H

/* PBKDF2-HMAC-SHA512 iterations for the volume header key.  200000 is VeraCrypt's default for
 * SHA-512 system encryption; the harness used 1000 while the format was being validated, but
 * the header is the sole gate to the master key, so the count IS the offline attack cost.
 * Must match vcheader.h (host tools) and veracrypt_impl.d (the kernel writes the headers). */
#define VC_HEADER_ITERATIONS 200000

enum { PREBOOT_REJECT = 0, PREBOOT_DECOY = 1, PREBOOT_HIDDEN = 2 };

int vc_open_header(const char *password, const unsigned char header[512],
                   unsigned char outMasterKey[256]);
/* As vc_open_header, but also returns the header's big-endian "Volume size" (bytes, offset
 * 100) and "Hidden volume size" (offset 92) fields -- the loader needs the volume size to
 * hand the kernel the bounds of the encrypted object-store region inside a hidden volume. */
int vc_open_header_ex(const char *password, const unsigned char header[512],
                      unsigned char outMasterKey[256],
                      unsigned long long *outVolumeSize, unsigned long long *outHiddenSize);
int preboot_authenticate(const char *password, const unsigned char decoy[512],
                         const unsigned char hidden[512], unsigned char outMasterKey[256]);
/* Same verdict; also returns the matched header's volume size (bytes) for the store bounds. */
int preboot_authenticate_ex(const char *password, const unsigned char decoy[512],
                            const unsigned char hidden[512], unsigned char outMasterKey[256],
                            unsigned long long *outVolumeSize);
/* §G2.1 — after a PREBOOT_DECOY verdict, the honey seed decoy_seed(canonical matched
 * password); 0 otherwise. The loader forwards it to the decoy on the kernel command line
 * (decoyseed=) so the synthetic-log generators seed the same universe the password implies. */
unsigned long long preboot_last_decoy_seed(void);

/* §E5d — XTS-decrypt one 512-byte data unit in place, for the pre-boot loader to decrypt the
 * matched OS's on-disk encrypted bootloader payload after unlock. `k1`/`k2` are the data/tweak
 * halves of the master key `preboot_authenticate` returns (outMasterKey[0..32) / [32..64)),
 * `unit` is the sector's index within the payload region (matching how the installer encrypts). */
void vc_xts_decrypt(unsigned char *buf, unsigned long long len, unsigned long long unit,
                    const unsigned char *k1, const unsigned char *k2);
/* Decrypt `nunits` consecutive 512-byte units in place (software path; key schedules expanded
 * once).  efi_aesni.c provides the AES-NI twin with the same contract. */
void vc_xts_decrypt_units(unsigned char *buf, unsigned long long nunits, unsigned long long first_unit,
                          const unsigned char *k1, const unsigned char *k2);
int  aesni_available(void);
void aesni_xts_decrypt_units(unsigned char *buf, unsigned long long nunits, unsigned long long first_unit,
                             const unsigned char *k1, const unsigned char *k2);

#endif
