/* deps/veracrypt — VeraCrypt volume-header engine (roadmap/INSTALLER.md §E2)
 *
 * Implements the on-disk header format from VOLUME_FORMAT.md on top of the
 * KAT-validated crypto core (libvc_crypto.a): create + open, with the hidden-volume
 * mechanism. This is the reference the kernel's native-D port (E2b) must match
 * byte-for-byte; the XTS + PBKDF2 here mirror veracrypt_impl.d's algorithms exactly. */
#ifndef VC_HEADER_H
#define VC_HEADER_H
#include <stdint.h>
#include <stddef.h>

#define VC_HEADER_SIZE          512    /* TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE (system enc.) */
#define VC_SALT_SIZE            64
#define VC_MASTER_KEYDATA_SIZE  256
/* PBKDF2 iterations. Kept modest so the harness is snappy; production uses VeraCrypt's
 * PIM-based counts (e.g. 200000 system / 500000 non-system for SHA-512). The format +
 * crypto pipeline is what's validated here, and create/open agree on this value. */
#define VC_HEADER_ITERATIONS    1000

/* Build a 512-byte VeraCrypt header. salt[64] is plaintext; masterKey[256] is the volume
 * key area; hiddenVolSize != 0 marks this as the OUTER header of a hidden pair. */
int  vc_create_header(const char *password,
                      const uint8_t salt[VC_SALT_SIZE],
                      const uint8_t masterKey[VC_MASTER_KEYDATA_SIZE],
                      uint64_t hiddenVolSize, uint64_t volumeSize,
                      uint64_t encAreaStart, uint64_t encAreaLen,
                      uint8_t out[VC_HEADER_SIZE]);

/* Try to open a header with `password`. Returns 0 and fills outMasterKey on success
 * (correct password → "VERA" magic + both CRCs verify); negative on any mismatch. */
int  vc_open_header(const char *password,
                    const uint8_t header[VC_HEADER_SIZE],
                    uint8_t outMasterKey[VC_MASTER_KEYDATA_SIZE]);

#endif
