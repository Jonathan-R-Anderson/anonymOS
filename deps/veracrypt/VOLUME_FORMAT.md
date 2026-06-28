# VeraCrypt volume-header format — distilled spec (roadmap/INSTALLER.md §E1/§E2)

This is the **format reference** for the hidden/decoy-OS feature, distilled from the
authoritative upstream source (`../VeraCrypt/src/Common/Volumes.h`,`Volumes.c`,`Crypto.c`).

**Why a spec instead of a port:** the VeraCrypt `Common/` encryption C (`Volumes.c`,
`Xts.c`, `Crypto.c`) is tangled with MSVC/Windows assumptions — `__int64`/`__int32`
intrinsics, `<strsafe.h>`/`<io.h>`/`<ntstrsafe.h>`, the EFI `_UEFI`+`<Uefi.h>` path, an
`EncryptionThreadPool`, and a Windows RNG. Porting it recreates the very "musl swamp"
the project rejected for §D2 (we chose the native object-FS partitioner over libparted
for exactly this reason). So §E keeps the split the architecture already implies:

- **The portable crypto core → C** (`libvc_crypto.a`, E1 — DONE, NIST-KAT-validated):
  the ciphers + hashes, the genuinely portable, audit-once primitives.
- **The XTS mode + volume header + hidden-volume layout → native D** in the kernel's
  `src/kernel/d/drivers/veracrypt_impl.d` (E2), which already seeds `xts_encrypt_sector`,
  `pbkdf2_sha512`, and `create_veracrypt_header`. The kernel owns block I/O (§D2(b)), so
  it owns the on-disk encryption; this spec is what it implements, byte-for-byte.
- **The `Boot/EFI` pre-boot loader → E5** (a separate UEFI-toolchain build, not E1).

Header-format parity means a real VeraCrypt could open our volumes — a strong correctness
check (§E2 validates the D header against this), not a runtime dependency.

## Header geometry
- `VOLUME_HEADER_VERSION = 0x0005`.
- Modern data-volume header: `TC_VOLUME_HEADER_SIZE = 64 KiB`. **System (boot) encryption
  — what the decoy/hidden OS use — uses `TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE = 512`.**
- Salt is plaintext; everything from offset 64 on is **encrypted** (XTS, header key).

## Field layout (byte offsets from header start)
| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0   | 64   | `HEADER_SALT` (`PKCS5_SALT_SIZE`) | **plaintext**; feeds the KDF |
| 64  | 4    | `MAGIC` = `"VERA"` | first encrypted field; password check |
| 68  | 2    | `VERSION` | |
| 70  | 2    | `REQUIRED_VERSION` | min program version |
| 72  | 4    | `KEY_AREA_CRC` | CRC32 of the master-keydata area |
| 76  | 8    | `VOLUME_CREATION_TIME` | |
| 84  | 8    | `MODIFICATION_TIME` | |
| 92  | 8    | **`HIDDEN_VOLUME_SIZE`** | **0 = normal; nonzero = this is the OUTER header of a hidden pair.** The deniability tell — but it lives *inside* the encrypted area, so it's invisible without the password. |
| 100 | 8    | `VOLUME_SIZE` | |
| 108 | 8    | `ENCRYPTED_AREA_START` | byte offset of the encrypted data region |
| 116 | 8    | `ENCRYPTED_AREA_LENGTH` | |
| 124 | 4    | `FLAGS` | |
| 128 | 4    | `SECTOR_SIZE` | |
| 252 | 4    | `HEADER_CRC` | CRC32 of fields 64..251 |
| 256 | …    | `MASTER_KEYDATA` | the XTS master key(s); volume data is encrypted under THESE, not the password |

## The hidden volume (where plausible deniability lives)
- The **hidden header** is a second, complete header at `TC_HIDDEN_VOLUME_HEADER_OFFSET
  = TC_VOLUME_HEADER_SIZE` (the second 64 KiB block; a distinct fixed offset for the
  512-byte boot headers). It is only decryptable with the **hidden password**.
- To anyone without that password it is **indistinguishable from random data** — which is
  why the whole volume (and all free space) must be filled with random on create, so the
  presence of a hidden header/volume cannot be detected by entropy.
- Both headers also have **backup copies** at the volume tail (`TC_TOTAL_VOLUME_HEADERS_SIZE
  = 4 × 64 KiB`): primary+hidden at the front, primary+hidden backups at the back.
- **Hidden OS:** the decoy OS is system-encrypted on the system partition; the hidden OS
  lives in a hidden volume inside a second ("outer") partition's free space. The pre-boot
  loader (§E5) tries the typed password against the decoy header and the hidden header and
  boots whichever matches.

## KDF + cipher (what `veracrypt_impl.d` must match)
- **KDF:** PBKDF2-HMAC over SHA-512 / Whirlpool / Streebog / BLAKE2s (or Argon2id in newer
  volumes — deferred; `libvc_crypto.a` provides the PBKDF2 hashes today). Iterations are
  large (PIM-tunable). Derives the **64-byte header key** for header XTS.
- **Cipher:** XTS mode over AES / Serpent / Twofish / Camellia / Kuznyechik and the cascades
  (`Crypto.c`'s EA table maps each algorithm → XTS). The header XTS protects the master
  keydata; the data-area XTS (under the master keys) protects the OS itself.
