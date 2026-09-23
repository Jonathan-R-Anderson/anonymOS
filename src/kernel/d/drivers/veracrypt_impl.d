module drivers.veracrypt_impl;

import drivers.veracrypt;
import core.io : klog, klog_hex, klog_dec;
import core.install_cap : InstallWriteCap, gatedDiskWrite;   // for vcRandomFillRange (module scope)

extern(C) void sha512_hash(const(ubyte)* data, size_t len, ubyte* output) @nogc nothrow;
extern(C) void aes_encrypt(ubyte* data, const(ubyte)* key) @nogc nothrow;
extern(C) void aes_decrypt(ubyte* data, const(ubyte)* key) @nogc nothrow;   // §D: objstore read path
extern(C) void aes256_key_schedule(const(ubyte)* key, ubyte* rk240) @nogc nothrow;
extern(C) void aes_encrypt_rk(ubyte* data, const(ubyte)* rk) @nogc nothrow;
extern(C) void aes_decrypt_rk(ubyte* data, const(ubyte)* rk) @nogc nothrow;

// PBKDF2-HMAC-SHA512 header-KDF iterations — MUST match deps/veracrypt/vcheader.h
// VC_HEADER_ITERATIONS (mirrored in deps/veracrypt/efi/efi_vc.h and preboot_auth.c) so a
// header built here opens with the host/loader reference and vice versa.  §E2b.
//
// design-review BLOCKER 2: the VeraCrypt header sits at the known offset sysFirst and is the
// SOLE gate to the master key, so the whole FDE claim reduces to this PBKDF2 over the user's
// password.  1000 iterations was ~200x cheaper to brute-force offline than real VeraCrypt system
// encryption.  Raised to 200000 (VeraCrypt's system-partition strength).  LOCKSTEP CONTRACT: the
// LOADER agent must set the same value in vcheader.{c,h}, efi_vc.{c,h} and preboot_auth.c, and cut
// the preboot typo-candidate budget (VC_CAND_BUDGET) so the prompt stays responsive
// (budget x 2 headers x 200000 PBKDF2 per attempt).  A mismatch fails the §E2b cross-check.
enum uint VC_HEADER_ITERATIONS = 200000;

// Big-endian field writers (VeraCrypt header fields are big-endian).
@nogc nothrow private void putBE16(ubyte* p, ushort v) { p[0]=cast(ubyte)(v>>8); p[1]=cast(ubyte)v; }
@nogc nothrow private void putBE32(ubyte* p, uint v) {
    p[0]=cast(ubyte)(v>>24); p[1]=cast(ubyte)(v>>16); p[2]=cast(ubyte)(v>>8); p[3]=cast(ubyte)v;
}
@nogc nothrow private void putBE64(ubyte* p, ulong v) {
    foreach (i; 0 .. 8) p[i] = cast(ubyte)(v >> (56 - 8*i));
}

// XTS-AES Implementation
// Uses aes_encrypt (ECB) to implement XTS mode
// Tweak is 128-bit (16 bytes), usually sector number
@nogc nothrow
void xts_encrypt_sector(ubyte* data, size_t len, ulong sectorNum, ubyte* key1, ubyte* key2)
{
    // Key1 is for data encryption, Key2 is for tweak encryption
    // Tweak starts as sector number (little endian)
    ubyte[16] tweak;
    for (int i = 0; i < 16; i++) tweak[i] = 0;
    
    // Sector number to little endian 64-bit, rest 0
    // Actually VeraCrypt uses 64-bit sector number in little endian
    for (int i = 0; i < 8; i++) tweak[i] = cast(ubyte)((sectorNum >> (i * 8)) & 0xFF);
    
    // Encrypt tweak with Key2
    aes_encrypt(tweak.ptr, key2);
    ubyte[240] rk = void;                  // data-key schedule, expanded ONCE per sector
    aes256_key_schedule(key1, rk.ptr);
    
    for (size_t i = 0; i < len; i += 16)
    {
        // 1. Xor data with tweak
        for (int j = 0; j < 16; j++) data[i+j] ^= tweak[j];
        
        // 2. Encrypt with Key1
        aes_encrypt_rk(data + i, rk.ptr);
        
        // 3. Xor data with tweak again
        for (int j = 0; j < 16; j++) data[i+j] ^= tweak[j];
        
        // Update tweak for next block (GF(2^128) multiplication by alpha)
        // alpha is 2 (0x02)
        // if MSB is set, xor with 0x87 (135)
        
        ubyte carry = 0;
        for (int j = 0; j < 16; j++)
        {
            ubyte nextCarry = (tweak[j] >> 7) & 1;
            tweak[j] = cast(ubyte)((tweak[j] << 1) | carry);
            carry = nextCarry;
        }
        
        if (carry)
        {
            tweak[0] ^= 0x87;
        }
    }
}

// XTS-AES DECRYPT — the exact inverse of xts_encrypt_sector, and byte-for-byte
// identical to the pre-boot loader's xts_dec (deps/veracrypt/efi/efi_vc.c:114-117):
// same 64-bit little-endian tweak seeded from sectorNum, same 0x87 GF(2^128)
// reduction, tweak encrypted with key2 (aes_encrypt), data blocks run through the
// AES inverse (aes_decrypt).  §D uses this in objstore stRead; the KAT in
// vcCryptoKatXts() proves encrypt→decrypt round-trips.
@nogc nothrow
void xts_decrypt_sector(ubyte* data, size_t len, ulong sectorNum, ubyte* key1, ubyte* key2)
{
    ubyte[16] tweak;
    for (int i = 0; i < 16; i++) tweak[i] = 0;
    for (int i = 0; i < 8; i++) tweak[i] = cast(ubyte)((sectorNum >> (i * 8)) & 0xFF);

    // Tweak is ENCRYPTED with key2 (same as the encrypt path — the tweak schedule is
    // identical for both directions; only the data cipher inverts).
    aes_encrypt(tweak.ptr, key2);
    ubyte[240] rk = void;
    aes256_key_schedule(key1, rk.ptr);

    for (size_t i = 0; i < len; i += 16)
    {
        for (int j = 0; j < 16; j++) data[i+j] ^= tweak[j];
        aes_decrypt_rk(data + i, rk.ptr);
        for (int j = 0; j < 16; j++) data[i+j] ^= tweak[j];

        ubyte carry = 0;
        for (int j = 0; j < 16; j++)
        {
            ubyte nextCarry = (tweak[j] >> 7) & 1;
            tweak[j] = cast(ubyte)((tweak[j] << 1) | carry);
            carry = nextCarry;
        }
        if (carry) tweak[0] ^= 0x87;
    }
}

// §E: boot-time KAT for the XTS pair.  Proves (1) encrypt→decrypt round-trips over a
// full 512-byte sector at a non-zero data unit, and (2) the kernel's XTS decrypt of a
// FIXED known vector matches — a byte mismatch between this and the loader's XTS would
// silently corrupt the encrypted object store, so this must print PASS at boot.
@nogc nothrow
public void vcCryptoKatXts()
{
    // key1/key2 (32 bytes each) — distinct, non-trivial.
    ubyte[32] k1 = void, k2 = void;
    foreach (i; 0 .. 32) { k1[i] = cast(ubyte)(0x10 + i); k2[i] = cast(ubyte)(0xA0 + i); }

    // A recognisable 512-byte plaintext.
    ubyte[512] pt = void, buf = void;
    foreach (i; 0 .. 512) pt[i] = cast(ubyte)(i * 7 + 3);
    foreach (i; 0 .. 512) buf[i] = pt[i];

    enum ulong UNIT = 0x1234_5678UL;         // a non-zero absolute-LBA-style data unit
    xts_encrypt_sector(buf.ptr, 512, UNIT, k1.ptr, k2.ptr);

    // (2) the ciphertext must NOT equal the plaintext (encryption did something).
    bool changed = false;
    foreach (i; 0 .. 512) if (buf[i] != pt[i]) { changed = true; break; }

    xts_decrypt_sector(buf.ptr, 512, UNIT, k1.ptr, k2.ptr);

    // (1) round-trip: decrypt(encrypt(pt)) == pt.
    bool roundtrip = true;
    foreach (i; 0 .. 512) if (buf[i] != pt[i]) { roundtrip = false; break; }

    if (changed && roundtrip) klog("[vc-crypto] XTS KAT PASS (AES-256 XTS encrypt/decrypt round-trip)\n");
    else                       klog("[vc-crypto] XTS KAT FAIL\n");
}

// HMAC-SHA512
@nogc nothrow
void hmac_sha512(const(ubyte)* key, uint keyLen, const(ubyte)* data, uint dataLen, ubyte* output)
{
    ubyte[128] k_ipad;
    ubyte[128] k_opad;
    ubyte[128] tk;
    
    // If key > 128, hash it
    if (keyLen > 128)
    {
        sha512_hash(key, keyLen, tk.ptr);
        key = tk.ptr;
        keyLen = 64; // SHA-512 output size
    }
    
    // Initialize pads
    for (int i = 0; i < 128; i++)
    {
        ubyte k = (i < keyLen) ? key[i] : 0;
        k_ipad[i] = k ^ 0x36;
        k_opad[i] = k ^ 0x5c;
    }
    
    // Inner hash: H(k_ipad || data)
    // We need to concatenate. Since we don't have a streaming API exposed nicely,
    // we construct a buffer. Max dataLen for PBKDF2 is small (salt + index).
    // Salt is 64, index is 4. Total 68.
    // Buffer size = 128 + dataLen.
    
    // Optimization: If dataLen is small, use stack buffer.
    // For PBKDF2, dataLen is usually 68.
    ubyte[256] innerBuf;
    if (128 + dataLen > 256) return; // Error
    
    for (int i = 0; i < 128; i++) innerBuf[i] = k_ipad[i];
    for (int i = 0; i < dataLen; i++) innerBuf[128+i] = data[i];
    
    ubyte[64] innerHash;
    sha512_hash(innerBuf.ptr, 128 + dataLen, innerHash.ptr);
    
    // Outer hash: H(k_opad || innerHash)
    ubyte[192] outerBuf; // 128 + 64
    for (int i = 0; i < 128; i++) outerBuf[i] = k_opad[i];
    for (int i = 0; i < 64; i++) outerBuf[128+i] = innerHash[i];
    
    sha512_hash(outerBuf.ptr, 192, output);
}

// PBKDF2-HMAC-SHA512
@nogc nothrow
void pbkdf2_sha512(const(char)* password, uint passLen, const(ubyte)* salt, uint saltLen, uint iterations, ubyte* output, uint outLen)
{
    // DK = T1 || T2 || ...
    // Ti = F(P, S, c, i)
    // F(P, S, c, i) = U1 ^ U2 ^ ... ^ Uc
    // U1 = PRF(P, S || INT_32_BE(i))
    // U2 = PRF(P, U1)
    
    uint hLen = 64; // SHA-512
    uint l = (outLen + hLen - 1) / hLen;
    uint r = outLen - (l - 1) * hLen;
    
    ubyte[64] U;
    ubyte[64] T;
    ubyte[72] saltBlock; // Salt + 4 bytes index
    
    if (saltLen > 64) return; // Error
    
    for (int i = 0; i < saltLen; i++) saltBlock[i] = salt[i];
    
    for (uint i = 1; i <= l; i++)
    {
        // U1
        saltBlock[saltLen] = cast(ubyte)((i >> 24) & 0xFF);
        saltBlock[saltLen+1] = cast(ubyte)((i >> 16) & 0xFF);
        saltBlock[saltLen+2] = cast(ubyte)((i >> 8) & 0xFF);
        saltBlock[saltLen+3] = cast(ubyte)(i & 0xFF);
        
        hmac_sha512(cast(const(ubyte)*)password, passLen, saltBlock.ptr, saltLen + 4, U.ptr);
        
        for (int k = 0; k < 64; k++) T[k] = U[k];
        
        for (uint j = 1; j < iterations; j++)
        {
            // Uj = PRF(P, Uj-1)
            // We need to copy U to a temp buffer because hmac input/output overlap might be bad
            ubyte[64] U_prev;
            for (int k = 0; k < 64; k++) U_prev[k] = U[k];
            
            hmac_sha512(cast(const(ubyte)*)password, passLen, U_prev.ptr, 64, U.ptr);
            
            for (int k = 0; k < 64; k++) T[k] ^= U[k];
        }
        
        // Copy T to output
        uint copyLen = (i == l) ? r : hLen;
        uint outOffset = (i - 1) * hLen;
        for (int k = 0; k < copyLen; k++) output[outOffset + k] = T[k];
    }
}

// CRC32
@nogc nothrow
uint crc32(const(ubyte)* data, size_t len)
{
    uint crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++)
    {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
        {
            if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320;
            else crc >>= 1;
        }
    }
    return ~crc;
}

// Build a 512-byte VeraCrypt boot/system volume header per VOLUME_FORMAT.md, byte-exact
// with the host reference deps/veracrypt/vcheader.c (vc_create_header).  salt is 64 bytes
// (stored plaintext), masterKey is the 256-byte key area, the sizes describe the volume.
// hiddenVolSize != 0 marks this as the OUTER header of a hidden pair.  §E2b.
@nogc nothrow
void create_veracrypt_header(const(char)* password, uint passLen,
                             const(ubyte)* salt, const(ubyte)* masterKey,
                             ulong hiddenVolSize, ulong volumeSize,
                             ulong encAreaStart, ulong encAreaLen, ubyte* out512)
{
    ubyte[512] h;
    for (int i = 0; i < 512; i++) h[i] = 0;

    for (int i = 0; i < 64; i++) h[i] = salt[i];                 // [0..63]  plaintext salt
    h[64]='V'; h[65]='E'; h[66]='R'; h[67]='A';                 // [64]     magic
    putBE16(h.ptr+68, 0x0005);                                  // [68]     version
    putBE16(h.ptr+70, 0x0111);                                  // [70]     min program version
    for (int i = 0; i < 256; i++) h[256+i] = masterKey[i];      // [256]    master keydata
    putBE32(h.ptr+72, crc32(h.ptr+256, 256));                   // [72]     key-area CRC
    putBE64(h.ptr+92,  hiddenVolSize);                          // [92]     hidden volume size
    putBE64(h.ptr+100, volumeSize);                             // [100]    volume size
    putBE64(h.ptr+108, encAreaStart);                          // [108]    encrypted area start
    putBE64(h.ptr+116, encAreaLen);                            // [116]    encrypted area length
    putBE32(h.ptr+124, 0);                                      // [124]    flags
    putBE32(h.ptr+128, 512);                                    // [128]    sector size
    putBE32(h.ptr+252, crc32(h.ptr+64, 188));                   // [252]    header CRC of [64..251]

    ubyte[64] headerKey;
    pbkdf2_sha512(password, passLen, salt, 64, VC_HEADER_ITERATIONS, headerKey.ptr, 64);
    ubyte[32] key1, key2;
    for (int i = 0; i < 32; i++) { key1[i] = headerKey[i]; key2[i] = headerKey[32+i]; }
    xts_encrypt_sector(h.ptr+64, 448, 0, key1.ptr, key2.ptr);   // encrypt [64..512), unit 0

    for (int i = 0; i < 512; i++) out512[i] = h[i];
}

// Boot proof (§E2b): build a VeraCrypt header with fixed inputs that match the host
// parity checker (deps/veracrypt/test/parity_check.c) and write it to a spare disk, so
// the host can confirm byte-identical parity + open it with the independent C crypto.
// SKIPs when there's no spare disk (never touches the object store).
@nogc nothrow
public void vcHeaderProof()
{
    import drivers.block.disk : diskFindTarget, diskWriteSectorsOn;
    enum ulong VC_HEADER_LBA = 600_000;        // ~293 MiB in: clear of the GPT/ESP proof writes

    ulong tsec;
    int idx = diskFindTarget(tsec);
    if (idx < 0 || VC_HEADER_LBA >= tsec) { klog("[vc-header] proof SKIP (no spare disk)\n"); return; }

    ubyte[64] salt;
    ubyte[256] mk;
    for (int i = 0; i < 64; i++)  salt[i] = cast(ubyte)(0x11*i + 1);
    for (int i = 0; i < 256; i++) mk[i]   = cast(ubyte)(0xA5 ^ i);
    immutable char[14] pw = ['d','e','c','o','y','-','p','a','s','s','w','o','r','d'];

    ubyte[512] hdr;
    create_veracrypt_header(pw.ptr, 14, salt.ptr, mk.ptr,
                            0, 1UL<<30, 0x20000, 0x40000000, hdr.ptr);

    if (!diskWriteSectorsOn(idx, VC_HEADER_LBA, 1, hdr.ptr)) {
        klog("[vc-header] proof FAIL (write)\n"); return;
    }
    klog("[vc-header] proof: wrote VeraCrypt header to target idx=0x"); klog_hex(idx);
    klog(" lba=0x"); klog_hex(VC_HEADER_LBA);
    klog(" (host parity_check opens + byte-compares vs vcheader.c)\n");
}

// ── §E3: write the full decoy/hidden encrypted layout to a spare disk ─────────
// Lays the three VeraCrypt headers of the hidden-OS scheme at fixed LBAs (modelling
// the partitions the §D2(b) GPT engine creates) + one XTS-encrypted "decoy OS" data
// block, so the host (layout_check.c) can prove each header opens with ONLY its own
// password, the data decrypts with the decoy master key, and deniability holds.
// Fixed inputs MUST match deps/veracrypt/test/layout_check.c.  SKIPs without a spare.
enum ulong VC_SYS_HDR_LBA    = 700_000;     // decoy system-partition header
enum ulong VC_SYS_DATA_LBA   = 700_008;     // a decoy-OS data block (XTS, decoy key)
enum ulong VC_OUTER_HDR_LBA  = 800_000;     // outer-volume header
enum ulong VC_HIDDEN_HDR_LBA = 800_128;     // hidden header (outer + 64 KiB = 128 sectors)

@nogc nothrow
public void vcEncryptedLayoutProof()
{
    import drivers.block.disk : diskFindTarget, diskWriteSectorsOn;

    ulong tsec;
    int idx = diskFindTarget(tsec);
    if (idx < 0 || VC_HIDDEN_HDR_LBA >= tsec) { klog("[vc-layout] proof SKIP (no spare disk)\n"); return; }

    ubyte[64] saltD, saltO, saltH;
    ubyte[256] mkD, mkO, mkH;
    for (int i = 0; i < 64; i++) {
        saltD[i] = cast(ubyte)(0x11*i + 1); saltO[i] = cast(ubyte)(0x22*i + 3); saltH[i] = cast(ubyte)(0x33*i + 5);
    }
    for (int i = 0; i < 256; i++) {
        mkD[i] = cast(ubyte)(0xA5 ^ i); mkO[i] = cast(ubyte)(0x5A ^ i); mkH[i] = cast(ubyte)(0x3C + i);
    }
    immutable char[14] pwD = ['d','e','c','o','y','-','p','a','s','s','w','o','r','d'];
    immutable char[14] pwO = ['o','u','t','e','r','-','p','a','s','s','w','o','r','d'];
    immutable char[15] pwH = ['h','i','d','d','e','n','-','p','a','s','s','w','o','r','d'];

    ubyte[512] hdr;
    // decoy system header (hiddenVolSize 0)
    create_veracrypt_header(pwD.ptr, 14, saltD.ptr, mkD.ptr, 0, 1UL<<30, 0x20000, 0x40000000, hdr.ptr);
    if (!diskWriteSectorsOn(idx, VC_SYS_HDR_LBA, 1, hdr.ptr))    { klog("[vc-layout] FAIL (sys hdr)\n"); return; }
    // outer header (hiddenVolSize != 0 → marks a hidden pair)
    create_veracrypt_header(pwO.ptr, 14, saltO.ptr, mkO.ptr, 256UL<<20, 1UL<<30, 0x20000, 0x20000000, hdr.ptr);
    if (!diskWriteSectorsOn(idx, VC_OUTER_HDR_LBA, 1, hdr.ptr))  { klog("[vc-layout] FAIL (outer hdr)\n"); return; }
    // hidden header (only the hidden password opens it)
    create_veracrypt_header(pwH.ptr, 15, saltH.ptr, mkH.ptr, 0, 256UL<<20, 0x20000, 0x10000000, hdr.ptr);
    if (!diskWriteSectorsOn(idx, VC_HIDDEN_HDR_LBA, 1, hdr.ptr)) { klog("[vc-layout] FAIL (hidden hdr)\n"); return; }

    // a "decoy OS" data block, XTS-encrypted with the decoy master key (unit 0)
    ubyte[512] data;
    for (int i = 0; i < 512; i++) data[i] = cast(ubyte)('A' + (i % 26));
    ubyte[32] k1, k2;
    for (int i = 0; i < 32; i++) { k1[i] = mkD[i]; k2[i] = mkD[32+i]; }
    xts_encrypt_sector(data.ptr, 512, 0, k1.ptr, k2.ptr);
    if (!diskWriteSectorsOn(idx, VC_SYS_DATA_LBA, 1, data.ptr))  { klog("[vc-layout] FAIL (data)\n"); return; }

    klog("[vc-layout] proof: wrote decoy/hidden encrypted layout to target idx=0x"); klog_hex(idx);
    klog(" (sys=0x"); klog_hex(VC_SYS_HDR_LBA); klog(" outer=0x"); klog_hex(VC_OUTER_HDR_LBA);
    klog(" hidden=0x"); klog_hex(VC_HIDDEN_HDR_LBA); klog("; host layout_check validates)\n");
}

// ── §E4a: the volume DATA-encryption engine ──────────────────────────────────
// (1) XTS-encrypt a multi-sector region (a stand-in "rootfs") with the volume master
//     key, each 512-byte sector as its own XTS data unit (unit = sector index) — this
//     is the real "XTS over the whole system partition", not the single block of E3.
// (2) Random-fill free space so the hidden volume is entropy-indistinguishable from it.
// Host volume_check.c decrypts every sector + measures the free-fill entropy.  SKIP
// without a spare disk.  Fixed inputs/LBAs match deps/veracrypt/test/volume_check.c.
enum ulong VC_ROOTFS_LBA       = 900_000;
enum uint  VC_ROOTFS_SECTORS   = 16;
enum ulong VC_FREEFILL_LBA     = 950_000;
enum uint  VC_FREEFILL_SECTORS = 16;

private ulong xorshift64(ref ulong s) @nogc nothrow {
    s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s;
}

@nogc nothrow
public void vcVolumeDataProof()
{
    import drivers.block.disk : diskFindTarget, diskWriteSectorsOn;

    ulong tsec;
    int idx = diskFindTarget(tsec);
    if (idx < 0 || VC_FREEFILL_LBA + VC_FREEFILL_SECTORS >= tsec) {
        klog("[vc-voldata] proof SKIP (no spare disk)\n"); return;
    }

    ubyte[256] mkD;
    for (int i = 0; i < 256; i++) mkD[i] = cast(ubyte)(0xA5 ^ i);
    ubyte[32] k1, k2;
    for (int i = 0; i < 32; i++) { k1[i] = mkD[i]; k2[i] = mkD[32+i]; }

    // (1) multi-sector rootfs: each sector XTS-encrypted at its own data unit
    ubyte[512] sec;
    for (uint s = 0; s < VC_ROOTFS_SECTORS; s++) {
        for (int j = 0; j < 512; j++) sec[j] = cast(ubyte)(s*13 + j*7 + 0x42);
        xts_encrypt_sector(sec.ptr, 512, s, k1.ptr, k2.ptr);    // data unit = sector index
        if (!diskWriteSectorsOn(idx, VC_ROOTFS_LBA + s, 1, sec.ptr)) { klog("[vc-voldata] FAIL (rootfs)\n"); return; }
    }

    // (2) random-fill free space (deterministic PRNG here; a real install uses a CSPRNG)
    ulong rng = 0x9E3779B97F4A7C15UL;
    for (uint s = 0; s < VC_FREEFILL_SECTORS; s++) {
        for (int j = 0; j < 512; j += 8) {
            ulong r = xorshift64(rng);
            for (int b = 0; b < 8; b++) sec[j+b] = cast(ubyte)(r >> (8*b));
        }
        if (!diskWriteSectorsOn(idx, VC_FREEFILL_LBA + s, 1, sec.ptr)) { klog("[vc-voldata] FAIL (fill)\n"); return; }
    }

    klog("[vc-voldata] proof: wrote XTS rootfs (0x"); klog_hex(VC_ROOTFS_SECTORS);
    klog(" sectors @0x"); klog_hex(VC_ROOTFS_LBA); klog(") + random free-fill @0x"); klog_hex(VC_FREEFILL_LBA);
    klog(" (host volume_check decrypts + entropy-checks)\n");
}

// ── §E4b: the encrypted-install layout on a REAL 3-partition GPT ──────────────
// Writes the encrypted-install GPT (ESP + system + outer) via the §D2(b) engine, formats
// the ESP FAT32, and places the decoy VeraCrypt header at the SYSTEM PARTITION START — so
// the header now lives at a real partition boundary, not an arbitrary LBA.  The decoy
// header uses the same fixed inputs as the §E2b parity check, so the host validates it
// with the existing `vc-parity <image> <sysFirst>` tool.  Runs last (its 3-part GPT is the
// final on-disk layout); SKIP without a spare disk.
enum ulong VC_INSTALL_ESP_SECTORS = 0x20000;   // 64 MiB ESP
enum ulong VC_INSTALL_SYS_SECTORS = 0x20000;   // 64 MiB system (decoy) partition
// sysFirst = FIRST_USABLE(34) + ESP = 34 + 0x20000 = 0x20022 (= 131106) — host reads here.

@nogc nothrow
public void vcEncryptedInstallProof()
{
    import drivers.block.disk : diskFindTarget;
    import core.diskpart : GptLayout, gptWriteEncryptedToDisk, fatFormatEsp;
    import core.install_cap : InstallWriteCap, mintInstallWriteCap, gatedDiskWrite, revokeInstallWriteCap;

    ulong tsec;
    int idx = diskFindTarget(tsec);
    if (idx < 0) { klog("[vc-install] proof SKIP (no spare disk)\n"); return; }

    // §E4c: the install holds a one-shot, disk-scoped block-write capability (not root).
    auto cap = mintInstallWriteCap(idx);

    GptLayout L;
    if (!gptWriteEncryptedToDisk(idx, tsec, VC_INSTALL_ESP_SECTORS, VC_INSTALL_SYS_SECTORS, L)) {
        klog("[vc-install] proof FAIL (gpt)\n"); revokeInstallWriteCap(cap); return;
    }
    fatFormatEsp(idx, L.espFirst, VC_INSTALL_ESP_SECTORS);

    // decoy system header at the system-partition start (same inputs as the §E2b parity test)
    ubyte[64] salt;
    ubyte[256] mk;
    for (int i = 0; i < 64; i++)  salt[i] = cast(ubyte)(0x11*i + 1);
    for (int i = 0; i < 256; i++) mk[i]   = cast(ubyte)(0xA5 ^ i);
    immutable char[14] pw = ['d','e','c','o','y','-','p','a','s','s','w','o','r','d'];
    ubyte[512] hdr;
    create_veracrypt_header(pw.ptr, 14, salt.ptr, mk.ptr, 0, 1UL<<30, 0x20000, 0x40000000, hdr.ptr);
    if (!gatedDiskWrite(cap, idx, L.sysFirst, 1, hdr.ptr)) { klog("[vc-install] proof FAIL (decoy hdr)\n"); revokeInstallWriteCap(cap); return; }

    // §E5: the two OTHER headers at their real boundaries so the pre-boot loader can route
    // decoy-vs-hidden: outer header at the outer-partition start, hidden header 64 KiB in.
    ubyte[64] saltO, saltH;
    ubyte[256] mkO, mkH;
    for (int i = 0; i < 64; i++)  { saltO[i] = cast(ubyte)(0x22*i + 3); saltH[i] = cast(ubyte)(0x33*i + 5); }
    for (int i = 0; i < 256; i++) { mkO[i]   = cast(ubyte)(0x5A ^ i);   mkH[i]   = cast(ubyte)(0x3C + i); }
    immutable char[14] pwO = ['o','u','t','e','r','-','p','a','s','s','w','o','r','d'];
    immutable char[15] pwH = ['h','i','d','d','e','n','-','p','a','s','s','w','o','r','d'];
    enum ulong VC_HIDDEN_HDR_OFFSET = 128;   // 64 KiB into the outer partition

    create_veracrypt_header(pwO.ptr, 14, saltO.ptr, mkO.ptr, 256UL<<20, 1UL<<30, 0x20000, 0x20000000, hdr.ptr);
    if (!gatedDiskWrite(cap, idx, L.outerFirst, 1, hdr.ptr)) { klog("[vc-install] proof FAIL (outer hdr)\n"); revokeInstallWriteCap(cap); return; }
    create_veracrypt_header(pwH.ptr, 15, saltH.ptr, mkH.ptr, 0, 256UL<<20, 0x20000, 0x10000000, hdr.ptr);
    if (!gatedDiskWrite(cap, idx, L.outerFirst + VC_HIDDEN_HDR_OFFSET, 1, hdr.ptr)) { klog("[vc-install] proof FAIL (hidden hdr)\n"); revokeInstallWriteCap(cap); return; }

    revokeInstallWriteCap(cap);    // one-shot: the cap dies with the install
    klog("[vc-install] proof: 3-part encrypted GPT + ESP FAT + decoy/outer/hidden headers @sys=0x"); klog_hex(L.sysFirst);
    klog(" outer=0x"); klog_hex(L.outerFirst); klog(" hidden=0x"); klog_hex(L.outerFirst + VC_HIDDEN_HDR_OFFSET);
    klog(" (cap-gated; host: sgdisk + vc-parity + preboot-check)\n");
}

// ── The in-kernel FULL-DISK installer (the §E7/F2 install, in the kernel, cap-gated) ──
// Does what the host mkinstall proved: GPT + ESP + the entire system partition encrypted
// (a synthetic rootfs + random-fill) + the entire outer partition random-filled, so an
// entropy map is featureless. Targets a small dedicated spare disk so the in-VM fill is
// fast (a real install streams the actual rootfs + a CSPRNG over the whole disk).
// Tiny geometry: polled AHCI does ~1 write/s with no IRQ-driven I/O, so a whole-disk fill
// is slow — keep the proof disk small (the host mkinstall proves the algorithm at scale; a
// production installer needs faster I/O or runs the fill as a background op, not at boot).
enum ulong VC_FI_ESP        = 0x800;    // 1 MiB ESP (entropy-excluded)
enum ulong VC_FI_SYS        = 0x800;    // 1 MiB system partition
enum uint  VC_FI_ROOTFS_SEC = 64;       // 32 KiB synthetic rootfs (stand-in)
__gshared ubyte[VC_FI_ROOTFS_SEC * 512] g_vcRootfs;   // __gshared, NOT `static` (betterC #PF)

private enum uint VC_FILL_CHUNK = 128;          // 64 KiB / call
__gshared ubyte[VC_FILL_CHUNK * 512] g_vcFillBuf;   // __gshared, NOT `static` (betterC #PF)
private void vcRandomFillRange(ref InstallWriteCap cap, int idx, ulong startLba, ulong endLba, ref ulong rng)
        @nogc nothrow {
    enum uint CHUNK = VC_FILL_CHUNK;
    alias buf = g_vcFillBuf;
    ulong lba = startLba;
    while (lba <= endLba) {
        uint n = cast(uint)((endLba - lba + 1) < CHUNK ? (endLba - lba + 1) : CHUNK);
        for (uint s = 0; s < n; s++)
            for (int j = 0; j < 512; j += 8) {
                ulong r = xorshift64(rng);     // PRNG for the proof; a real install uses a CSPRNG
                for (int b = 0; b < 8; b++) buf[s*512 + j + b] = cast(ubyte)(r >> (8*b));
            }
        gatedDiskWrite(cap, idx, lba, n, buf.ptr);
        lba += n;
    }
}

@nogc nothrow
public void vcFullInstallProof()
{
    import drivers.block.disk : diskFindTargetBySize;
    import core.diskpart : GptLayout, gptWriteEncryptedToDisk, fatFormatEsp;
    import core.install_cap : InstallWriteCap, mintInstallWriteCap, gatedDiskWrite, revokeInstallWriteCap;

    ulong tsec;
    int idx = diskFindTargetBySize(200_000, tsec);     // the small (~96 MiB) dedicated install disk
    if (idx < 0) { klog("[vc-fullinstall] SKIP (no small spare disk)\n"); return; }

    klog("[vc-fullinstall] start (idx=0x"); klog_hex(idx); klog(" disksec=0x"); klog_hex(tsec); klog(")\n");
    auto cap = mintInstallWriteCap(idx);               // §E4c: least-privilege, one-shot
    GptLayout L;
    if (!gptWriteEncryptedToDisk(idx, tsec, VC_FI_ESP, VC_FI_SYS, L)) { klog("[vc-fullinstall] FAIL (gpt)\n"); revokeInstallWriteCap(cap); return; }
    fatFormatEsp(idx, L.espFirst, VC_FI_ESP);

    ubyte[256] mkD; for (int i=0;i<256;i++) mkD[i]=cast(ubyte)(0xA5 ^ i);   // decoy master key
    ubyte[32] k1, k2; for (int i=0;i<32;i++){ k1[i]=mkD[i]; k2[i]=mkD[32+i]; }

    // 1. random-fill the WHOLE system + outer partitions → no zeros anywhere (featureless).
    ulong rng = 0x9E3779B97F4A7C15UL;
    vcRandomFillRange(cap, idx, L.sysFirst,   L.sysLast,   rng);
    klog("[vc-fullinstall] system filled; filling outer\n");
    vcRandomFillRange(cap, idx, L.outerFirst, L.outerLast, rng);
    klog("[vc-fullinstall] outer filled\n");

    // 2. encrypt a synthetic rootfs into the system partition (batched write over the random)
    for (uint i=0;i<VC_FI_ROOTFS_SEC;i++){
        for (int j=0;j<512;j++) g_vcRootfs[i*512+j]=cast(ubyte)(i*7 + j + 0x33);
        xts_encrypt_sector(g_vcRootfs.ptr + i*512, 512, i, k1.ptr, k2.ptr);   // each sector at unit i
    }
    gatedDiskWrite(cap, idx, L.sysFirst+1, VC_FI_ROOTFS_SEC, g_vcRootfs.ptr);

    // 3. the decoy header at the system-partition start (same inputs as the §E2b parity check)
    ubyte[64] salt; for (int i=0;i<64;i++) salt[i]=cast(ubyte)(0x11*i + 1);
    immutable char[14] pw = ['d','e','c','o','y','-','p','a','s','s','w','o','r','d'];
    ubyte[512] hdr;
    create_veracrypt_header(pw.ptr, 14, salt.ptr, mkD.ptr, 0, 1UL<<30, 0x20000, 0x40000000, hdr.ptr);
    gatedDiskWrite(cap, idx, L.sysFirst, 1, hdr.ptr);

    revokeInstallWriteCap(cap);
    klog("[vc-fullinstall] FULL encrypted install on idx=0x"); klog_hex(idx);
    klog(" disksec=0x"); klog_hex(tsec); klog(" sys=0x"); klog_hex(L.sysFirst);
    klog(" outer=0x"); klog_hex(L.outerFirst);
    klog(" (cap-gated; host: sgdisk + entropy featureless + rootfs decrypts)\n");
}

// ─── In-OS BOOTABLE installer (INSTALLER §D: install the running OS to a disk) ────────
// Writes a single-ESP bootable GPT to disk `idx`, then drops the prebuilt FAT32 boot
// image (the "esp-image" boot module: limine BOOTX64.EFI + kernel + modules + limine.conf)
// into the ESP, so UEFI firmware boots the installed OS — no install medium needed.
// Cap-gated.  Distinct from the §E ENCRYPTED installer above; this is the plain bootable
// install the desktop "Install to Disk" button drives.  The esp-image module ships only in
// an INSTALL=1 ISO, so on a normal boot the proof SKIPs.

align(8) private struct InstBootModRec { ulong mod_start; ulong mod_end; char[112] name; }  // 64-bit phys (modules can load >4 GiB)

@nogc nothrow
private bool instFindModule(string want, out ulong phys, out ulong size) {
    import core.exports : g_mboot_modules, g_module_count;
    phys = 0; size = 0;
    if (g_mboot_modules is null || g_module_count <= 0) return false;
    auto recs = cast(const(InstBootModRec)*) g_mboot_modules;
    for (int i = 0; i < g_module_count; i++) {
        const(char)* nm = cast(const(char)*)&recs[i].name[0];
        const(char)* base = nm;
        for (const(char)* p = nm; *p != 0; p++) if (*p == '/') base = p + 1;
        size_t j = 0;
        for (; j < want.length; j++) if (base[j] != want[j]) goto next;
        if (base[j] != 0) goto next;
        phys = cast(ulong) recs[i].mod_start;
        size = cast(ulong) recs[i].mod_end - cast(ulong) recs[i].mod_start;
        return true;
    next:;
    }
    return false;
}

// ── Install state machine ────────────────────────────────────────────────────────────────
// The install runs in BATCHES so the desktop can show a progress bar: each /config/install.
// action write advances one batch (installStep) and returns, the GUI reads /config/install.
// progress (installProgressPermille) between writes.  installBootableToDisk() loops to the end
// synchronously for direct/headless callers.
__gshared bool   g_instActive = false;
__gshared bool   g_instDone   = false;
__gshared bool   g_instFailed = false;
__gshared int    g_instIdx;
__gshared ulong  g_instLba, g_instRemaining, g_instTotal, g_instOff;
__gshared ulong  g_instEspFirst, g_instEspSectors;
__gshared const(ubyte)* g_instSrc;
// UPDATE U1-B A/B dual-slot install state (0 => legacy single-ESP path).
__gshared bool   g_abInstall;
__gshared ulong  g_instSlotBFirst, g_instBootEspFirst, g_instBootEspSectors;
__gshared const(ubyte)* g_instBootSrc;
__gshared InstallWriteCap g_instCap;
private enum size_t INST_CONFIG_MAX = 8192;
private enum uint INST_SECRET_MAX = 128;
private enum uint INST_CRYPT_CHUNK = 128;
private enum ubyte INST_PHASE_ESP = 0;
private enum ubyte INST_PHASE_SYS_RANDOM = 1;
private enum ubyte INST_PHASE_OUTER_RANDOM = 2;
private enum ubyte INST_PHASE_DECOY_IMAGE = 3;
private enum ubyte INST_PHASE_HIDDEN_IMAGE = 4;
private enum ubyte INST_PHASE_HEADERS = 5;
private enum ubyte INST_PHASE_SLOTB = 6;     // UPDATE U1-B: stream esp-image → slot-B
private enum ubyte INST_PHASE_BOOTESP = 7;   // UPDATE U1-B: stream esp-boot (arbiter) → ESP-boot
private enum ubyte INST_PHASE_FDE_IMAGE = 8;  // §E6 Full disk: descriptor v3 + esp-image → sys partition
private enum ulong INST_HIDDEN_HDR_OFFSET = 128; // VeraCrypt hidden header, 64 KiB into outer volume.
__gshared char[INST_CONFIG_MAX] g_instConfig;
__gshared uint g_instConfigLen;
__gshared bool g_instConfigPresent;
__gshared bool g_instConfigHidden;
__gshared bool g_instConfigFde;          // §D: encryption == "Full disk"
__gshared char[INST_SECRET_MAX] g_instDiskPassword;   // §D: FDE disk password (RAM only)
__gshared uint g_instDiskPasswordLen;
__gshared bool g_instHiddenMode;
__gshared bool g_instFdeMode;                 // §E6: Full-disk install in flight (3-partition layout, no decoy)
// Whether the outer partition gets the full random pass.  This is the single biggest cost of an
// encrypted install -- on a 500 GB disk it IS the install -- and it buys exactly one thing:
// DENIABILITY.  A hidden volume lives inside the outer partition's free space, so that space must
// be indistinguishable from random or the hidden volume's boundary is visible; a Hidden-OS install
// therefore always fills.  A Full-disk install has no hidden volume to conceal: filling only makes
// the disk LOOK like it might have one.  That is a real property, so it stays available -- but it
// is now the user's choice rather than hours everyone pays by default (install.json
// "outerFill": "deniable" | "fast").
__gshared bool g_instFillOuter = true;
__gshared ubyte g_instPhase;
__gshared ulong g_instProgressDone;
__gshared char[INST_SECRET_MAX] g_instHiddenPassword;
__gshared uint g_instHiddenPasswordLen;
__gshared char[INST_SECRET_MAX] g_instOuterPassword;
__gshared uint g_instOuterPasswordLen;
__gshared char[INST_SECRET_MAX] g_instDecoyBootPassword;
__gshared uint g_instDecoyBootPasswordLen;
__gshared ulong g_instSysFirst, g_instSysSectors;
__gshared ulong g_instOuterFirst, g_instOuterSectors;
__gshared const(ubyte)* g_instDecoyImageSrc;
__gshared ulong g_instDecoyImageSize;
__gshared ulong g_instDecoyImageSectors;
__gshared const(ubyte)* g_instHiddenImageSrc;
__gshared ulong g_instHiddenImageSize;
__gshared ulong g_instHiddenImageSectors;
__gshared ubyte[256] g_instMkD, g_instMkO, g_instMkH;
__gshared ubyte[64] g_instSaltD, g_instSaltO, g_instSaltH;
__gshared ubyte[INST_CRYPT_CHUNK * 512] g_instCryptBuf;

@nogc nothrow
private bool instCtlPrefix(const(char)* cmd, size_t len, string pfx) {
    if (cmd is null || len < pfx.length) return false;
    foreach (i; 0 .. pfx.length) if (cmd[i] != pfx[i]) return false;
    return true;
}

@nogc nothrow
private bool instSliceEq(const(char)* s, uint len, string lit) {
    if (s is null || len != lit.length) return false;
    foreach (i; 0 .. lit.length) if (s[i] != lit[i]) return false;
    return true;
}

@nogc nothrow
private void instClearTransientPasswords() {
    foreach (i; 0 .. g_instHiddenPassword.length) g_instHiddenPassword[i] = 0;
    foreach (i; 0 .. g_instOuterPassword.length) g_instOuterPassword[i] = 0;
    foreach (i; 0 .. g_instDecoyBootPassword.length) g_instDecoyBootPassword[i] = 0;
    foreach (i; 0 .. g_instDiskPassword.length) g_instDiskPassword[i] = 0;
    g_instHiddenPasswordLen = 0;
    g_instOuterPasswordLen = 0;
    g_instDecoyBootPasswordLen = 0;
    g_instDiskPasswordLen = 0;
}

@nogc nothrow
private void instClearHiddenInstallState() {
    instUnpublishJob();
    foreach (i; 0 .. g_instMkD.length) { g_instMkD[i] = 0; g_instMkO[i] = 0; g_instMkH[i] = 0; }
    foreach (i; 0 .. g_instSaltD.length) { g_instSaltD[i] = 0; g_instSaltO[i] = 0; g_instSaltH[i] = 0; }
    g_instHiddenMode = false;
    g_instFdeMode = false;
    g_instPhase = INST_PHASE_ESP;
    g_instProgressDone = 0;
    g_instSysFirst = 0; g_instSysSectors = 0;
    g_instOuterFirst = 0; g_instOuterSectors = 0;
    g_instDecoyImageSrc = null; g_instDecoyImageSize = 0; g_instDecoyImageSectors = 0;
    g_instHiddenImageSrc = null; g_instHiddenImageSize = 0; g_instHiddenImageSectors = 0;
}

@nogc nothrow
private void instStoreSecret(const(char)* val, uint valLen, char[] outBuf, ref uint outLen) {
    outLen = 0;
    foreach (i; 0 .. valLen) {
        if (outLen + 1 >= outBuf.length) break;
        outBuf[outLen++] = val[i];
    }
    if (outLen < outBuf.length) outBuf[outLen] = 0;
}

@nogc nothrow
private bool instJsonKeyEq(const(char)* src, size_t len, size_t p, string key, out size_t afterQuote) {
    afterQuote = p;
    if (p >= len || src[p] != '"') return false;
    ++p;
    foreach (i; 0 .. key.length) {
        if (p + i >= len || src[p + i] != key[i]) return false;
    }
    p += key.length;
    if (p >= len || src[p] != '"') return false;
    afterQuote = p + 1;
    return true;
}

@nogc nothrow private bool instJsonWs(char c) {
    return c == ' ' || c == '\n' || c == '\r' || c == '\t';
}

@nogc nothrow
private bool instJsonGetString(const(char)* src, size_t len, string key, char[] outBuf, ref uint outLen) {
    outLen = 0;
    if (src is null || len == 0) return false;
    foreach (p0; 0 .. len) {
        size_t p;
        if (!instJsonKeyEq(src, len, p0, key, p)) continue;
        while (p < len && instJsonWs(src[p])) ++p;
        if (p >= len || src[p] != ':') continue;
        ++p;
        while (p < len && instJsonWs(src[p])) ++p;
        if (p >= len || src[p] != '"') continue;
        ++p;
        while (p < len) {
            char c = src[p++];
            if (c == '"') {
                if (outLen < outBuf.length) outBuf[outLen] = 0;
                return true;
            }
            if (c == '\\' && p < len) {
                char e = src[p++];
                if (e == '"' || e == '\\' || e == '/') c = e;
                else if (e == 'n') c = '\n';
                else if (e == 't') c = '\t';
                else c = e;
            }
            if (c >= 0x20 && c < 0x7f && outLen + 1 < outBuf.length)
                outBuf[outLen++] = c;
        }
    }
    return false;
}

@nogc nothrow
private void instCfgAppend(const(char)* s) {
    if (s is null) return;
    while (*s != 0 && g_instConfigLen + 1 < INST_CONFIG_MAX)
        g_instConfig[g_instConfigLen++] = *s++;
}

@nogc nothrow
private void instCfgAppendSlice(const(char)* s, uint len) {
    foreach (i; 0 .. len)
        if (g_instConfigLen + 1 < INST_CONFIG_MAX)
            g_instConfig[g_instConfigLen++] = s[i];
}

@nogc nothrow
private void instCfgAppendJsonString(const(char)* key, const(char)* val, uint valLen, bool comma) {
    instCfgAppend("  \"".ptr);
    instCfgAppend(key);
    instCfgAppend("\": \"".ptr);
    foreach (i; 0 .. valLen) {
        const char c = val[i];
        if (c == '"' || c == '\\') {
            if (g_instConfigLen + 2 < INST_CONFIG_MAX) {
                g_instConfig[g_instConfigLen++] = '\\';
                g_instConfig[g_instConfigLen++] = c;
            }
        } else if (c >= 0x20 && c < 0x7f) {
            if (g_instConfigLen + 1 < INST_CONFIG_MAX)
                g_instConfig[g_instConfigLen++] = c;
        }
    }
    instCfgAppend(comma ? "\",\n".ptr : "\"\n".ptr);
}

@nogc nothrow
private void instHexSha512(const(char)* val, uint valLen, char[] outHex, ref uint outLen) {
    static immutable char[16] hex = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'];
    outLen = 0;
    if (valLen == 0) {
        if (outHex.length > 0) outHex[0] = 0;
        return;
    }
    ubyte[64] digest;
    sha512_hash(cast(const(ubyte)*)val, valLen, digest.ptr);
    foreach (i; 0 .. 64) {
        if (outLen + 2 >= outHex.length) break;
        outHex[outLen++] = hex[(digest[i] >> 4) & 0xf];
        outHex[outLen++] = hex[digest[i] & 0xf];
    }
    if (outLen < outHex.length) outHex[outLen] = 0;
}

@nogc nothrow
private void instGetOrDefault(const(char)* src, size_t len, string key,
                              const(char)* def, char[] outBuf, ref uint outLen) {
    if (instJsonGetString(src, len, key, outBuf, outLen)) return;
    outLen = 0;
    while (def !is null && def[outLen] != 0 && outLen + 1 < outBuf.length) {
        outBuf[outLen] = def[outLen];
        ++outLen;
    }
    if (outLen < outBuf.length) outBuf[outLen] = 0;
}

@nogc nothrow
private bool installBuildPersistedConfig(const(char)* raw, size_t len) {
    char[128] hostname; uint hostnameLen;
    char[128] user; uint userLen;
    char[128] encryption; uint encryptionLen;
    char[128] decoyUser; uint decoyUserLen;
    char[128] decoyFullName; uint decoyFullNameLen;
    char[128] decoyHostname; uint decoyHostnameLen;
    char[128] pw; uint pwLen;
    char[129] hash; uint hashLen;

    g_instConfigHidden = false;
    g_instConfigFde = false;
    g_instFillOuter = true;
    instClearTransientPasswords();
    g_instConfigLen = 0;
    instCfgAppend("{\n");
    instCfgAppendJsonString("schema".ptr, "epin.install.v1".ptr, cast(uint)"epin.install.v1".length, true);
    instGetOrDefault(raw, len, "hostname", "epin".ptr, hostname[], hostnameLen);
    instCfgAppendJsonString("hostname".ptr, hostname.ptr, hostnameLen, true);
    instGetOrDefault(raw, len, "user", "user".ptr, user[], userLen);
    instCfgAppendJsonString("user".ptr, user.ptr, userLen, true);

    // INSTALLER §Phase5/Phase7: carry the declarative, non-secret wizard selections through
    // into the persisted /install.json so first boot consumes them (locale/keyboard/timezone/
    // network/filesystem/target-disk/boot-integrity/identities).  These never hold secrets, so
    // they are stored verbatim (unlike the password fields, which are hashed below).
    {
        char[160] v; uint vl;
        instGetOrDefault(raw, len, "userFullName", "".ptr, v[], vl);
        instCfgAppendJsonString("userFullName".ptr, v.ptr, vl, true);
        instGetOrDefault(raw, len, "locale", "en_US".ptr, v[], vl);
        instCfgAppendJsonString("locale".ptr, v.ptr, vl, true);
        instGetOrDefault(raw, len, "localeName", "English (US)".ptr, v[], vl);
        instCfgAppendJsonString("localeName".ptr, v.ptr, vl, true);
        instGetOrDefault(raw, len, "keymap", "us".ptr, v[], vl);
        instCfgAppendJsonString("keymap".ptr, v.ptr, vl, true);
        instGetOrDefault(raw, len, "timezone", "UTC".ptr, v[], vl);
        instCfgAppendJsonString("timezone".ptr, v.ptr, vl, true);
        instGetOrDefault(raw, len, "network", "offline".ptr, v[], vl);
        instCfgAppendJsonString("network".ptr, v.ptr, vl, true);
        instGetOrDefault(raw, len, "filesystem", "ext4".ptr, v[], vl);
        instCfgAppendJsonString("filesystem".ptr, v.ptr, vl, true);
        instGetOrDefault(raw, len, "targetDisk", "auto".ptr, v[], vl);
        instCfgAppendJsonString("targetDisk".ptr, v.ptr, vl, true);
        instGetOrDefault(raw, len, "bootIntegrity", "off".ptr, v[], vl);
        instCfgAppendJsonString("bootIntegrity".ptr, v.ptr, vl, true);
        instGetOrDefault(raw, len, "identities", "".ptr, v[], vl);
        instCfgAppendJsonString("identities".ptr, v.ptr, vl, true);
        instGetOrDefault(raw, len, "drivers", "".ptr, v[], vl);
        instCfgAppendJsonString("drivers".ptr, v.ptr, vl, true);
    }

    // Encryption mode is detected BEFORE the password fields so the scheme-password hashes can be
    // withheld on encrypted installs.  design-review RISK: install.json lives inside the (encrypted)
    // esp-image, but for a Hidden/Full-disk install it must NOT enumerate unsalted fast SHA-512 of
    // every scheme password — that hands an attacker who opens the volume a cheap crack target for
    // the disk/hidden/outer/decoy-boot passwords.  We keep only non-secret declarative fields plus
    // the login credential (userPasswordSha512), and capture the scheme passwords into RAM-only
    // transients that installStep wipes after use.  Never hash the disk password into the JSON.
    instGetOrDefault(raw, len, "encryption", "none".ptr, encryption[], encryptionLen);
    g_instConfigHidden = instSliceEq(encryption.ptr, encryptionLen, "Hidden OS") ||
                         instSliceEq(encryption.ptr, encryptionLen, "hidden");
    {   // "outerFill": "fast" trades the hidden-volume disguise for hours of writing.  Hidden OS
        // ignores it: there the fill is the mechanism, not a cosmetic.
        char[32] fill; uint fillLen;
        instJsonGetString(raw, len, "outerFill", fill[], fillLen);
        g_instFillOuter = !(instSliceEq(fill.ptr, fillLen, "fast"));
    }
    g_instConfigFde = instSliceEq(encryption.ptr, encryptionLen, "Full disk") ||
                      instSliceEq(encryption.ptr, encryptionLen, "fulldisk") ||
                      instSliceEq(encryption.ptr, encryptionLen, "full");
    const bool encrypted = g_instConfigHidden || g_instConfigFde;

    instJsonGetString(raw, len, "userPassword", pw[], pwLen);
    instHexSha512(pw.ptr, pwLen, hash[], hashLen);
    instCfgAppendJsonString("userPasswordSha512".ptr, hash.ptr, hashLen, true);
    instCfgAppendJsonString("encryption".ptr, encryption.ptr, encryptionLen, true);

    // FDE disk password: from "diskPassword", falling back to "hiddenPassword" for the old installer
    // (which only emitted the Hidden-OS field names).  RAM only — never hashed into the JSON.
    if (g_instConfigFde) {
        instJsonGetString(raw, len, "diskPassword", pw[], pwLen);
        if (pwLen == 0) instJsonGetString(raw, len, "hiddenPassword", pw[], pwLen);
        instStoreSecret(pw.ptr, pwLen, g_instDiskPassword[], g_instDiskPasswordLen);
    }

    instJsonGetString(raw, len, "hiddenPassword", pw[], pwLen);
    if (g_instConfigHidden) instStoreSecret(pw.ptr, pwLen, g_instHiddenPassword[], g_instHiddenPasswordLen);
    if (!encrypted) {
        instHexSha512(pw.ptr, pwLen, hash[], hashLen);
        instCfgAppendJsonString("hiddenPasswordSha512".ptr, hash.ptr, hashLen, true);
    }
    instJsonGetString(raw, len, "outerPassword", pw[], pwLen);
    if (g_instConfigHidden) instStoreSecret(pw.ptr, pwLen, g_instOuterPassword[], g_instOuterPasswordLen);
    if (!encrypted) {
        instHexSha512(pw.ptr, pwLen, hash[], hashLen);
        instCfgAppendJsonString("outerPasswordSha512".ptr, hash.ptr, hashLen, true);
    }
    instJsonGetString(raw, len, "decoyBootPassword", pw[], pwLen);
    if (g_instConfigHidden) instStoreSecret(pw.ptr, pwLen, g_instDecoyBootPassword[], g_instDecoyBootPasswordLen);
    if (!encrypted) {
        instHexSha512(pw.ptr, pwLen, hash[], hashLen);
        instCfgAppendJsonString("decoyBootPasswordSha512".ptr, hash.ptr, hashLen, true);
    }
    instGetOrDefault(raw, len, "decoyUser", "decoy".ptr, decoyUser[], decoyUserLen);
    instCfgAppendJsonString("decoyUser".ptr, decoyUser.ptr, decoyUserLen, true);
    instGetOrDefault(raw, len, "decoyFullName", "Decoy User".ptr, decoyFullName[], decoyFullNameLen);
    instCfgAppendJsonString("decoyFullName".ptr, decoyFullName.ptr, decoyFullNameLen, true);
    if (!encrypted) {
        instJsonGetString(raw, len, "decoyPassword", pw[], pwLen);
        instHexSha512(pw.ptr, pwLen, hash[], hashLen);
        instCfgAppendJsonString("decoyPasswordSha512".ptr, hash.ptr, hashLen, true);
    }
    instGetOrDefault(raw, len, "decoyHostname", "decoy-pc".ptr, decoyHostname[], decoyHostnameLen);
    instCfgAppendJsonString("decoyHostname".ptr, decoyHostname.ptr, decoyHostnameLen, false);
    instCfgAppend("}\n".ptr);
    g_instConfig[g_instConfigLen] = 0;
    return g_instConfigLen > 0 && g_instConfigLen < INST_CONFIG_MAX;
}

@nogc nothrow
private bool installCaptureConfig(const(char)* json, size_t len) {
    if (json is null || len == 0) return false;
    while (len > 0 && (json[len - 1] == 0 || json[len - 1] == '\r')) --len;
    if (!installBuildPersistedConfig(json, len)) return false;
    g_instConfigPresent = true;
    klog("[install] captured install config bytes=0x"); klog_hex(g_instConfigLen);
    klog(" (passwords hashed for persistence)\n");
    return true;
}

@nogc nothrow
private void installEnsureDefaultConfig() {
    if (g_instConfigPresent && g_instConfigLen > 0) return;
    // No install.json was captured: a headless hook (installBeginHiddenTest / installBeginFdeTest)
    // or a bare `echo install > /config/install.action`.  The hooks set the mode and the passwords
    // DIRECTLY, so this must not reset them -- it used to, which was harmless only because it ran
    // after the headers were written; the in-RAM install.json patch now runs it first, and a
    // reset here turned into "Full disk selected without a disk password" at header time.  The
    // text below is only the persisted configuration; its "encryption" value follows the mode.
    static immutable string d =
`{
  "schema": "epin.install.v1",
  "hostname": "epin",
  "user": "user",
  "userFullName": "",
  "locale": "en_US",
  "localeName": "English (US)",
  "keymap": "us",
  "timezone": "UTC",
  "network": "offline",
  "filesystem": "ext4",
  "targetDisk": "auto",
  "bootIntegrity": "off",
  "identities": "",
  "drivers": "",
  "userPasswordSha512": "",
  "encryption": "none",
  "hiddenPasswordSha512": "",
  "outerPasswordSha512": "",
  "decoyBootPasswordSha512": "",
  "decoyUser": "decoy",
  "decoyFullName": "Decoy User",
  "decoyPasswordSha512": "",
  "decoyHostname": "decoy-pc"
}
`;
    foreach (i; 0 .. d.length) g_instConfig[i] = d[i];
    g_instConfig[d.length] = 0;
    g_instConfigLen = cast(uint)d.length;
    g_instConfigPresent = true;
    // "encryption": "none" -> the real mode ("Hidden OS" / "Full disk" both fit in the slot when
    // padded: the literal is 4 chars; the replacements are 9, so the buffer is shifted right).
    if (g_instConfigHidden || g_instConfigFde) {
        static immutable string key = `"encryption": "none"`;
        static immutable string hid = `"encryption": "Hidden OS"`;
        static immutable string fde = `"encryption": "Full disk"`;
        const string repl = g_instConfigHidden ? hid : fde;
        size_t at = size_t.max;
        for (size_t i = 0; i + key.length <= g_instConfigLen; i++) {
            bool m = true;
            foreach (j; 0 .. key.length) if (g_instConfig[i + j] != key[j]) { m = false; break; }
            if (m) { at = i; break; }
        }
        if (at != size_t.max && g_instConfigLen + (repl.length - key.length) < INST_CONFIG_MAX - 1) {
            const size_t grow = repl.length - key.length;
            // shift the tail right by `grow`, then drop the replacement in
            for (size_t i = g_instConfigLen; i-- > at + key.length;) g_instConfig[i + grow] = g_instConfig[i];
            foreach (j; 0 .. repl.length) g_instConfig[at + j] = repl[j];
            g_instConfigLen += cast(uint)grow;
            g_instConfig[g_instConfigLen] = 0;
        }
    }
}

@nogc nothrow private ushort instFat16(const(ubyte)* p) {
    return cast(ushort)(cast(ushort)p[0] | (cast(ushort)p[1] << 8));
}

@nogc nothrow private uint instFat32(const(ubyte)* p) {
    return cast(uint)p[0] |
           (cast(uint)p[1] << 8) |
           (cast(uint)p[2] << 16) |
           (cast(uint)p[3] << 24);
}

@nogc nothrow private void instPutFat32(ubyte* p, uint v) {
    p[0] = cast(ubyte)(v & 0xff);
    p[1] = cast(ubyte)((v >> 8) & 0xff);
    p[2] = cast(ubyte)((v >> 16) & 0xff);
    p[3] = cast(ubyte)((v >> 24) & 0xff);
}

@nogc nothrow private bool instShortNameEq(const(ubyte)* e) {
    static immutable ubyte[11] want = ['I','N','S','T','A','L','~','1','J','S','O'];
    foreach (i; 0 .. 11) if (e[i] != want[i]) return false;
    return true;
}

@nogc nothrow
private bool instFatNextCluster(int idx, ulong fatFirst, uint cluster, out uint next) {
    import drivers.block.disk : diskReadSectorsOn;
    enum uint SEC = 512;
    ubyte[SEC] sec = void;
    const ulong off = cast(ulong)cluster * 4UL;
    if (!diskReadSectorsOn(idx, fatFirst + off / SEC, 1, sec.ptr)) return false;
    next = instFat32(sec.ptr + cast(size_t)(off % SEC)) & 0x0fffffffu;
    return true;
}

@nogc nothrow
private ulong instFatClusterLba(ulong dataFirst, ubyte spc, uint cluster) {
    return dataFirst + (cast(ulong)cluster - 2UL) * cast(ulong)spc;
}

@nogc nothrow
private bool installPersistConfigToEsp() {
    import drivers.block.disk : diskReadSectorsOn;
    import core.install_cap : gatedDiskWrite;
    enum uint SEC = 512;
    installEnsureDefaultConfig();
    // §E6: an encrypted install's ESP is the preboot ESP (no install.json); the config was
    // patched into the in-RAM boot volume before it was streamed (installPatchConfigIntoImage).
    if (g_instHiddenMode || g_instFdeMode) return true;
    if (g_instEspFirst == 0 || g_instConfigLen == 0) return false;

    ubyte[SEC] sec = void;
    if (!diskReadSectorsOn(g_instIdx, g_instEspFirst, 1, sec.ptr)) return false;
    const ushort bps = instFat16(sec.ptr + 11);
    const ubyte spc = sec[13];
    const ushort reserved = instFat16(sec.ptr + 14);
    const ubyte fats = sec[16];
    uint fatSz = instFat32(sec.ptr + 36);
    if (fatSz == 0) fatSz = instFat16(sec.ptr + 22);
    const uint rootCluster = instFat32(sec.ptr + 44);
    if (bps != SEC || spc == 0 || reserved == 0 || fats == 0 || fatSz == 0 || rootCluster < 2)
        return false;

    const ulong fatFirst = g_instEspFirst + reserved;
    const ulong dataFirst = g_instEspFirst + reserved + cast(ulong)fats * fatSz;

    uint dirCluster = rootCluster;
    ulong dirEntryLba = 0;
    size_t dirEntryOff = 0;
    uint fileCluster = 0;
    bool found = false;
    while (dirCluster >= 2 && dirCluster < 0x0ffffff8u && !found) {
        const ulong clba = instFatClusterLba(dataFirst, spc, dirCluster);
        foreach (s; 0 .. spc) {
            if (!diskReadSectorsOn(g_instIdx, clba + s, 1, sec.ptr)) return false;
            foreach (off; 0 .. 16) {
                const size_t o = cast(size_t)off * 32;
                if (sec[o] == 0x00) break;
                if (sec[o] == 0xE5 || sec[o + 11] == 0x0F) continue;
                if (!instShortNameEq(sec.ptr + o)) continue;
                dirEntryLba = clba + s;
                dirEntryOff = o;
                fileCluster = (instFat16(sec.ptr + o + 20) << 16) |
                              instFat16(sec.ptr + o + 26);
                found = true;
                break;
            }
            if (found) break;
        }
        if (found) break;
        uint next;
        if (!instFatNextCluster(g_instIdx, fatFirst, dirCluster, next)) return false;
        if (next == 0 || next == dirCluster) break;
        dirCluster = next;
    }
    if (!found || fileCluster < 2) {
        klog("[install] FAIL: ESP install.json placeholder not found\n");
        return false;
    }

    instPutFat32(sec.ptr + dirEntryOff + 28, g_instConfigLen);
    if (!gatedDiskWrite(g_instCap, g_instIdx, dirEntryLba, 1, sec.ptr)) return false;

    uint cluster = fileCluster;
    uint remaining = g_instConfigLen;
    uint copied = 0;
    while (cluster >= 2 && cluster < 0x0ffffff8u && remaining > 0) {
        const ulong clba = instFatClusterLba(dataFirst, spc, cluster);
        foreach (s; 0 .. spc) {
            foreach (i; 0 .. SEC) sec[i] = 0;
            uint n = remaining > SEC ? SEC : remaining;
            foreach (i; 0 .. n) sec[i] = cast(ubyte)g_instConfig[copied + i];
            if (!gatedDiskWrite(g_instCap, g_instIdx, clba + s, 1, sec.ptr)) return false;
            copied += n;
            remaining -= n;
            if (remaining == 0) break;
        }
        if (remaining == 0) break;
        uint next;
        if (!instFatNextCluster(g_instIdx, fatFirst, cluster, next)) return false;
        if (next == 0 || next == cluster) break;
        cluster = next;
    }
    if (remaining != 0) {
        klog("[install] FAIL: ESP install.json placeholder too small\n");
        return false;
    }
    klog("[install] persisted install.json bytes=0x"); klog_hex(g_instConfigLen); klog("\n");
    return true;
}

// §E6: patch /install.json into the IN-MEMORY esp-image (the Limine boot module is plain RAM
// through the HHDM), so an encrypted install carries its configuration INSIDE the encrypted
// boot volume.  Same FAT32 walk as installPersistConfigToEsp, over a byte buffer instead of the
// disk: the root directory is scanned for the 8.3 entry INSTALL.JSON (the ISO builder creates it
// as a 32 KiB zero placeholder so no cluster allocation is ever needed), its size field is set
// and its cluster chain filled.  A plain install keeps the on-disk path.
@nogc nothrow
private bool installPatchConfigIntoImage(ubyte* img, ulong imgSize) {
    enum uint SEC = 512;
    installEnsureDefaultConfig();
    if (img is null || imgSize < 65536 || g_instConfigLen == 0) return false;
    const ubyte* bs = img;
    const ushort bps = instFat16(bs + 11);
    const ubyte spc = bs[13];
    const ushort reserved = instFat16(bs + 14);
    const ubyte fats = bs[16];
    uint fatSz = instFat32(bs + 36);
    if (fatSz == 0) fatSz = instFat16(bs + 22);
    const uint rootCluster = instFat32(bs + 44);
    if (bps != SEC || spc == 0 || reserved == 0 || fats == 0 || fatSz == 0 || rootCluster < 2)
        return false;
    const ulong totalSectors = imgSize / SEC;
    const ulong fatFirst = reserved;
    const ulong dataFirst = reserved + cast(ulong)fats * fatSz;
    if (dataFirst >= totalSectors) return false;

    // FAT32 next-cluster lookup, in memory
    bool nextCluster(uint c, out uint nx) @nogc nothrow {
        const ulong byteOff = fatFirst * SEC + cast(ulong)c * 4;
        if (byteOff + 4 > imgSize) return false;
        nx = instFat32(img + byteOff) & 0x0fffffffu;
        return true;
    }
    ulong clusterSector(uint c) @nogc nothrow { return dataFirst + cast(ulong)(c - 2) * spc; }

    uint dirCluster = rootCluster;
    ulong entryOff = 0;
    uint fileCluster = 0;
    bool found = false;
    uint guard = 0;
    while (dirCluster >= 2 && dirCluster < 0x0ffffff8u && !found && guard++ < 4096) {
        const ulong clba = clusterSector(dirCluster);
        foreach (sIdx; 0 .. spc) {
            const ulong so = (clba + sIdx) * SEC;
            if (so + SEC > imgSize) return false;
            const ubyte* sec = img + so;
            foreach (off; 0 .. 16) {
                const size_t o = cast(size_t)off * 32;
                if (sec[o] == 0x00) break;
                if (sec[o] == 0xE5 || sec[o + 11] == 0x0F) continue;
                if (!instShortNameEq(sec + o)) continue;
                entryOff = so + o;
                fileCluster = (instFat16(sec + o + 20) << 16) | instFat16(sec + o + 26);
                found = true;
                break;
            }
            if (found) break;
        }
        if (found) break;
        uint nx;
        if (!nextCluster(dirCluster, nx)) return false;
        if (nx == 0 || nx == dirCluster) break;
        dirCluster = nx;
    }
    if (!found || fileCluster < 2) {
        klog("[install] FAIL: boot volume image has no install.json placeholder\n");
        return false;
    }
    instPutFat32(img + entryOff + 28, g_instConfigLen);

    uint cluster = fileCluster;
    uint remaining = g_instConfigLen;
    uint copied = 0;
    guard = 0;
    while (cluster >= 2 && cluster < 0x0ffffff8u && remaining > 0 && guard++ < 4096) {
        const ulong clba = clusterSector(cluster);
        foreach (sIdx; 0 .. spc) {
            const ulong so = (clba + sIdx) * SEC;
            if (so + SEC > imgSize) return false;
            ubyte* sec = img + so;
            foreach (i; 0 .. SEC) sec[i] = 0;
            const uint n = remaining > SEC ? SEC : remaining;
            foreach (i; 0 .. n) sec[i] = cast(ubyte)g_instConfig[copied + i];
            copied += n;
            remaining -= n;
            if (remaining == 0) break;
        }
        if (remaining == 0) break;
        uint nx;
        if (!nextCluster(cluster, nx)) return false;
        if (nx == 0 || nx == cluster) break;
        cluster = nx;
    }
    if (remaining != 0) {
        klog("[install] FAIL: boot volume install.json placeholder too small\n");
        return false;
    }
    klog("[install] install.json placed in the boot volume image bytes=0x"); klog_hex(g_instConfigLen); klog("\n");
    return true;
}

// ── §E6: streaming an encrypted install WITHOUT stalling the desktop ─────────────────────────
//
// Every byte of an encrypted install is either CSPRNG output (the random fill) or XTS ciphertext
// (the payloads), and until now all of it was computed inside the kernel loop with the Big Kernel
// Lock held, one batch per millisecond: the compositor, the cursor and every app got what was left
// of each millisecond after ~15-45 ms of crypto.  That is the "cursor barely moves while the OS
// installs".
//
// Now the work is split.  PREPARATION (random generation / encryption) fills 1 MiB staging slots
// and needs no lock -- it runs on the SECOND CORE when one is up (installApWorkerStep, called from
// the AP's kernel loop), and on the BSP only as a fallback for single-CPU machines.  WRITING (one
// DMA per slot) is all the BSP loop does, under an input-aware time budget (kernel_main.d), so the
// desktop keeps the core while a person is moving the mouse.
//
// Cross-CPU protocol (x86-TSO + mfence; the D compiler is kept honest with volatileLoad/Store):
//   BSP publishes a job under the BKL: parameters, seeded RNG, then g_instJobGen := n (n > 0).
//   AP: reads gen; claims a FREE slot (state 1); re-checks gen; prepares; state := READY.
//   BSP: writes READY slots in unit order; state := FREE.
//   BSP unpublishes: gen := 0, waits until the AP is not inside a prepare, clears every slot.
import core.random : ChaChaCtx, chacha_seed, chacha_fill, chacha_needs_reseed, chacha_ratchet;
import core.volatile : volatileLoad, volatileStore;
import ldc.llvmasm : __asm;
enum uint INST_STAGE_SECTORS = 2048;                 // 1 MiB per slot
enum uint INST_STAGE_SLOTS   = 4;
enum ubyte SLOT_FREE = 0, SLOT_FILLING = 1, SLOT_READY = 2;
__gshared ubyte[INST_STAGE_SECTORS * 512][INST_STAGE_SLOTS] g_instStageBuf;
__gshared ulong[INST_STAGE_SLOTS] g_instSlotFirstUnit;
__gshared uint[INST_STAGE_SLOTS]  g_instSlotSectors;
__gshared ubyte[INST_STAGE_SLOTS] g_instSlotState;
__gshared uint   g_instJobGen = 0;                    // 0 = no job
__gshared uint   g_instJobSeq = 0;
__gshared ubyte  g_instJobKind = 0;                   // 1 random fill, 2 encrypt image
__gshared ulong  g_instJobEndUnit = 0;
__gshared ulong  g_instPrepNext = 0;                  // next unit to prepare (one preparer at a time)
__gshared ubyte[32] g_instJobK1, g_instJobK2;
__gshared const(ubyte)* g_instJobSrc = null;
__gshared ulong  g_instJobImageSize = 0;
__gshared bool   g_instJobDescriptor = false;         // unit 0 is a synthesized ANOSBOOT descriptor
__gshared ChaChaCtx g_instRng;
__gshared ubyte  g_instApWorkerSeen = 0;              // the AP has visited installApWorkerStep
__gshared ubyte  g_instApPreparing = 0;
// Where the AP last was inside its worker, so a stall dump can say which step it died on rather
// than only that it stopped.  1 locked, 2 slot claimed, 3 ratcheting the RNG, 4 generating,
// 5 encrypting, 6 finished the chunk, 7 released.
__gshared ubyte  g_instApStage = 0;
__gshared ulong  g_instApSteps = 0;                   // times the AP entered the worker at all
__gshared uint   g_instPrepLock = 0;                  // xchg lock: exactly one preparer at a time
__gshared ulong  g_instWaitSinceMs = 0;               // BSP: how long it has waited on the AP for a READY slot
__gshared ulong  g_instApChunks = 0;                  // chunks prepared on the AP (for the DONE line)
__gshared ulong  g_instBspChunks = 0;                 // ... and on the BSP (fallback)

@nogc nothrow private void instFence() { __asm("mfence", "~{memory}"); }
// The preparer lock guards g_instPrepNext + the slot claim.  Non-blocking on both sides: a loser
// simply comes back later.  (The AP can appear mid-install -- it is released after the desktop is
// up -- so the BSP fallback and the AP must never both believe they own the next unit.)
@nogc nothrow private bool instPrepTryLock() {
    uint old = void; uint* p = &g_instPrepLock;
    asm @nogc nothrow { mov RDX, p; mov EAX, 1; xchg [RDX], EAX; mov old, EAX; }
    return old == 0;
}
@nogc nothrow private void instPrepUnlock() { instFence(); volatileStore(&g_instPrepLock, 0u); }

@nogc nothrow
private void instUnpublishJob() {
    volatileStore(&g_instJobGen, 0u);
    instFence();
    for (uint spin = 0; spin < 400_000_000u && (volatileLoad(&g_instApPreparing) != 0); ++spin) { __asm("pause", ""); }
    foreach (i; 0 .. INST_STAGE_SLOTS) volatileStore(&g_instSlotState[i], SLOT_FREE);
    g_instJobKind = 0; g_instJobEndUnit = 0; g_instPrepNext = 0;
    g_instJobSrc = null; g_instJobImageSize = 0; g_instJobDescriptor = false;
    foreach (i; 0 .. 32) { g_instJobK1[i] = 0; g_instJobK2[i] = 0; }
    instFence();
}

// BSP, under the BKL.  kind 1 = random fill of `units` sectors; kind 2 = encrypt the image
// (descriptor + image when `desc`) with k1/k2.
@nogc nothrow
private void instPublishJob(ubyte kind, ulong units, const(ubyte)* src, ulong imageSize, bool desc,
                            const(ubyte)* k1, const(ubyte)* k2) {
    instUnpublishJob();
    g_instJobKind = kind;
    g_instJobEndUnit = units;
    g_instPrepNext = 0;
    g_instJobSrc = src; g_instJobImageSize = imageSize; g_instJobDescriptor = desc;
    foreach (i; 0 .. 32) { g_instJobK1[i] = k1 ? k1[i] : 0; g_instJobK2[i] = k2 ? k2[i] : 0; }
    chacha_seed(g_instRng);                            // pool access: BSP only
    instFence();
    volatileStore(&g_instJobGen, ++g_instJobSeq);
}

// Prepare the next chunk into `slot`.  Pure computation on the job's own state: no lock, any CPU.
@nogc nothrow
private bool installPrepareSlot(uint slot, bool onAp) {
    enum uint SEC = 512;
    const ulong next = g_instPrepNext;
    if (next >= g_instJobEndUnit) return false;
    // The CSPRNG's periodic rekey does not run on the AP.  Measured: the AP faults inside
    // chacha_ratchet on the first rekey (64 chunks in, exactly CHACHA_REKEY_BYTES) and halts
    // there holding the staging lock, which stalls the install until the watchdog breaks it.
    // The BSP rekeys eagerly in installStep, so declining here costs the AP one pass, not 64 MiB.
    if (onAp && g_instJobKind == 1 && chacha_needs_reseed(g_instRng)) return false;
    const ulong left = g_instJobEndUnit - next;
    const uint n = cast(uint)(left < INST_STAGE_SECTORS ? left : INST_STAGE_SECTORS);
    ubyte* buf = g_instStageBuf[slot].ptr;
    if (g_instJobKind == 1) {
        if (chacha_needs_reseed(g_instRng)) chacha_ratchet(g_instRng);   // BSP only (see above)
        volatileStore(&g_instApStage, cast(ubyte)4);
        chacha_fill(g_instRng, buf, cast(ulong)n * SEC);
    } else {
        volatileStore(&g_instApStage, cast(ubyte)5);
        foreach (sIdx; 0 .. n) {
            ubyte* out_ = buf + cast(size_t)sIdx * SEC;
            const ulong unit = next + sIdx;
            if (g_instJobDescriptor && unit == 0) {
                instBuildAnosbootDescriptor(out_, g_instJobImageSize);
            } else {
                const ulong byteOff = (g_instJobDescriptor ? unit - 1 : unit) * SEC;
                const ulong bytesLeft = g_instJobImageSize > byteOff ? g_instJobImageSize - byteOff : 0;
                const ulong copyBytes = bytesLeft < SEC ? bytesLeft : SEC;
                foreach (i; 0 .. cast(size_t)copyBytes) out_[i] = g_instJobSrc[cast(size_t)byteOff + i];
                foreach (i; cast(size_t)copyBytes .. cast(size_t)SEC) out_[i] = 0;
            }
            xts_encrypt_sector(out_, SEC, unit, g_instJobK1.ptr, g_instJobK2.ptr);
        }
    }
    g_instSlotFirstUnit[slot] = next;
    g_instSlotSectors[slot] = n;
    g_instPrepNext = next + n;
    instFence();
    volatileStore(&g_instSlotState[slot], SLOT_READY);
    return true;
}

// The AP's hook: called from its kernel loop (kmain.d apKernelLoopBody) WITHOUT the BKL.  One chunk
// per call; returns quickly when there is nothing to do.
public bool installApJobActive() @nogc nothrow { return volatileLoad(&g_instJobGen) != 0; }
public void installApWorkerStep() @nogc nothrow {
    volatileStore(&g_instApWorkerSeen, cast(ubyte)1);
    ++g_instApSteps;
    const uint gen = volatileLoad(&g_instJobGen);
    if (gen == 0) return;
    // The AP prepares the RANDOM FILL only (kind 1).  It faults and halts inside the XTS path,
    // the same way it used to inside chacha_ratchet: both are -O2-vectorised routines with stack
    // buffers, while the ChaCha fill -- which the AP runs by the gigabyte without trouble -- is
    // not.  That points at the AP's stack alignment after apSwitchToUserspace rather than at
    // anything in the crypto, and chasing it belongs with the SMP code, not here.
    //
    // Splitting the work this way costs almost nothing: the fill is the phase that grows with the
    // disk (hours on a big one), the payload is a fixed ~512 MiB the boot core does in seconds.
    if (g_instJobKind != 1) return;
    if (!instPrepTryLock()) return;                       // the BSP fallback is mid-prepare
    volatileStore(&g_instApStage, cast(ubyte)1);
    volatileStore(&g_instApPreparing, cast(ubyte)1);
    instFence();
    if (volatileLoad(&g_instJobGen) != gen) { volatileStore(&g_instApPreparing, cast(ubyte)0); instPrepUnlock(); return; }
    foreach (i; 0 .. INST_STAGE_SLOTS) {
        if (volatileLoad(&g_instSlotState[i]) != SLOT_FREE) continue;
        volatileStore(&g_instSlotState[i], SLOT_FILLING);
        volatileStore(&g_instApStage, cast(ubyte)2);
        if (installPrepareSlot(i, true)) ++g_instApChunks;
        else volatileStore(&g_instSlotState[i], SLOT_FREE);   // nothing left in this job
        volatileStore(&g_instApStage, cast(ubyte)6);
        break;
    }
    instFence();
    volatileStore(&g_instApPreparing, cast(ubyte)0);
    instPrepUnlock();
    volatileStore(&g_instApStage, cast(ubyte)7);
}

// The BSP consumer: write READY slots in unit order; when no AP is preparing, prepare here.
// `sync` (installBootableToDisk's run-to-completion) never waits on the AP.
@nogc nothrow
private bool installStreamCurrentPhase(uint maxSectors, ref uint did) {
    import core.install_cap : gatedDiskWrite;
    enum uint SEC = 512;
    const bool sync = maxSectors == 0xFFFFFFFFu;
    while (g_instRemaining > 0 && did < maxSectors) {
        const ulong want = g_instOff / SEC;
        int slot = -1;
        foreach (i; 0 .. INST_STAGE_SLOTS)
            if (volatileLoad(&g_instSlotState[i]) == SLOT_READY && g_instSlotFirstUnit[i] == want) { slot = cast(int)i; break; }
        if (slot < 0) {
            // Wait for the AP only while it is actually delivering.  If nothing has become READY
            // for a while (the AP never ran the hook for this job, or died), the BSP prepares the
            // chunk itself -- the install must never depend on the second core being alive.
            import core.ticks : pitMs;
            const ulong nowMs = pitMs();
            if (g_instWaitSinceMs == 0) g_instWaitSinceMs = nowMs;
            const bool apAlive = (volatileLoad(&g_instApWorkerSeen) != 0) && !sync &&
                                 g_instJobKind == 1 &&      // the AP only prepares the random fill
                                 (nowMs - g_instWaitSinceMs) < 2000;
            if (apAlive) return true;                     // the AP is filling; come back next pass
            // Fallback (single CPU, or synchronous run): prepare one chunk here, then write it.
            int free_ = -1;
            foreach (i; 0 .. INST_STAGE_SLOTS)
                if (volatileLoad(&g_instSlotState[i]) == SLOT_FREE) { free_ = cast(int)i; break; }
            if (free_ < 0) return true;                   // (cannot happen: 4 slots, sequential) — yield
            if (!instPrepTryLock()) return true;          // an AP just appeared and owns the prepare
            if (g_instPrepNext != want) g_instPrepNext = want;   // the BSP resumes exactly at the write point
            volatileStore(&g_instSlotState[free_], SLOT_FILLING);
            const bool okPrep = installPrepareSlot(cast(uint)free_, false);
            instPrepUnlock();
            if (!okPrep) { volatileStore(&g_instSlotState[free_], SLOT_FREE); return false; }
            ++g_instBspChunks;
            slot = free_;
        }
        g_instWaitSinceMs = 0;                            // something was ready: the wait clock restarts
        const uint n = g_instSlotSectors[slot];
        if (!gatedDiskWrite(g_instCap, g_instIdx, g_instLba, n, g_instStageBuf[slot].ptr)) return false;
        g_instLba += n;
        g_instOff += cast(ulong)n * SEC;
        g_instRemaining -= n;
        g_instProgressDone += n;
        did += n;
        instFence();
        volatileStore(&g_instSlotState[slot], SLOT_FREE);
    }
    return true;
}

@nogc nothrow
private bool installRandomFillCurrentPhase(uint maxSectors, ref uint did) {
    import core.install_cap : gatedDiskWrite;
    import core.random : random_get_bytes;
    enum uint SEC = 512;
    while (g_instRemaining > 0 && did < maxSectors) {
        uint n = cast(uint)(g_instRemaining > INST_CRYPT_CHUNK ? INST_CRYPT_CHUNK : g_instRemaining);
        if (n > maxSectors - did) n = maxSectors - did;
        if (n == 0) break;
        random_get_bytes(g_instCryptBuf.ptr, cast(ulong)n * SEC);
        if (!gatedDiskWrite(g_instCap, g_instIdx, g_instLba, n, g_instCryptBuf.ptr))
            return false;
        g_instLba += n;
        g_instRemaining -= n;
        g_instProgressDone += n;
        did += n;
    }
    return true;
}

// The EpinAnonymOS payload (Full disk: the sys partition; Hidden OS: the hidden volume) is the
// raw esp-image FAT32 volume behind a synthesized ANOSBOOT v3 descriptor:
//   unit 0            "ANOSBOOT" | u64 plen (= esp-image bytes) | u64 rootfs 0 | u64 kind 1
//   units 1..n        esp-image sector (unit-1)
// which is exactly what deps/veracrypt/efi/efi_main.c:decrypt_and_boot expects for kind 1 (it
// decrypts the volume into RAM and chain-loads its BOOTX64.EFI).  The decoy payload (decoy-boot.img)
// already carries its own descriptor from wrap-decoy-payload.py, so it streams as-is from unit 0.
@nogc nothrow
private void instBuildAnosbootDescriptor(ubyte* sec, ulong plen) {
    foreach (i; 0 .. 512) sec[i] = 0;
    immutable string MAGIC = "ANOSBOOT";
    foreach (i; 0 .. 8) sec[i] = cast(ubyte)MAGIC[i];
    foreach (i; 0 .. 8) sec[8 + i] = cast(ubyte)(plen >> (8 * i));      // payload length
    /* [16..24) rootfs sectors = 0 (no dm-crypt root: the volume IS the root) */
    sec[24] = 1;                                                        // [24..32) kind = 1 (FAT volume)
}

@nogc nothrow
private bool installEncryptImageCurrentPhase(uint maxSectors, ref uint did) {
    import core.install_cap : gatedDiskWrite;
    enum uint SEC = 512;
    ubyte[32] k1, k2;
    // Which master key, which source image, and whether unit 0 is a synthesized descriptor:
    //   DECOY_IMAGE   MkD, decoy-boot.img, already wrapped (units 0.. = file sectors 0..)
    //   HIDDEN_IMAGE  MkH, esp-image, descriptor + image (unit 0 synthesized, unit u -> sector u-1)
    //   FDE_IMAGE     MkD, esp-image, descriptor + image
    const bool hiddenPayload = g_instPhase == INST_PHASE_HIDDEN_IMAGE;
    const bool epinPayload   = hiddenPayload || g_instPhase == INST_PHASE_FDE_IMAGE;
    foreach (i; 0 .. 32) {
        k1[i] = hiddenPayload ? g_instMkH[i] : g_instMkD[i];
        k2[i] = hiddenPayload ? g_instMkH[32 + i] : g_instMkD[32 + i];
    }
    const(ubyte)* src = epinPayload ? g_instHiddenImageSrc : g_instDecoyImageSrc;
    const ulong imageSize = epinPayload ? g_instHiddenImageSize : g_instDecoyImageSize;

    while (g_instRemaining > 0 && did < maxSectors) {
        uint n = cast(uint)(g_instRemaining > INST_CRYPT_CHUNK ? INST_CRYPT_CHUNK : g_instRemaining);
        if (n > maxSectors - did) n = maxSectors - did;
        if (n == 0) break;
        const ulong sector = g_instOff / SEC;          // first XTS unit of this chunk
        foreach (sIdx; 0 .. n) {
            ubyte* out_ = g_instCryptBuf.ptr + cast(size_t)sIdx * SEC;
            const ulong unit = sector + sIdx;
            if (epinPayload && unit == 0) {
                instBuildAnosbootDescriptor(out_, imageSize);
            } else {
                const ulong byteOff = (epinPayload ? unit - 1 : unit) * SEC;
                const ulong bytesLeft = imageSize > byteOff ? imageSize - byteOff : 0;
                const ulong copyBytes = bytesLeft < SEC ? bytesLeft : SEC;
                foreach (i; 0 .. cast(size_t)copyBytes) out_[i] = src[cast(size_t)byteOff + i];
                foreach (i; cast(size_t)copyBytes .. cast(size_t)SEC) out_[i] = 0;
            }
        }
        foreach (s; 0 .. n)
            xts_encrypt_sector(g_instCryptBuf.ptr + cast(size_t)s * SEC, SEC, sector + s, k1.ptr, k2.ptr);
        if (!gatedDiskWrite(g_instCap, g_instIdx, g_instLba, n, g_instCryptBuf.ptr))
            return false;
        g_instLba += n;
        g_instOff += cast(ulong)n * SEC;
        g_instRemaining -= n;
        g_instProgressDone += n;
        did += n;
    }
    return true;
}

// The hidden volume holds the descriptor + the EpinAnonymOS boot volume AND, after them, the
// hidden system's encrypted object store (core/fde.d hands the kernel that tail as its store
// bounds).  So it is sized image + the larger of 1 GiB and a quarter of the outer partition, capped
// to what the outer partition can hold past the hidden header.
@nogc nothrow
private ulong installHiddenVolumeBytes() {
    enum uint SEC = 512;
    if (g_instOuterSectors <= INST_HIDDEN_HDR_OFFSET + 1) return 0;
    const ulong outerBytes = g_instOuterSectors * SEC;
    ulong storeBytes = 1UL << 30;
    if (outerBytes / 4 > storeBytes) storeBytes = outerBytes / 4;
    ulong hiddenBytes = (g_instHiddenImageSectors + 1 + 2048) * SEC + storeBytes;   // +1 descriptor, +1 MiB guard
    const ulong maxBytes = (g_instOuterSectors - INST_HIDDEN_HDR_OFFSET - 1) * SEC;
    if (hiddenBytes > maxBytes) hiddenBytes = maxBytes;
    return hiddenBytes;
}

// Per-phase throughput, reported when the phase ends.  An encrypted install is hours of writing on
// a real disk, so "which phase, how many MB/s" is the only way to know whether the cost is the
// CSPRNG, the cipher or the disk -- and it is the number the GUI's estimate is built on.
__gshared ulong g_instPhaseStartMs = 0;
__gshared ulong g_instPhaseStartDone = 0;
@nogc nothrow
private void installReportPhaseRate() {
    // tscMs, not pitMs: this loop suppresses interrupts in long stretches and the PIT loses those
    // ticks, which inflated every rate printed here by roughly the duty cycle (a 512 MiB AES-XTS
    // phase claimed 1700 MiB/s on a CPU with no AES-NI).  The TSC does not stop.
    import core.ticks : tscMs;
    if (g_instPhaseStartMs == 0) return;
    const ulong ms = tscMs() - g_instPhaseStartMs;
    if (g_instProgressDone <= g_instPhaseStartDone) return;   // reset or rewound: nothing to report
    const ulong sectors = g_instProgressDone - g_instPhaseStartDone;
    if (ms == 0) return;
    const ulong kbps = (sectors / 2) * 1000 / ms;          // sectors/2 = KiB
    klog("[install] phase 0x"); klog_hex(g_instPhase);
    klog(" done: "); klog_dec(sectors / 2048); klog(" MiB in "); klog_dec(ms / 1000);
    klog(" s = "); klog_dec(kbps / 1024); klog(" MiB/s\n");
}

@nogc nothrow
private void installEnterHiddenPhase(ubyte phase) {
    import core.ticks : tscMs;
    installReportPhaseRate();
    g_instPhaseStartMs = tscMs();
    g_instPhaseStartDone = g_instProgressDone;
    g_instPhase = phase;
    g_instOff = 0;
    switch (phase) {
    case INST_PHASE_SYS_RANDOM:
        // Only the TAIL needs randomising: the front of this partition is about to be overwritten
        // with the encrypted payload (header + descriptor + image), and ciphertext is already
        // indistinguishable from random -- writing random there first and the image over it is
        // paying for the same sectors twice.  On a Full-disk install that is 512 MiB of pure waste
        // per install; with a decoy it is ~1 GiB.
        {
            const ulong payload = 1 + (g_instFdeMode ? (g_instHiddenImageSectors + 1)
                                                     : g_instDecoyImageSectors);
            const ulong skip = payload < g_instSysSectors ? payload : g_instSysSectors;
            g_instLba = g_instSysFirst + skip;
            g_instRemaining = g_instSysSectors - skip;
            g_instProgressDone += skip;          // accounted, just not written twice
            klog(g_instFdeMode ? "[install] Full disk: randomizing the system partition tail\n"
                               : "[install] Hidden OS: randomizing the decoy system partition tail\n");
            instPublishJob(1, g_instRemaining, null, 0, false, null, null);
        }
        break;
    case INST_PHASE_OUTER_RANDOM:
        g_instLba = g_instOuterFirst;
        g_instRemaining = g_instOuterSectors;
        if (!g_instFillOuter) {
            // Fast mode: randomise only the head (the headers and the region a reader touches
            // first), leave the rest untouched.  The system is still fully encrypted; what is
            // given up is the pretence that a hidden volume MIGHT be in there.
            const ulong head = 1UL << 15;                    // 16 MiB
            if (g_instRemaining > head) {
                g_instProgressDone += g_instRemaining - head;
                g_instRemaining = head;
            }
            klog("[install] Full disk (fast): randomizing the head of the outer partition only\n");
        } else {
            klog(g_instFdeMode ? "[install] Full disk: randomizing the whole outer partition (deniable)\n"
                               : "[install] Hidden OS: randomizing full outer volume partition\n");
        }
        instPublishJob(1, g_instRemaining, null, 0, false, null, null);
        break;
    case INST_PHASE_DECOY_IMAGE:
        g_instLba = g_instSysFirst + 1;
        g_instRemaining = g_instDecoyImageSectors;
        klog("[install] Hidden OS: writing encrypted decoy Linux image\n");
        instPublishJob(2, g_instRemaining, g_instDecoyImageSrc, g_instDecoyImageSize, false, g_instMkD.ptr, g_instMkD.ptr + 32);
        break;
    case INST_PHASE_HIDDEN_IMAGE:
        g_instLba = g_instOuterFirst + INST_HIDDEN_HDR_OFFSET + 1;
        g_instRemaining = g_instHiddenImageSectors + 1;      // + the ANOSBOOT v3 descriptor
        klog("[install] Hidden OS: writing encrypted hidden EpinAnonymOS boot volume\n");
        instPublishJob(2, g_instRemaining, g_instHiddenImageSrc, g_instHiddenImageSize, true, g_instMkH.ptr, g_instMkH.ptr + 32);
        break;
    case INST_PHASE_FDE_IMAGE:
        g_instLba = g_instSysFirst + 1;
        g_instRemaining = g_instHiddenImageSectors + 1;      // + the ANOSBOOT v3 descriptor
        klog("[install] Full disk: writing encrypted EpinAnonymOS boot volume\n");
        instPublishJob(2, g_instRemaining, g_instHiddenImageSrc, g_instHiddenImageSize, true, g_instMkD.ptr, g_instMkD.ptr + 32);
        break;
    case INST_PHASE_HEADERS:
        g_instLba = 0;
        g_instRemaining = 0;
        instUnpublishJob();
        break;
    case INST_PHASE_ESP:
        break;
    default:
        break;
    }
}

@nogc nothrow
private bool installWriteHiddenHeaders() {
    import core.install_cap : gatedDiskWrite;
    enum uint SEC = 512;

    if (g_instFdeMode) {
        // §E6 Full disk: ONE header, at sysFirst, keyed by the disk password.  The outer partition
        // stays pure random -- no outer/hidden headers -- so the disk is byte-for-byte the shape
        // of a Hidden-OS install (same GPT geometry, same random fill, one plaintext preboot ESP).
        if (g_instHiddenImageSrc is null || g_instHiddenImageSize == 0) {
            klog("[install] FAIL: Full disk selected but the esp-image boot volume is missing\n");
            return false;
        }
        if (g_instDiskPasswordLen == 0) {
            klog("[install] FAIL: Full disk selected without a disk password\n");
            return false;
        }
        const ulong sysBytes = g_instSysSectors * SEC;
        ubyte[512] hdr;
        create_veracrypt_header(g_instDiskPassword.ptr, g_instDiskPasswordLen,
                                g_instSaltD.ptr, g_instMkD.ptr, 0, sysBytes, SEC, sysBytes, hdr.ptr);
        if (!gatedDiskWrite(g_instCap, g_instIdx, g_instSysFirst, 1, hdr.ptr)) {
            klog("[install] FAIL: writing full-disk system header\n");
            return false;
        }
        foreach (i; 0 .. 512) hdr[i] = 0;
        g_instProgressDone++;
        klog("[install] Full disk layout written: boot volume sectors=0x"); klog_hex(g_instHiddenImageSectors + 1);
        klog(" sys=0x"); klog_hex(g_instSysFirst);
        klog(" outer=0x"); klog_hex(g_instOuterFirst); klog(" (random)\n");
        return true;
    }
    if (!g_instHiddenMode) return true;
    if (g_instDecoyImageSrc is null || g_instDecoyImageSize == 0) {
        klog("[install] FAIL: Hidden OS selected but decoy Linux image module is missing\n");
        return false;
    }
    if (g_instHiddenImageSrc is null || g_instHiddenImageSize == 0) {
        klog("[install] FAIL: Hidden OS selected but hidden EpinAnonymOS image module is missing\n");
        return false;
    }
    if (g_instHiddenPasswordLen == 0 || g_instOuterPasswordLen == 0 || g_instDecoyBootPasswordLen == 0) {
        klog("[install] FAIL: Hidden OS selected without all boot-volume passwords\n");
        return false;
    }
    if (g_instDecoyImageSectors == 0 || g_instDecoyImageSectors + 1 > g_instSysSectors) {
        klog("[install] FAIL: decoy Linux image does not fit encrypted system partition\n");
        return false;
    }
    if (g_instHiddenImageSectors == 0) {
        klog("[install] FAIL: hidden EpinAnonymOS image is empty\n");
        return false;
    }
    // (the hidden payload is the descriptor + esp-image, so +1 vs. the raw image size)
    if (g_instOuterSectors <= INST_HIDDEN_HDR_OFFSET + 1) {
        klog("[install] FAIL: outer partition too small for hidden header\n");
        return false;
    }

    const ulong sysBytes = g_instSysSectors * SEC;
    const ulong outerBytes = g_instOuterSectors * SEC;
    const ulong hiddenBytes = installHiddenVolumeBytes();
    const ulong minHiddenBytes = (g_instHiddenImageSectors + 2) * SEC;
    if (hiddenBytes < minHiddenBytes) {
        klog("[install] FAIL: hidden EpinAnonymOS image does not fit hidden volume\n");
        return false;
    }

    ubyte[512] hdr;
    create_veracrypt_header(g_instDecoyBootPassword.ptr, g_instDecoyBootPasswordLen,
                            g_instSaltD.ptr, g_instMkD.ptr, 0, sysBytes, SEC, sysBytes, hdr.ptr);
    if (!gatedDiskWrite(g_instCap, g_instIdx, g_instSysFirst, 1, hdr.ptr)) {
        klog("[install] FAIL: writing decoy system header\n");
        return false;
    }
    g_instProgressDone++;

    create_veracrypt_header(g_instOuterPassword.ptr, g_instOuterPasswordLen,
                            g_instSaltO.ptr, g_instMkO.ptr, hiddenBytes, outerBytes, SEC, outerBytes, hdr.ptr);
    if (!gatedDiskWrite(g_instCap, g_instIdx, g_instOuterFirst, 1, hdr.ptr)) {
        klog("[install] FAIL: writing outer volume header\n");
        return false;
    }
    g_instProgressDone++;

    create_veracrypt_header(g_instHiddenPassword.ptr, g_instHiddenPasswordLen,
                            g_instSaltH.ptr, g_instMkH.ptr, 0, hiddenBytes, SEC, hiddenBytes, hdr.ptr);
    if (!gatedDiskWrite(g_instCap, g_instIdx, g_instOuterFirst + INST_HIDDEN_HDR_OFFSET, 1, hdr.ptr)) {
        klog("[install] FAIL: writing hidden volume header\n");
        return false;
    }
    g_instProgressDone++;

    klog("[install] Hidden OS layout written: decoy Linux sectors=0x"); klog_hex(g_instDecoyImageSectors);
    klog(" hidden image sectors=0x"); klog_hex(g_instHiddenImageSectors);
    klog(" sys=0x"); klog_hex(g_instSysFirst);
    klog(" outer=0x"); klog_hex(g_instOuterFirst);
    klog(" hidden=0x"); klog_hex(g_instOuterFirst + INST_HIDDEN_HDR_OFFSET);
    klog("\n");
    return true;
}

// Start an install of the esp-image payload to disk `idx` (dsec sectors): write the GPT, set
// up the streaming state.  Returns false (and does nothing) if no payload / disk too small.
@nogc nothrow
public bool installBegin(int idx, ulong dsec) {
    import core.diskpart : GptLayout, gptWriteBootableEsp, gptWriteEncryptedToDisk, gptWriteABToDisk;
    import core.install_cap : mintInstallWriteCap, revokeInstallWriteCap;
    import core.exports : phys_to_virt;
    import core.random : random_get_bytes;
    enum uint SEC = 512;
    if (g_instActive) return true;                       // already running

    const bool hidden = g_instConfigHidden;
    const bool fde    = g_instConfigFde && !hidden;      // §E6 Full disk (Hidden OS wins if both are set)
    const bool enc    = hidden || fde;
    // The ESP.  Encrypted installs boot through the PREBOOT ESP: 8 MiB holding only the pre-boot
    // authenticator -- the one plaintext thing on the disk.  (esp-hidden-image, the old 512 MiB
    // hidden ESP, carried the whole boot tree in plaintext; accepted only as a fallback for an
    // older ISO, with a warning, because a plaintext tree next to an "encrypted" install is the
    // hole this work exists to close.)
    string espModule = enc ? "esp-preboot-image" : "esp-image";
    ulong phys, size;
    if (!instFindModule(espModule, phys, size)) {
        if (enc && instFindModule("esp-hidden-image", phys, size)) {
            klog("[install] WARNING: no esp-preboot-image; falling back to the plaintext esp-hidden-image ESP\n");
            espModule = "esp-hidden-image";
        } else {
            klog(enc ? "[install] no esp-preboot-image boot module (build an INSTALL ISO)\n"
                     : "[install] no esp-image boot module (build an INSTALL ISO)\n");
            g_instFailed = true;                         // surface as progress=-1 to the GUI
            return false;
        }
    }
    ulong decoyPhys = 0, decoySize = 0;
    ulong hiddenPhys = 0, hiddenSize = 0;
    if (enc) {
        // Both encrypted modes size the system partition from the SAME inputs (design-review
        // BLOCKER 1): a Full-disk disk must be geometrically identical to a Hidden-OS disk, or
        // the plaintext GPT alone tells them apart.  So the decoy image is measured even when it
        // will not be written.
        if (!instFindModule("decoy-linux.ext4", decoyPhys, decoySize)) {
            if (hidden) {
                klog("[install] FAIL: Hidden OS selected but decoy-linux.ext4 is not staged\n");
                g_instFailed = true;
                return false;
            }
            decoySize = 0;   // Full disk on an image without the decoy: fall back to the boot-volume rule
        }
        if (!instFindModule("esp-image", hiddenPhys, hiddenSize)) {
            klog("[install] FAIL: encrypted install selected but the esp-image boot volume is not staged\n");
            g_instFailed = true;
            return false;
        }
        if (hidden && (g_instHiddenPasswordLen == 0 || g_instOuterPasswordLen == 0 || g_instDecoyBootPasswordLen == 0)) {
            klog("[install] FAIL: Hidden OS selected but boot-volume passwords are incomplete\n");
            g_instFailed = true;
            return false;
        }
        if (fde && g_instDiskPasswordLen == 0) {
            klog("[install] FAIL: Full disk selected but no disk password was given\n");
            g_instFailed = true;
            return false;
        }
    }
    const ulong espSectors = (size + SEC - 1) / SEC;
    const ulong decoyImageSectors = (enc && decoySize) ? ((decoySize + SEC - 1) / SEC) : 0;
    const ulong hiddenImageSectors = enc ? ((hiddenSize + SEC - 1) / SEC) : 0;
    ulong sysSectors = VC_INSTALL_SYS_SECTORS;
    // One sizing rule for both encrypted modes: room for whichever payload is larger, the decoy
    // (descriptor already inside decoy-boot.img) or the EpinAnonymOS boot volume (+1 descriptor),
    // plus slack -- identical numbers whether the partition ends up holding Alpine or EpinAnonymOS.
    if (enc) {
        if (sysSectors < decoyImageSectors + 4096)      sysSectors = decoyImageSectors + 4096;
        if (sysSectors < hiddenImageSectors + 1 + 4096) sysSectors = hiddenImageSectors + 1 + 4096;
    }

    // UPDATE U1-B: the non-hidden install is now A/B — find the ESP-boot arbiter image.
    // If it isn't staged, fall back to the legacy single-ESP install (no A/B) rather than
    // failing, so an older ISO still installs.
    ulong bootPhys = 0, bootSize = 0;
    const bool abInstall = !enc && instFindModule("esp-boot-image", bootPhys, bootSize);
    const ulong bootEspSectors = abInstall ? ((bootSize + SEC - 1) / SEC) : 0;
    if (!enc) {
        const ulong need = abInstall ? (2048 + bootEspSectors + 2 * espSectors + 2048 + 64)
                                     : (espSectors + 2048 + 64);
        if (dsec < need) { klog("[install] FAIL: target disk too small\n"); g_instFailed = true; return false; }
    }
    klog("[install] begin idx=0x"); klog_hex(idx); klog(" image=0x"); klog_hex(size);
    klog("B sectors=0x"); klog_hex(espSectors); klog("\n");

    if (enc) {
        random_get_bytes(g_instMkD.ptr, cast(ulong)g_instMkD.length);
        random_get_bytes(g_instMkO.ptr, cast(ulong)g_instMkO.length);
        random_get_bytes(g_instMkH.ptr, cast(ulong)g_instMkH.length);
        random_get_bytes(g_instSaltD.ptr, cast(ulong)g_instSaltD.length);
        random_get_bytes(g_instSaltO.ptr, cast(ulong)g_instSaltO.length);
        random_get_bytes(g_instSaltH.ptr, cast(ulong)g_instSaltH.length);
    }

    g_instCap = mintInstallWriteCap(idx);
    GptLayout L;
    bool gptOk;
    if (enc)
        gptOk = gptWriteEncryptedToDisk(idx, dsec, espSectors, sysSectors, L);
    else if (abInstall)
        gptOk = gptWriteABToDisk(idx, dsec, bootEspSectors, espSectors, L);
    else
        gptOk = gptWriteBootableEsp(idx, dsec, espSectors, L);
    if (!gptOk) {
        klog("[install] FAIL (gpt)\n");
        revokeInstallWriteCap(g_instCap);
        instClearTransientPasswords();
        instClearHiddenInstallState();
        g_instFailed = true;
        return false;
    }
    g_instIdx = idx; g_instSrc = cast(const(ubyte)*) phys_to_virt(phys);
    g_instEspFirst = L.espFirst; g_instEspSectors = espSectors;
    g_instHiddenMode = hidden;
    g_instFdeMode = fde;
    g_instPhase = INST_PHASE_ESP;
    g_instProgressDone = 0;
    g_instSysFirst = L.sysFirst; g_instSysSectors = enc ? (L.sysLast - L.sysFirst + 1) : 0;
    g_instOuterFirst = L.outerFirst; g_instOuterSectors = enc ? (L.outerLast - L.outerFirst + 1) : 0;
    g_instDecoyImageSrc = (hidden && decoyPhys) ? cast(const(ubyte)*) phys_to_virt(decoyPhys) : null;
    g_instDecoyImageSize = hidden ? decoySize : 0;
    g_instDecoyImageSectors = hidden ? decoyImageSectors : 0;
    g_instHiddenImageSrc = enc ? cast(const(ubyte)*) phys_to_virt(hiddenPhys) : null;
    g_instHiddenImageSize = enc ? hiddenSize : 0;
    g_instHiddenImageSectors = hiddenImageSectors;
    // §E6: on an encrypted install the persisted install.json lives INSIDE the encrypted boot
    // volume, so it is patched into the in-RAM esp-image now, before that image is streamed.
    // (The preboot ESP carries no placeholder; installPersistConfigToEsp is a no-op there.)
    if (enc && !installPatchConfigIntoImage(cast(ubyte*) phys_to_virt(hiddenPhys), hiddenSize)) {
        klog("[install] FAIL: could not place install.json in the boot volume image\n");
        revokeInstallWriteCap(g_instCap);
        instClearTransientPasswords();
        instClearHiddenInstallState();
        g_instFailed = true;
        return false;
    }
    g_instLba = L.espFirst; g_instRemaining = espSectors;
    // UPDATE U1-B A/B state: slot-A first (= L.espFirst above), then slot-B, then ESP-boot.
    g_abInstall = abInstall;
    g_instSlotBFirst = abInstall ? L.slotBFirst : 0;
    g_instBootEspFirst = abInstall ? L.bootEspFirst : 0;
    g_instBootEspSectors = bootEspSectors;
    g_instBootSrc = abInstall ? cast(const(ubyte)*) phys_to_virt(bootPhys) : null;
    g_instTotal = hidden ? (espSectors + g_instSysSectors + g_instOuterSectors + decoyImageSectors + hiddenImageSectors + 1 + 3)
                : fde    ? (espSectors + g_instSysSectors + g_instOuterSectors + hiddenImageSectors + 1 + 1)
                : (abInstall ? (2 * espSectors + bootEspSectors) : espSectors);
    g_instOff = 0;
    g_instLastBeat = 0;
    g_instActive = true; g_instDone = false; g_instFailed = false;
    if (hidden) {
        klog("[install] encrypted Hidden OS GPT written; ESP @lba=0x"); klog_hex(L.espFirst);
        klog(" sys=0x"); klog_hex(L.sysFirst);
        klog(" outer=0x"); klog_hex(L.outerFirst);
        klog("; streaming preboot ESP, then encrypted decoy Linux + hidden OS boot volume + outer volume\n");
    } else if (fde) {
        klog("[install] encrypted Full-disk GPT written; ESP @lba=0x"); klog_hex(L.espFirst);
        klog(" sys=0x"); klog_hex(L.sysFirst);
        klog(" outer=0x"); klog_hex(L.outerFirst);
        klog("; streaming preboot ESP, then the encrypted EpinAnonymOS boot volume + random outer\n");
    } else if (abInstall) {
        klog("[install] A/B GPT written; ESP-boot @lba=0x"); klog_hex(L.bootEspFirst);
        klog(" slotA @lba=0x"); klog_hex(L.slotAFirst);
        klog(" slotB @lba=0x"); klog_hex(L.slotBFirst);
        klog("; streaming slot-A first\n");
    } else {
        klog("[install] GPT written; ESP @lba=0x"); klog_hex(L.espFirst); klog("; streaming image\n");
    }
    return true;
}

// Advance the in-flight install by up to `maxSectors` (0xFFFFFFFF = run to completion).
__gshared ulong g_instLastBeat = 0;   // heartbeat: last progress value klogged

// The install must never depend on the second core being alive.  installStreamCurrentPhase waits
// for a READY slot while the AP looks alive, and the AP claims g_instPrepLock / g_instApPreparing
// around each prepare -- so an AP that dies (or is simply never scheduled again) mid-prepare leaves
// a lock nobody will release and the whole install stops with no explanation.  Observed: an install
// stopped dead after the first 64 MiB on a 2-CPU guest and sat there until the VM was killed.
//
// So: watch g_instProgressDone.  After STALL_REPORT_MS with no sector written, print the ring state
// (this is the only view into the cross-CPU protocol from a serial log).  After STALL_BREAK_MS,
// declare the AP dead, break its lock and fall back to preparing on the BSP -- slower, but it
// finishes.  Both clocks are the TSC, because the PIT loses ticks during exactly this work.
private enum ulong STALL_REPORT_MS = 5_000;
private enum ulong STALL_BREAK_MS  = 12_000;
__gshared ulong g_instStallDone = 0;
__gshared ulong g_instStallSinceMs = 0;
__gshared ulong g_instStallReportedMs = 0;
__gshared ulong g_instApBroken = 0;
@nogc nothrow
private void installStallWatchdog() {
    import core.ticks : tscMs;
    const ulong nowMs = tscMs();
    if (g_instProgressDone != g_instStallDone) {          // progress: reset the clock
        g_instStallDone = g_instProgressDone;
        g_instStallSinceMs = nowMs;
        g_instStallReportedMs = 0;
        return;
    }
    if (g_instStallSinceMs == 0) { g_instStallSinceMs = nowMs; return; }
    const ulong stalledMs = nowMs - g_instStallSinceMs;
    if (stalledMs < STALL_REPORT_MS) return;
    if (nowMs - g_instStallReportedMs >= STALL_REPORT_MS) {
        g_instStallReportedMs = nowMs;
        klog("[install] STALL "); klog_dec(stalledMs / 1000);
        klog("s phase=0x"); klog_hex(g_instPhase);
        klog(" want="); klog_dec(g_instOff / 512);
        klog(" prepNext="); klog_dec(g_instPrepNext);
        klog(" end="); klog_dec(g_instJobEndUnit);
        klog(" gen="); klog_dec(cast(ulong)volatileLoad(&g_instJobGen));
        klog(" apSeen="); klog_dec(cast(ulong)volatileLoad(&g_instApWorkerSeen));
        klog(" apPrep="); klog_dec(cast(ulong)volatileLoad(&g_instApPreparing));
        klog(" lock="); klog_dec(cast(ulong)volatileLoad(&g_instPrepLock));
        klog(" apStage="); klog_dec(cast(ulong)volatileLoad(&g_instApStage));
        {   // If the second core parked in the catch-all fault handler, say where.
            import core.kmain : apActivatedHalted;
            ulong w0, w1, cr2;
            if (apActivatedHalted(w0, w1, cr2)) {
                klog(" AP-HALTED w0=0x"); klog_hex(w0);
                klog(" w1=0x"); klog_hex(w1);
                klog(" cr2=0x"); klog_hex(cr2);
            }
        }
        klog(" apSteps="); klog_dec(g_instApSteps);
        klog(" apChunks="); klog_dec(g_instApChunks);
        klog(" slots=");
        foreach (i; 0 .. INST_STAGE_SLOTS) {
            klog_dec(cast(ulong)volatileLoad(&g_instSlotState[i])); klog(":");
            klog_dec(g_instSlotFirstUnit[i]); klog(" ");
        }
        klog("\n");
    }
    if (stalledMs >= STALL_BREAK_MS && g_instApBroken == 0) {
        g_instApBroken = 1;
        // The AP is not coming back.  Stop believing it, drop whatever it was holding, and put any
        // slot it left half-filled back in the pool -- the BSP re-prepares those units itself.
        volatileStore(&g_instApWorkerSeen, cast(ubyte)0);
        volatileStore(&g_instApPreparing, cast(ubyte)0);
        foreach (i; 0 .. INST_STAGE_SLOTS)
            if (volatileLoad(&g_instSlotState[i]) == SLOT_FILLING)
                volatileStore(&g_instSlotState[i], SLOT_FREE);
        instFence();
        volatileStore(&g_instPrepLock, 0u);
        g_instWaitSinceMs = 0;
        klog("[install] STALL: second core declared dead; preparing on the boot core instead");
        klog(" (the install continues, more slowly)\n");
    }
}

@nogc nothrow
public void installStep(uint maxSectors) {
    import core.install_cap : gatedDiskWrite, revokeInstallWriteCap;
    enum uint SEC = 512;
    if (!g_instActive) return;
    installStallWatchdog();
    // Rekey the fill CSPRNG here, on the boot core, before the AP can find it due.  This runs far
    // more often than once per CHACHA_REKEY_BYTES, so the AP's decline path above is effectively
    // never taken -- and the rekey never happens on the core that cannot survive it.
    if (g_instJobKind == 1 && chacha_needs_reseed(g_instRng) && instPrepTryLock()) {
        if (chacha_needs_reseed(g_instRng)) chacha_ratchet(g_instRng);
        instPrepUnlock();
    }
    // Heartbeat every 32 MiB so a stall in the klog pinpoints the phase + LBA.
    if (g_instProgressDone - g_instLastBeat >= 65536) {
        g_instLastBeat = g_instProgressDone;
        klog("[install] progress 0x"); klog_hex(g_instProgressDone);
        klog("/0x"); klog_hex(g_instTotal);
        klog(" phase=0x"); klog_hex(g_instPhase);
        klog(" lba=0x"); klog_hex(g_instLba); klog("\n");
    }
    uint did = 0;
    while (g_instActive && did < maxSectors) {
        // UPDATE U1-B: INST_PHASE_ESP / _SLOTB / _BOOTESP are all raw-image streams
        // (src+off → lba). They share the streaming loop; only the completion transition
        // differs. INST_PHASE_ESP targets slot-A (the active slot) in A/B mode.
        if (g_instPhase == INST_PHASE_ESP || g_instPhase == INST_PHASE_SLOTB ||
            g_instPhase == INST_PHASE_BOOTESP) {
            const(ubyte)* src = (g_instPhase == INST_PHASE_BOOTESP) ? g_instBootSrc : g_instSrc;
            while (g_instRemaining > 0 && did < maxSectors) {
                // 1 MiB per command, not the historical 64 KiB: this is a straight copy out of the
                // boot module with no crypto in the way, so the only cost per command is the AHCI
                // round trip -- and at 64 KiB a 512 MiB ESP paid that round trip 8192 times.
                // diskWrite splits to the DMA bounce buffer itself (drivers/block/disk.d).
                uint chunk = cast(uint)(g_instRemaining > INST_STAGE_SECTORS ? INST_STAGE_SECTORS : g_instRemaining);
                if (chunk > maxSectors - did) chunk = maxSectors - did;
                if (chunk == 0) break;
                if (!gatedDiskWrite(g_instCap, g_instIdx, g_instLba, chunk, src + g_instOff)) {
                    klog("[install] FAIL (write @lba=0x"); klog_hex(g_instLba); klog(")\n");
                    revokeInstallWriteCap(g_instCap); g_instActive = false; g_instFailed = true;
                    instClearTransientPasswords(); instClearHiddenInstallState();
                    return;
                }
                g_instLba += chunk;
                g_instOff += cast(ulong)chunk * SEC;
                g_instRemaining -= chunk;
                g_instProgressDone += chunk;
                did += chunk;
            }
            if (g_instRemaining != 0) break;

            if (g_instPhase == INST_PHASE_ESP && (g_instHiddenMode || g_instFdeMode)) {
                installEnterHiddenPhase(INST_PHASE_SYS_RANDOM);
                continue;
            }

            // Legacy single-ESP path (no A/B): persist config to the one ESP and finish.
            if (g_instPhase == INST_PHASE_ESP && !g_abInstall) {
                if (!installPersistConfigToEsp()) {
                    revokeInstallWriteCap(g_instCap); g_instActive = false; g_instFailed = true;
                    instClearTransientPasswords(); instClearHiddenInstallState();
                    klog("[install] FAIL (persist install config)\n");
                    return;
                }
                revokeInstallWriteCap(g_instCap); g_instActive = false; g_instDone = true;
                instClearTransientPasswords(); instClearHiddenInstallState();
                klog("[install] DONE: installed to idx=0x"); klog_hex(g_instIdx);
                klog(" (reboot from this disk → UEFI → limine → EpinAnonymOS)\n");
                return;
            }

            // A/B: slot-A done → persist config to slot-A, then stream slot-B.
            if (g_instPhase == INST_PHASE_ESP) {
                // g_instEspFirst still points at slot-A (set in installBegin).
                if (!installPersistConfigToEsp()) {
                    revokeInstallWriteCap(g_instCap); g_instActive = false; g_instFailed = true;
                    instClearTransientPasswords();
                    klog("[install] FAIL (persist config slot-A)\n");
                    return;
                }
                g_instPhase = INST_PHASE_SLOTB;
                g_instLba = g_instSlotBFirst; g_instRemaining = g_instEspSectors; g_instOff = 0;
                klog("[install] A/B: slot-A written; streaming slot-B @lba=0x"); klog_hex(g_instSlotBFirst); klog("\n");
                continue;
            }

            // A/B: slot-B done → persist config to slot-B, then stream the ESP-boot arbiter.
            if (g_instPhase == INST_PHASE_SLOTB) {
                g_instEspFirst = g_instSlotBFirst;
                if (!installPersistConfigToEsp()) {
                    revokeInstallWriteCap(g_instCap); g_instActive = false; g_instFailed = true;
                    instClearTransientPasswords();
                    klog("[install] FAIL (persist config slot-B)\n");
                    return;
                }
                g_instPhase = INST_PHASE_BOOTESP;
                g_instLba = g_instBootEspFirst; g_instRemaining = g_instBootEspSectors; g_instOff = 0;
                klog("[install] A/B: slot-B written; streaming ESP-boot arbiter @lba=0x"); klog_hex(g_instBootEspFirst); klog("\n");
                continue;
            }

            // A/B: ESP-boot (arbiter) done → initialize the boot-state to slot-A, finish.
            if (g_instPhase == INST_PHASE_BOOTESP) {
                import core.bootstate : bootStateInit, SLOT_A;
                if (!bootStateInit(SLOT_A))
                    klog("[install] WARN: boot-state init failed (arbiter defaults to slot A)\n");
                else
                    klog("[install] A/B: boot-state initialized (active=slot A, tries reset)\n");
                revokeInstallWriteCap(g_instCap); g_instActive = false; g_instDone = true;
                instClearTransientPasswords(); instClearHiddenInstallState();
                klog("[install] DONE (A/B): idx=0x"); klog_hex(g_instIdx);
                klog(" — arbiter → slot A → limine → EpinAnonymOS\n");
                return;
            }
        }

        if (g_instPhase == INST_PHASE_SYS_RANDOM || g_instPhase == INST_PHASE_OUTER_RANDOM) {
            if (!installStreamCurrentPhase(maxSectors, did)) {
                revokeInstallWriteCap(g_instCap); g_instActive = false; g_instFailed = true;
                instClearTransientPasswords(); instClearHiddenInstallState();
                if (g_instPhase == INST_PHASE_SYS_RANDOM)
                    klog("[install] FAIL: randomizing encrypted decoy system partition\n");
                else
                    klog("[install] FAIL: randomizing full outer volume partition\n");
                return;
            }
            if (g_instRemaining != 0) break;              // (also: nothing ready yet -- next pass)
            if (g_instPhase == INST_PHASE_SYS_RANDOM)
                installEnterHiddenPhase(INST_PHASE_OUTER_RANDOM);
            else if (g_instFdeMode)
                installEnterHiddenPhase(INST_PHASE_FDE_IMAGE);      // Full disk: no decoy, no hidden volume
            else
                installEnterHiddenPhase(INST_PHASE_DECOY_IMAGE);
            continue;
        }

        if (g_instPhase == INST_PHASE_DECOY_IMAGE || g_instPhase == INST_PHASE_HIDDEN_IMAGE ||
            g_instPhase == INST_PHASE_FDE_IMAGE) {
            if (!installStreamCurrentPhase(maxSectors, did)) {
                revokeInstallWriteCap(g_instCap); g_instActive = false; g_instFailed = true;
                instClearTransientPasswords(); instClearHiddenInstallState();
                if (g_instPhase == INST_PHASE_DECOY_IMAGE)
                    klog("[install] FAIL: writing encrypted decoy Linux image\n");
                else
                    klog("[install] FAIL: writing encrypted EpinAnonymOS boot volume\n");
                return;
            }
            if (g_instRemaining != 0) break;
            if (g_instPhase == INST_PHASE_DECOY_IMAGE)
                installEnterHiddenPhase(INST_PHASE_HIDDEN_IMAGE);
            else
                installEnterHiddenPhase(INST_PHASE_HEADERS);       // hidden or full-disk volume done
            continue;
        }

        if (g_instPhase == INST_PHASE_HEADERS) {
            if (!installWriteHiddenHeaders()) {
                revokeInstallWriteCap(g_instCap); g_instActive = false; g_instFailed = true;
                instClearTransientPasswords(); instClearHiddenInstallState();
                klog("[install] FAIL (write hidden/decoy headers)\n");
                return;
            }
            if (!installPersistConfigToEsp()) {
                revokeInstallWriteCap(g_instCap); g_instActive = false; g_instFailed = true;
                instClearTransientPasswords(); instClearHiddenInstallState();
                klog("[install] FAIL (persist install config)\n");
                return;
            }
            const bool wasFde = g_instFdeMode;
            revokeInstallWriteCap(g_instCap); g_instActive = false; g_instDone = true;
            instClearTransientPasswords(); instClearHiddenInstallState();
            klog("[install] DONE: installed to idx=0x"); klog_hex(g_instIdx);
            klog(wasFde ? " (Full disk: preboot ESP + encrypted EpinAnonymOS boot volume + random outer volume were written)\n"
                        : " (Hidden OS selected: preboot ESP + encrypted decoy Linux + encrypted hidden OS + headers were written)\n");
            installReportPhaseRate();
            klog("[install] crypto chunks prepared on the second core: "); klog_dec(g_instApChunks);
            klog(", on the BSP: "); klog_dec(g_instBspChunks); klog("\n");
            g_instApChunks = 0; g_instBspChunks = 0;
            return;
        }

        klog("[install] FAIL: invalid install phase\n");
        revokeInstallWriteCap(g_instCap); g_instActive = false; g_instFailed = true;
        instClearTransientPasswords(); instClearHiddenInstallState();
        return;
    }
}

// Progress of the current/last install: -1 = FAILED, 0 = idle/never started,
// 1..1000 permille.  Floored at 1 while active: Hidden OS randomizes the WHOLE
// disk, so true permille stays 0 for hundreds of polls on a large drive — a
// poller must be able to tell "started but early" from "never started".
@nogc nothrow
public int installProgressPermille() {
    if (g_instDone) return 1000;
    if (g_instFailed) return -1;
    if (!g_instActive || g_instTotal == 0) return 0;
    ulong done = g_instProgressDone;
    if (done > g_instTotal) done = g_instTotal;
    const uint p = cast(uint)((done * 1000UL) / g_instTotal);
    return (p == 0) ? 1 : cast(int)p;
}

// Synchronous full install (direct/headless callers).
@nogc nothrow
public bool installBootableToDisk(int idx, ulong dsec) {
    if (!installBegin(idx, dsec)) return false;
    while (g_instActive) installStep(0xFFFFFFFFu);
    return g_instDone;
}

// Control-write executor: the desktop "Install to Disk" button (and a manual
//   echo install > /config/install.action
// ) lands here.  Command grammar: "install" → install the running OS to the first target
// disk; "install <idx>" → to disk index <idx>.  Deny-by-default.
//
// BATCHED: the FIRST "install" (when idle) starts the install (writes the GPT) + does one
// batch; each SUBSEQUENT "install" advances another batch.  The GUI loops "write install →
// read /config/install.progress → redraw bar" so it can show progress (the whole image is too
// big to write in one syscall without freezing the UI).
@nogc nothrow
public bool installControlWrite(const(char)* cmd, size_t len) {
    import drivers.block.disk : diskFindTarget, diskIndexCapacity, diskFindBootDisk;
    enum uint BATCH = 8192;                          // 4 MiB / write → ~60 bar updates
    static immutable string C = "config ";
    static immutable string P = "install";
    if (instCtlPrefix(cmd, len, C)) {
        if (g_instActive || g_instDone) {
            klog("[install] control: config rejected after install start\n");
            return false;
        }
        return installCaptureConfig(cmd + C.length, len - C.length);
    }
    if (cmd is null || len < P.length) return false;
    foreach (i; 0 .. P.length) if (cmd[i] != P[i]) return false;

    if (!g_instActive && !g_instDone) {              // start a new install
        import drivers.block.disk : diskStoreIndex;
        int idx = -1; ulong dsec = 0;
        size_t p = P.length;
        while (p < len && (cmd[p] == ' ' || cmd[p] == '\t')) p++;
        if (p < len && cmd[p] >= '0' && cmd[p] <= '9') {   // explicit "install <idx>"
            int n = 0;
            while (p < len && cmd[p] >= '0' && cmd[p] <= '9') { n = n * 10 + (cmd[p] - '0'); p++; }
            ulong sec = 0;
            if (!diskIndexCapacity(n, sec)) {
                klog("[install] control: bad disk index\n"); g_instFailed = true; return false;
            }
            idx = n; dsec = sec;
        } else {
            idx = diskFindBootDisk(dsec);            // the disk UEFI boots first (lowest port)
            if (idx < 0) idx = diskFindTarget(dsec); // else a spare disk distinct from the store
            if (idx < 0) idx = diskStoreIndex(dsec); // single-disk: install onto the only disk
        }
        if (idx < 0) { klog("[install] control: no disk to install to\n"); g_instFailed = true; return false; }
        klog("[install] control: 'install' → target idx=0x"); klog_hex(idx); klog("\n");
        if (!installBegin(idx, dsec)) return false;
    }
    if (g_instActive) installStep(BATCH);            // advance one batch
    return true;
}

// Boot smoke check: report installer READINESS (do NOT auto-wipe a disk).  Installing is
// driven by the user (the "Install to Disk" button → /config/install.action).
// True iff this boot carries the installer payload (the esp-image module) — i.e. an INSTALL
// image.  The object store uses this to stay in-memory so the disk is a free install target.
@nogc nothrow
public bool bootHasInstallPayload() {
    ulong phys, size;
    return instFindModule("esp-image", phys, size);
}

@nogc nothrow
public void installBootableProof() {
    import drivers.block.disk : diskFindTarget, diskStoreIndex, diskFindBootDisk;
    ulong phys, size;
    if (!instFindModule("esp-image", phys, size)) { klog("[install] not an INSTALL image (no esp-image module)\n"); return; }
    ulong dsec;
    int idx = diskFindBootDisk(dsec);                // the disk UEFI boots first
    if (idx < 0) idx = diskFindTarget(dsec);
    if (idx < 0) idx = diskStoreIndex(dsec);         // single-disk: the only disk is the target
    if (idx < 0) { klog("[install] READY: payload present, but no disk attached\n"); return; }
    klog("[install] READY: esp-image=0x"); klog_hex(size);
    klog("B, target idx=0x"); klog_hex(idx); klog(" dsec=0x"); klog_hex(dsec);
    klog(" — click 'Install to Disk' (or: echo install > /config/install.action)\n");
}

// ── Headless install, for the test harness only (roadmap 4.8) ────────────────────────────────
//
// §F's IMMUTABLE-1 can only be true on a system whose store is on a real disk, and the only honest
// way to demonstrate that is to INSTALL the OS and boot the result.  Until now the installer could
// be driven exactly one way -- a human clicking "Install to Disk" -- so the claim "immutable" was
// provable only by hand, which in practice means not provable at all.
//
// GATED ON A BOOT MODULE, deliberately.  This runs only when a module literally named
// "autoinstall" is present, which the Makefile stages only under AUTOINSTALL=1.  A shipped ISO
// never carries it, so this cannot wipe a user's disk: the trigger is absent from the image rather
// than merely disabled inside it, which is the difference between a flag and a build decision.
//
// It takes the SAME path the GUI takes -- installBegin then step to completion -- rather than a
// parallel "test install", because a test that exercises a different code path proves something
// about the test.
__gshared bool g_autoInstallDone = false;

// TEST-ONLY repro of the GUI Hidden-OS install: preseed the three boot-volume passwords and
// begin a hidden install, so the kernel-loop driver can run it WHILE the desktop is up — the
// exact scenario a user hits by clicking "Install now" with Hidden OS selected. Reproduces the
// freeze (or confirms it is fixed) headlessly on the serial.
@nogc nothrow
public bool installBeginHiddenTest() {
    import drivers.block.disk : diskFindTarget, diskStoreIndex, diskFindBootDisk;
    void setpw(ref char[INST_SECRET_MAX] dst, ref uint dlen, string s) @nogc nothrow {
        uint n = 0; foreach (c; s) { if (n < INST_SECRET_MAX) dst[n++] = c; } dlen = n;
    }
    g_instConfigHidden = true;
    setpw(g_instHiddenPassword,    g_instHiddenPasswordLen,    "hidden-password");
    setpw(g_instOuterPassword,     g_instOuterPasswordLen,     "outer-password");
    setpw(g_instDecoyBootPassword, g_instDecoyBootPasswordLen, "decoy-boot-pw");
    ulong dsec = 0;
    int idx = diskFindBootDisk(dsec);                // the disk UEFI boots first
    if (idx < 0) idx = diskFindTarget(dsec);
    if (idx < 0) idx = diskStoreIndex(dsec);
    if (idx < 0) { klog("[install] TEST hidden: no disk\n"); return false; }
    return installBegin(idx, dsec);
}

// Called every main-loop pass; starts the delayed hidden test install once, only on a test image
// that carries the "autoinstall-hidden" module, and only after the desktop has had time to come up.
__gshared bool g_hiddenTestStarted = false;
@nogc nothrow
public void installMaybeStartHiddenTest(ulong nowMs) {
    if (g_hiddenTestStarted || nowMs < 90000) return;
    ulong phys, size;
    if (!instFindModule("hiddeninstall-test", phys, size)) return;   // test image only
    g_hiddenTestStarted = true;
    klog("[install] TEST: delayed HIDDEN install starting from the loop (desktop is up)\n");
    installBeginHiddenTest();
}

// §E6 TEST IMAGE ONLY (AUTOINSTALL_FDE=1 stages the "autoinstall-fde" trigger module): run a
// Full-disk install with the fixed password "disk-password" once the desktop is up, so the whole
// chain -- kernel installer -> preboot ESP -> encrypted boot volume -> OVMF password prompt ->
// EpinAnonymOS with an encrypted object store -- is provable without a person at the wizard
// (scripts/encrypted-boot-test.py boots the result).
__gshared bool g_fdeTestStarted = false;
@nogc nothrow
public bool installBeginFdeTest() {
    import drivers.block.disk : diskFindTarget, diskStoreIndex, diskFindBootDisk;
    void setpw(ref char[INST_SECRET_MAX] dst, ref uint dlen, string str) @nogc nothrow {
        uint n = 0; foreach (c; str) { if (n < INST_SECRET_MAX) dst[n++] = c; } dlen = n;
    }
    g_instConfigHidden = false;
    g_instConfigFde = true;
    setpw(g_instDiskPassword, g_instDiskPasswordLen, "disk-password");
    ulong dsec = 0;
    int idx = diskFindBootDisk(dsec);
    if (idx < 0) idx = diskFindTarget(dsec);
    if (idx < 0) idx = diskStoreIndex(dsec);
    if (idx < 0) { klog("[install] TEST fde: no disk\n"); return false; }
    return installBegin(idx, dsec);
}
@nogc nothrow
public void installMaybeStartFdeTest(ulong nowMs) {
    if (g_fdeTestStarted || nowMs < 60000) return;
    ulong phys, size;
    if (!instFindModule("autoinstall-fde", phys, size)) return;      // test image only
    g_fdeTestStarted = true;
    klog("[install] TEST: FULL-DISK install starting from the loop (password: disk-password)\n");
    installBeginFdeTest();
}

@nogc nothrow
public void installAutoIfRequested() {
    if (g_autoInstallDone) return;
    g_autoInstallDone = true;

    ulong phys, size;
    if (!instFindModule("autoinstall", phys, size)) return;   // not a test image: do nothing

    import drivers.block.disk : diskStoreIndex, diskFindTarget, diskFindBootDisk;
    ulong dsec = 0;
    int idx = diskFindBootDisk(dsec);                // the disk UEFI boots first
    if (idx < 0) idx = diskFindTarget(dsec);
    if (idx < 0) idx = diskStoreIndex(dsec);
    if (idx < 0) {
        klog("[install] AUTOINSTALL requested but no disk to install to\n");
        return;
    }
    klog("[install] AUTOINSTALL (test image only): installing to idx=0x");
    klog_hex(idx); klog(" disksec=0x"); klog_hex(dsec); klog("\n");

    // Start the install the BATCHED way (like the GUI's first write to /config/install.action)
    // and let the kernel-loop driver (kernel_main installStep tick) run it to completion — this
    // exercises the same autonomous path that keeps a real GUI install from freezing when the
    // desktop stalls. installStep logs "[install] DONE"/"FAIL" from the loop.
    if (installBegin(idx, dsec))
        klog("[install] AUTOINSTALL started; kernel loop is driving it to completion\n");
    else
        klog("[install] AUTOINSTALL FAILED to begin\n");
}

// INSTALLER diagnostics: the install's phase and byte counters, for /config/install.progress.
//
// The progress file used to carry a permille number and nothing else, so a GUI could not tell
// "advancing slowly" from "wedged" -- and on a software-rendered desktop the installer advances
// one 4 MiB batch per compositor round-trip, which looks exactly like wedged.  Exposing the phase
// and the raw counters lets the caller say which, and lets a serial log say it too.
@nogc nothrow public ubyte installPhase()        { return g_instPhase; }
@nogc nothrow public ulong installProgressDone() { return g_instProgressDone; }
@nogc nothrow public ulong installProgressTotal(){ return g_instTotal; }
@nogc nothrow public ulong installProgressLba()  { return g_instLba; }
