module drivers.veracrypt_impl;

import drivers.veracrypt;
import core.io : klog, klog_hex;
import core.install_cap : InstallWriteCap, gatedDiskWrite;   // for vcRandomFillRange (module scope)

extern(C) void sha512_hash(const(ubyte)* data, size_t len, ubyte* output) @nogc nothrow;
extern(C) void aes_encrypt(ubyte* data, const(ubyte)* key) @nogc nothrow;

// PBKDF2 header-KDF iterations — MUST match deps/veracrypt/vcheader.h VC_HEADER_ITERATIONS
// so a header built here opens with the host reference (and vice versa).  §E2b.
enum uint VC_HEADER_ITERATIONS = 1000;

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
    
    for (size_t i = 0; i < len; i += 16)
    {
        // 1. Xor data with tweak
        for (int j = 0; j < 16; j++) data[i+j] ^= tweak[j];
        
        // 2. Encrypt with Key1
        aes_encrypt(data + i, key1);
        
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
