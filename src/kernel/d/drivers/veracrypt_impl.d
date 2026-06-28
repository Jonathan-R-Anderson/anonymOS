module drivers.veracrypt_impl;

import drivers.veracrypt;
import core.io : klog, klog_hex;

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
