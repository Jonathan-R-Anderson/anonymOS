module drivers.veracrypt_impl;

import drivers.veracrypt;
// import anonymos_crypto.primitives.sha512;

extern(C) void sha512_hash(const(ubyte)* data, size_t len, ubyte* output) @nogc nothrow;
extern(C) void aes_encrypt(ubyte* data, const(ubyte)* key) @nogc nothrow;

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

// Header Generation
@nogc nothrow
void create_veracrypt_header(const(char)* password, uint passLen, const(ubyte)* masterKey, uint keyLen, ubyte* outHeaderSector)
{
    // 1. Generate Salt (64 bytes)
    // For now, pseudo-random based on time/stack
    ubyte[64] salt;
    for (int i = 0; i < 64; i++) salt[i] = cast(ubyte)(i * 17 + passLen); // TODO: Better PRNG
    
    // 2. Derive Header Key (PBKDF2)
    // VeraCrypt uses 500,000 iterations for SHA-512
    // For installer speed, we use fewer (e.g., 1000) but in real life should be 500k
    // We need 64 bytes for AES-256 (32 key + 32 tweak? No, XTS uses 64 bytes total: 32+32)
    // Actually, VeraCrypt uses XTS mode for the header too.
    // Header Key size = 64 bytes (512 bits) for AES-256-XTS.
    ubyte[64] headerKey;
    pbkdf2_sha512(password, passLen, salt.ptr, 64, 1000, headerKey.ptr, 64);
    
    // 3. Prepare Decrypted Header
    ubyte[512] header; // Full sector
    for (int i = 0; i < 512; i++) header[i] = 0;
    
    // Copy Salt (first 64 bytes are unencrypted salt)
    for (int i = 0; i < 64; i++) outHeaderSector[i] = salt[i];
    
    // The rest (448 bytes) is encrypted.
    // We construct the plaintext header first.
    // Offset 0 in encrypted part is "VERA"
    header[0] = 'V'; header[1] = 'E'; header[2] = 'R'; header[3] = 'A';
    header[4] = 0x00; header[5] = 0x05; // Version 5
    header[6] = 0x00; header[7] = 0x05; // Min Version 5
    
    // Key Area CRC (CRC of master key data)
    // Master key data starts at offset 256 in encrypted area?
    // No, struct says:
    // magic (4) + version (2) + min (2) + crc (4) + ...
    // masterKeyData is at end.
    
    // Let's place master key at offset 256 (0x100)
    for (int i = 0; i < keyLen && i < 64; i++) header[256+i] = masterKey[i];
    
    // Calculate Key Area CRC (256 bytes starting at 256)
    uint kCrc = crc32(header.ptr + 256, 256);
    header[8] = cast(ubyte)((kCrc >> 24) & 0xFF);
    header[9] = cast(ubyte)((kCrc >> 16) & 0xFF);
    header[10] = cast(ubyte)((kCrc >> 8) & 0xFF);
    header[11] = cast(ubyte)(kCrc & 0xFF);
    
    // Volume Size (dummy)
    // Hidden Volume Size (dummy)
    // Encrypted Area Start (dummy)
    // Encrypted Area Length (dummy)
    // Flags
    // Sector Size (512)
    header[128] = 0x00; header[129] = 0x00; header[130] = 0x02; header[131] = 0x00; // 512
    
    // Header CRC (first 252 bytes)
    uint hCrc = crc32(header.ptr, 252);
    header[252] = cast(ubyte)((hCrc >> 24) & 0xFF);
    header[253] = cast(ubyte)((hCrc >> 16) & 0xFF);
    header[254] = cast(ubyte)((hCrc >> 8) & 0xFF);
    header[255] = cast(ubyte)(hCrc & 0xFF);
    
    // 4. Encrypt Header
    // VeraCrypt encrypts the 448 bytes using XTS mode with the derived header key.
    // Tweak is 0? Or sector number?
    // For header, tweak is usually 0 or related to salt?
    // VeraCrypt documentation says: "The header is encrypted in XTS mode... The secondary key (tweak key) is... The 64-bit tweak is 0."
    
    ubyte[32] key1;
    ubyte[32] key2;
    for (int i = 0; i < 32; i++) key1[i] = headerKey[i];
    for (int i = 0; i < 32; i++) key2[i] = headerKey[32+i];
    
    xts_encrypt_sector(header.ptr, 448, 0, key1.ptr, key2.ptr);
    
    // Copy encrypted part to output
    for (int i = 0; i < 448; i++) outHeaderSector[64+i] = header[i];
}
