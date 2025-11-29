module anonymos.crypto.sha256;

/// SHA-256 implementation
export extern(C) void sha256_hash(const(ubyte)* data, uint len, ubyte* output) @nogc nothrow {
    // SHA-256 constants
    immutable uint[64] K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    
    // Initial hash values
    uint[8] H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];
    
    // Prepare message
    ulong bitLen = cast(ulong)len * 8;
    uint paddedLen = ((len + 8) / 64 + 1) * 64;
    
    ubyte[128] buffer;
    uint bufferLen = 0;
    
    // Copy data
    for (uint i = 0; i < len && i < 55; i++) {
        buffer[bufferLen++] = data[i];
    }
    
    // Padding
    buffer[bufferLen++] = 0x80;
    while (bufferLen < 56) {
        buffer[bufferLen++] = 0;
    }
    
    // Length (big-endian)
    for (int i = 7; i >= 0; i--) {
        buffer[bufferLen++] = cast(ubyte)((bitLen >> (i * 8)) & 0xFF);
    }
    
    // Process block
    uint[64] W;
    
    // Prepare message schedule
    for (uint i = 0; i < 16; i++) {
        W[i] = (cast(uint)buffer[i*4] << 24) |
               (cast(uint)buffer[i*4+1] << 16) |
               (cast(uint)buffer[i*4+2] << 8) |
               cast(uint)buffer[i*4+3];
    }
    
    for (uint i = 16; i < 64; i++) {
        uint s0 = rotr(W[i-15], 7) ^ rotr(W[i-15], 18) ^ (W[i-15] >> 3);
        uint s1 = rotr(W[i-2], 17) ^ rotr(W[i-2], 19) ^ (W[i-2] >> 10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }
    
    // Working variables
    uint a = H[0], b = H[1], c = H[2], d = H[3];
    uint e = H[4], f = H[5], g = H[6], h = H[7];
    
    // Main loop
    for (uint i = 0; i < 64; i++) {
        uint S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint ch = (e & f) ^ (~e & g);
        uint temp1 = h + S1 + ch + K[i] + W[i];
        uint S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint temp2 = S0 + maj;
        
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    
    // Add to hash
    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    
    // Output (big-endian)
    for (uint i = 0; i < 8; i++) {
        output[i*4] = cast(ubyte)(H[i] >> 24);
        output[i*4+1] = cast(ubyte)(H[i] >> 16);
        output[i*4+2] = cast(ubyte)(H[i] >> 8);
        output[i*4+3] = cast(ubyte)H[i];
    }
}

private uint rotr(uint x, uint n) @nogc nothrow {
    return (x >> n) | (x << (32 - n));
}
