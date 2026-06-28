/* deps/veracrypt — VeraCrypt volume-header engine (§E2). See vcheader.h. */
#include "vcheader.h"
#include <string.h>
#include "Crypto/Aes.h"
#include "Crypto/Sha2.h"

/* ── big-endian field writers/readers (VeraCrypt header fields are big-endian) ── */
static void be16(uint8_t *p, uint16_t v){ p[0]=v>>8; p[1]=v; }
static void be32(uint8_t *p, uint32_t v){ p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v; }
static void be64(uint8_t *p, uint64_t v){ for(int i=0;i<8;i++) p[i]=(uint8_t)(v>>(56-8*i)); }
static uint32_t rbe32(const uint8_t *p){ return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3]; }

/* ── CRC32 (IEEE, poly 0xEDB88320) — matches veracrypt_impl.d crc32 ── */
static uint32_t crc32_(const uint8_t *d, size_t n){
    uint32_t c = 0xFFFFFFFFu;
    for(size_t i=0;i<n;i++){ c^=d[i]; for(int j=0;j<8;j++) c = (c&1)?(c>>1)^0xEDB88320u:(c>>1); }
    return ~c;
}

/* ── HMAC-SHA512 + PBKDF2-HMAC-SHA512 (mirror veracrypt_impl.d) ── */
static void hmac_sha512_(const uint8_t *key, size_t keyLen,
                         const uint8_t *data, size_t dataLen, uint8_t out[64]){
    uint8_t k_ipad[128], k_opad[128], tk[64], inner[128+128], outer[128+64], ih[64];
    if(keyLen>128){ sha512(tk,key,keyLen); key=tk; keyLen=64; }
    for(int i=0;i<128;i++){ uint8_t k=(i<(int)keyLen)?key[i]:0; k_ipad[i]=k^0x36; k_opad[i]=k^0x5c; }
    memcpy(inner,k_ipad,128); memcpy(inner+128,data,dataLen);
    sha512(ih, inner, 128+dataLen);
    memcpy(outer,k_opad,128); memcpy(outer+128,ih,64);
    sha512(out, outer, 192);
}
static void pbkdf2_(const char *pw, const uint8_t *salt, size_t saltLen,
                    uint32_t iters, uint8_t *out, size_t outLen){
    size_t pwl=strlen(pw); uint32_t blocks=(outLen+63)/64;
    uint8_t sb[128], U[64], T[64];
    for(uint32_t b=1;b<=blocks;b++){
        memcpy(sb,salt,saltLen);
        sb[saltLen]=b>>24; sb[saltLen+1]=b>>16; sb[saltLen+2]=b>>8; sb[saltLen+3]=b;
        hmac_sha512_((const uint8_t*)pw,pwl,sb,saltLen+4,U); memcpy(T,U,64);
        for(uint32_t i=1;i<iters;i++){ uint8_t up[64]; memcpy(up,U,64);
            hmac_sha512_((const uint8_t*)pw,pwl,up,64,U); for(int k=0;k<64;k++) T[k]^=U[k]; }
        size_t off=(b-1)*64, cp=(outLen-off<64)?outLen-off:64; memcpy(out+off,T,cp);
    }
}

/* ── XTS over one data unit (index `unit`), len a multiple of 16 ──
 * Mirrors veracrypt_impl.d xts_encrypt_sector: tweak = E_key2(unit_LE), per-block
 * XOR-cipher-XOR, GF(2^128) mul by alpha (reduce with 0x87). */
static void xts_(uint8_t *buf, size_t len, uint64_t unit,
                 const aes_encrypt_ctx *ek1, const aes_decrypt_ctx *dk1,
                 const aes_encrypt_ctx *ek2, int encrypt){
    uint8_t tw[16]; memset(tw,0,16);
    for(int i=0;i<8;i++) tw[i]=(uint8_t)(unit>>(8*i));
    aes_encrypt(tw,tw,ek2);
    for(size_t o=0;o<len;o+=16){
        for(int j=0;j<16;j++) buf[o+j]^=tw[j];
        if(encrypt) aes_encrypt(buf+o,buf+o,ek1); else aes_decrypt(buf+o,buf+o,dk1);
        for(int j=0;j<16;j++) buf[o+j]^=tw[j];
        uint8_t carry=0; for(int j=0;j<16;j++){ uint8_t nc=tw[j]>>7; tw[j]=(uint8_t)(tw[j]<<1)|carry; carry=nc; }
        if(carry) tw[0]^=0x87;
    }
}

int vc_create_header(const char *password, const uint8_t salt[VC_SALT_SIZE],
                     const uint8_t masterKey[VC_MASTER_KEYDATA_SIZE],
                     uint64_t hiddenVolSize, uint64_t volumeSize,
                     uint64_t encAreaStart, uint64_t encAreaLen,
                     uint8_t out[VC_HEADER_SIZE]){
    uint8_t h[VC_HEADER_SIZE]; memset(h,0,sizeof h);
    memcpy(h, salt, VC_SALT_SIZE);                 /* [0..63]  plaintext salt        */
    memcpy(h+64, "VERA", 4);                       /* [64]     magic                 */
    be16(h+68, 0x0005);                            /* [68]     version               */
    be16(h+70, 0x0111);                            /* [70]     min program version   */
    memcpy(h+256, masterKey, VC_MASTER_KEYDATA_SIZE);/* [256]  master keydata        */
    be32(h+72, crc32_(h+256, VC_MASTER_KEYDATA_SIZE));/* [72]  key-area CRC          */
    be64(h+92,  hiddenVolSize);                    /* [92]     hidden volume size    */
    be64(h+100, volumeSize);                       /* [100]    volume size           */
    be64(h+108, encAreaStart);                     /* [108]    encrypted area start  */
    be64(h+116, encAreaLen);                       /* [116]    encrypted area length */
    be32(h+124, 0);                                /* [124]    flags                 */
    be32(h+128, 512);                              /* [128]    sector size           */
    be32(h+252, crc32_(h+64, 188));                /* [252]    header CRC of [64..251]*/

    uint8_t hk[64]; pbkdf2_(password, salt, VC_SALT_SIZE, VC_HEADER_ITERATIONS, hk, 64);
    aes_encrypt_ctx ek1, ek2; aes_encrypt_key256(hk,&ek1); aes_encrypt_key256(hk+32,&ek2);
    xts_(h+64, VC_HEADER_SIZE-64, 0, &ek1, 0, &ek2, 1);  /* encrypt [64..512) */
    memcpy(out, h, VC_HEADER_SIZE);
    return 0;
}

void vc_xts_encrypt(uint8_t *buf, size_t len, uint64_t unit,
                    const uint8_t key1[32], const uint8_t key2[32]){
    aes_encrypt_ctx ek1, ek2; aes_encrypt_key256(key1,&ek1); aes_encrypt_key256(key2,&ek2);
    xts_(buf, len, unit, &ek1, 0, &ek2, 1);
}
void vc_xts_decrypt(uint8_t *buf, size_t len, uint64_t unit,
                    const uint8_t key1[32], const uint8_t key2[32]){
    aes_decrypt_ctx dk1; aes_decrypt_key256(key1,&dk1);
    aes_encrypt_ctx ek2; aes_encrypt_key256(key2,&ek2);
    xts_(buf, len, unit, 0, &dk1, &ek2, 0);
}

int vc_open_header(const char *password, const uint8_t header[VC_HEADER_SIZE],
                   uint8_t outMasterKey[VC_MASTER_KEYDATA_SIZE]){
    uint8_t h[VC_HEADER_SIZE]; memcpy(h, header, VC_HEADER_SIZE);
    uint8_t hk[64]; pbkdf2_(password, h /*salt*/, VC_SALT_SIZE, VC_HEADER_ITERATIONS, hk, 64);
    aes_encrypt_ctx ek2; aes_encrypt_key256(hk+32,&ek2);
    aes_decrypt_ctx dk1; aes_decrypt_key256(hk,&dk1);
    xts_(h+64, VC_HEADER_SIZE-64, 0, 0, &dk1, &ek2, 0);  /* decrypt [64..512) */
    if(memcmp(h+64, "VERA", 4) != 0)            return -1;   /* wrong password   */
    if(rbe32(h+252) != crc32_(h+64, 188))       return -2;   /* header CRC       */
    if(rbe32(h+72)  != crc32_(h+256, VC_MASTER_KEYDATA_SIZE)) return -3; /* key CRC */
    memcpy(outMasterKey, h+256, VC_MASTER_KEYDATA_SIZE);
    return 0;
}
