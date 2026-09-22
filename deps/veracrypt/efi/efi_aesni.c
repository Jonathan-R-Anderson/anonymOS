/* deps/veracrypt/efi — AES-NI accelerated XTS for the pre-boot loader (INSTALLER.md §E5d/E6).
 *
 * The software AES in efi_vc.c expands the key schedule for EVERY 16-byte block (it was
 * written for a 512-byte header and a 12 MB UKI).  A Full-disk / Hidden-OS EpinAnonymOS boot
 * decrypts the whole 512 MiB boot volume off the raw disk before Limine can run, and at the
 * software path's rate that is minutes; with AES-NI it is well under a second.
 *
 * Semantics are IDENTICAL to efi_vc.c:xts_dec (validated by aesni_xts_selftest, run by the
 * PROOF build): tweak = AES-256-encrypt(k2, LE64(unit) || 0*8), per-block ct ^ tw -> AES-256-
 * decrypt(k1) -> ^ tw, tweak advanced by GF(2^128) x-multiplication in little-endian byte order
 * with the 0x87 feedback into byte 0.
 *
 * Freestanding PE target: clang -target x86_64-unknown-windows -maes -msse2.  <wmmintrin.h>
 * drags in mm_malloc.h -> <stdlib.h>, which does not exist here; pre-defining __MM_MALLOC_H
 * skips that include (the standard trick for freestanding intrinsics). */
#define __MM_MALLOC_H
#include <wmmintrin.h>
#include <emmintrin.h>

typedef unsigned char      u8;
typedef unsigned int       u32;
typedef unsigned long long u64;

int aesni_available(void){
    u32 a, b, c, d;
    __asm__ __volatile__("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
    return (c >> 25) & 1;            /* CPUID.1:ECX.AESNI */
}

/* AES-256 key expansion (FIPS-197 §5.2) with AESKEYGENASSIST: the two-step pattern for a
 * 256-bit key — RotWord/SubWord/Rcon on the odd steps, SubWord only on the even ones. */
static inline __m128i kexp_a(__m128i k, __m128i t){          /* t = keygenassist(..., rcon) */
    t = _mm_shuffle_epi32(t, 0xFF);
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    return _mm_xor_si128(k, t);
}
static inline __m128i kexp_b(__m128i k, __m128i t){          /* t = keygenassist(prev, 0) */
    t = _mm_shuffle_epi32(t, 0xAA);
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    return _mm_xor_si128(k, t);
}
static void aes256_expand(const u8 *key, __m128i rk[15]){
    __m128i k0 = _mm_loadu_si128((const __m128i*)key);
    __m128i k1 = _mm_loadu_si128((const __m128i*)(key + 16));
    rk[0] = k0; rk[1] = k1;
#define STEP(i, rcon) \
    k0 = kexp_a(k0, _mm_aeskeygenassist_si128(k1, rcon)); rk[2*(i)]   = k0; \
    k1 = kexp_b(k1, _mm_aeskeygenassist_si128(k0, 0));    rk[2*(i)+1] = k1;
    STEP(1, 0x01) STEP(2, 0x02) STEP(3, 0x04) STEP(4, 0x08) STEP(5, 0x10) STEP(6, 0x20)
#undef STEP
    k0 = kexp_a(k0, _mm_aeskeygenassist_si128(k1, 0x40)); rk[14] = k0;
}
/* Equivalent-inverse-cipher round keys for AESDEC: reversed order, IMC on the inner rounds. */
static void aes256_expand_dec(const __m128i enc[15], __m128i dec[15]){
    dec[0] = enc[14];
    for (int i = 1; i < 14; i++) dec[i] = _mm_aesimc_si128(enc[14 - i]);
    dec[14] = enc[0];
}
static inline __m128i aes_enc_block(__m128i s, const __m128i rk[15]){
    s = _mm_xor_si128(s, rk[0]);
    for (int r = 1; r < 14; r++) s = _mm_aesenc_si128(s, rk[r]);
    return _mm_aesenclast_si128(s, rk[14]);
}
static inline __m128i aes_dec_block(__m128i s, const __m128i dk[15]){
    s = _mm_xor_si128(s, dk[0]);
    for (int r = 1; r < 14; r++) s = _mm_aesdec_si128(s, dk[r]);
    return _mm_aesdeclast_si128(s, dk[14]);
}
/* tweak <- tweak * x in GF(2^128), little-endian byte order (byte 15 bit 7 is the MSB; the
 * carry out of it feeds 0x87 into byte 0).  Per-lane 32-bit shifts carry correctly inside a
 * little-endian lane; the cross-lane carries are the rotated sign lanes masked to 1 (or 0x87
 * for the wrap-around lane). */
static inline __m128i xts_mul_x(__m128i tw){
    const __m128i mask = _mm_set_epi32(1, 1, 1, 0x87);
    __m128i c = _mm_srai_epi32(tw, 31);                       /* all-ones where a lane's MSB is set */
    c = _mm_shuffle_epi32(c, 0x93);                           /* lane3->0, lane0->1, lane1->2, lane2->3 */
    c = _mm_and_si128(c, mask);
    return _mm_xor_si128(_mm_slli_epi32(tw, 1), c);
}

/* Decrypt `nunits` consecutive 512-byte data units in place; the first has index `first_unit`. */
void aesni_xts_decrypt_units(u8 *buf, u64 nunits, u64 first_unit, const u8 *k1, const u8 *k2){
    __m128i ek1[15], dk1[15], ek2[15];
    aes256_expand(k1, ek1); aes256_expand_dec(ek1, dk1);
    aes256_expand(k2, ek2);
    for (u64 u = 0; u < nunits; u++){
        u8 *p = buf + u * 512;
        __m128i tw = aes_enc_block(_mm_set_epi64x(0, (long long)(first_unit + u)), ek2);
        for (int o = 0; o < 512; o += 16){
            __m128i c = _mm_loadu_si128((const __m128i*)(p + o));
            c = _mm_xor_si128(c, tw);
            c = aes_dec_block(c, dk1);
            c = _mm_xor_si128(c, tw);
            _mm_storeu_si128((__m128i*)(p + o), c);
            tw = xts_mul_x(tw);
        }
    }
    /* scrub the schedules: they are the master key in another form */
    for (int i = 0; i < 15; i++){ ek1[i] = _mm_setzero_si128(); dk1[i] = _mm_setzero_si128(); ek2[i] = _mm_setzero_si128(); }
    __asm__ __volatile__("" : : "r"(ek1), "r"(dk1), "r"(ek2) : "memory");
}
