#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "fim.h"

/* ── Portable SHA-256 implementation ───────────────────────────────────── */
/* Self-contained; no external dependencies. */

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
    int      buflen;
} sha256_ctx_t;

static const uint32_t K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SIG0(x)  (ROTR32(x,  7) ^ ROTR32(x, 18) ^ ((x) >>  3))
#define SIG1(x)  (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))
#define EP0(x)   (ROTR32(x,  2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define EP1(x)   (ROTR32(x,  6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

static void sha256_transform(uint32_t state[8], const uint8_t data[64])
{
    uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[i*4]   << 24) |
               ((uint32_t)data[i*4+1] << 16) |
               ((uint32_t)data[i*4+2] <<  8) |
               ((uint32_t)data[i*4+3]);
    }
    for (; i < 64; i++)
        w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e,f,g) + K256[i] + w[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256_init(sha256_ctx_t *ctx)
{
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
    ctx->count  = 0;
    ctx->buflen = 0;
}

static void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len)
{
    while (len > 0) {
        int space = 64 - ctx->buflen;
        int take  = (len < (size_t)space) ? (int)len : space;
        memcpy(ctx->buf + ctx->buflen, data, take);
        ctx->buflen += take;
        ctx->count  += (uint64_t)take * 8;
        data        += take;
        len         -= (size_t)take;
        if (ctx->buflen == 64) {
            sha256_transform(ctx->state, ctx->buf);
            ctx->buflen = 0;
        }
    }
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t digest[32])
{
    int i;
    ctx->buf[ctx->buflen++] = 0x80;
    if (ctx->buflen > 56) {
        while (ctx->buflen < 64) ctx->buf[ctx->buflen++] = 0;
        sha256_transform(ctx->state, ctx->buf);
        ctx->buflen = 0;
    }
    while (ctx->buflen < 56) ctx->buf[ctx->buflen++] = 0;
    /* Length in bits, big-endian */
    uint64_t bits = ctx->count;
    for (i = 7; i >= 0; i--) { ctx->buf[56 + (7 - i)] = (uint8_t)(bits >> (i * 8)); }
    sha256_transform(ctx->state, ctx->buf);

    for (i = 0; i < 8; i++) {
        digest[i*4]   = (uint8_t)(ctx->state[i] >> 24);
        digest[i*4+1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i*4+2] = (uint8_t)(ctx->state[i] >>  8);
        digest[i*4+3] = (uint8_t)(ctx->state[i]);
    }
}

/* Hash a file and write 32-byte digest into out.
 * Returns 0 on success, -1 on error. */
static int hash_file(const char *path, uint8_t digest[32])
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;

    sha256_ctx_t ctx;
    sha256_init(&ctx);

    uint8_t buf[4096];
    size_t  n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        sha256_update(&ctx, buf, n);

    fclose(f);
    sha256_final(&ctx, digest);
    return 0;
}

/* ── FIM watchlist ──────────────────────────────────────────────────────── */

#define FIM_MAX 16

typedef struct {
    char    path[256];
    uint8_t hash[32];   /* current known-good SHA-256 */
    int     valid;      /* 1 = hash populated, 0 = file not readable at init */
} fim_entry_t;

static fim_entry_t g_entries[FIM_MAX];
static int         g_count = 0;

/* ── public API ─────────────────────────────────────────────────────────── */

void fim_init(const char (*paths)[256], int count)
{
    g_count = 0;
    if (!paths || count <= 0)
        return;
    if (count > FIM_MAX)
        count = FIM_MAX;

    for (int i = 0; i < count; i++) {
        fim_entry_t *ent = &g_entries[g_count++];
        strncpy(ent->path, paths[i], sizeof(ent->path) - 1);
        ent->path[sizeof(ent->path) - 1] = '\0';
        ent->valid = (hash_file(ent->path, ent->hash) == 0) ? 1 : 0;
        if (!ent->valid)
            fprintf(stderr, "[FIM] warning: could not hash %s at init\n",
                    ent->path);
    }
}

void fim_check(const event_t *e)
{
    if (!e || e->type != EVENT_WRITE_CLOSE)
        return;

    for (int i = 0; i < g_count; i++) {
        if (strncmp(e->filename, g_entries[i].path, 255) != 0)
            continue;

        uint8_t new_hash[32];
        if (hash_file(g_entries[i].path, new_hash) != 0)
            return;   /* file unreadable — skip silently */

        if (memcmp(new_hash, g_entries[i].hash, 32) != 0) {
            fprintf(stderr, "[FIM] %s hash changed\n", g_entries[i].path);
            memcpy(g_entries[i].hash, new_hash, 32);
        }
        return;   /* path matched; no need to check further entries */
    }
}

void fim_free(void)
{
    memset(g_entries, 0, sizeof(g_entries));
    g_count = 0;
}
