/* deps/decoy — deterministic decoy activity generator engine (§G). See decoy.h. */
#include "decoy.h"

#define FP 16              /* 16.16 fixed-point */
#define ONE (1u << FP)     /* 1.0 == 65536 */

/* splitmix64 finalizer — good avalanche, fully deterministic */
static uint64_t mix(uint64_t x){
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}
static uint64_t h2(uint64_t s, uint64_t a){ return mix(s ^ mix(a)); }
static uint64_t h3(uint64_t s, uint64_t a, uint64_t b){ return mix(s ^ mix(a*0xD1B54A32D192ED03ULL ^ b)); }
static uint64_t h4(uint64_t s, uint64_t a, uint64_t b, uint64_t c){ return mix(h3(s,a,b) ^ mix(c)); }

uint64_t decoy_seed(const char *password){
    uint64_t s = 0xCBF29CE484222325ULL;            /* FNV-1a offset */
    for (const char *p = password; *p; p++){ s ^= (uint8_t)*p; s *= 0x100000001B3ULL; }
    return mix(s);
}

/* value of the noise lattice at integer node i, in [0,ONE) */
static uint32_t node(uint64_t seed, int64_t i){ return (uint32_t)(h2(seed, (uint64_t)i) & (ONE - 1)); }

/* smoothstep on a fixed-point fraction f in [0,ONE): 3f^2 - 2f^3 */
static uint32_t smooth(uint32_t f){
    uint64_t ff = (uint64_t)f * f >> FP;            /* f^2 */
    uint64_t fff = ff * f >> FP;                    /* f^3 */
    return (uint32_t)(3 * ff - 2 * fff);
}

/* 1-D value noise at fixed-point position t_fp (16.16), in [0,ONE) */
static uint32_t vnoise(uint64_t seed, int64_t t_fp){
    int64_t  i = t_fp >> FP;
    uint32_t f = (uint32_t)(t_fp & (ONE - 1));
    int32_t  a = (int32_t)node(seed, i), b = (int32_t)node(seed, i + 1);
    uint32_t s = smooth(f);
    return (uint32_t)(a + (((int64_t)(b - a) * s) >> FP));
}

/* fractional Brownian motion: 4 octaves of value noise, result in [0,ONE) */
static uint32_t fbm(uint64_t seed, int64_t t_fp){
    int64_t acc = 0, norm = 0;
    int32_t amp = ONE;
    for (int o = 0; o < 4; o++){
        acc  += (int64_t)vnoise(seed + (uint64_t)o * 0x1000, t_fp << o) * amp;
        norm += amp;
        amp >>= 1;
    }
    return (uint32_t)(acc / norm);
}

uint32_t decoy_intensity(uint64_t seed, uint64_t bin){
    /* one octave-rich field over slow time (period ~ tens of hours) so activity comes in
     * multi-hour bursts, modulated by a daily cycle so nights are quiet. */
    uint64_t isd = seed ^ 0xA5A5A5A5A5A5A5A5ULL;
    uint32_t base = fbm(isd, (int64_t)((bin << FP) / 17));      /* slow coherent swell */
    uint32_t hour = bin % 24;
    /* daily envelope: low at night (~0.3), high midday (~1.0), triangle-ish */
    uint32_t day = (hour < 12 ? hour : 24 - hour);             /* 0..12 */
    uint32_t env = ONE/3 + (day * (ONE - ONE/3)) / 12;          /* [0.33, 1.0] */
    return (uint32_t)(((uint64_t)base * env) >> FP);
}

/* per-subsystem tuning: base events/hour at full intensity, and the burstiness exponent */
static const uint16_t SUB_BASE[DECOY_NSUB]  = { 9, 6, 2, 1, 7, 1, 5, 4 };
static const uint8_t  SUB_GAMMA[DECOY_NSUB] = { 2, 3, 2, 1, 3, 4, 3, 2 };

int decoy_events(uint64_t seed, int subsys, uint64_t bin0, uint64_t nbins,
                 DecoyEvent *out, int max){
    if (subsys < 0 || subsys >= DECOY_NSUB) return 0;
    int n = 0;
    for (uint64_t b = bin0; b < bin0 + nbins; b++){
        uint32_t inten = decoy_intensity(seed, b);                   /* shared field -> correlation */
        uint32_t ic = inten;
        for (int g = 1; g < SUB_GAMMA[subsys]; g++) ic = (uint32_t)(((uint64_t)ic * inten) >> FP);
        /* lambda (events this hour) in 16.16 = base * intensity^gamma */
        uint64_t lam = (uint64_t)SUB_BASE[subsys] * ic;              /* [0, base.0] */
        uint32_t cnt = (uint32_t)(lam >> FP);
        uint64_t hb = h3(seed, (uint64_t)subsys, b);
        if ((uint32_t)(hb & (ONE - 1)) < (uint32_t)(lam & (ONE - 1))) cnt++;   /* bernoulli on the frac */
        /* heavy-tailed bursts during high-activity periods (a service flood, a scan, a
         * batch job): gated on the SHARED intensity so bursts also correlate across
         * subsystems, with a per-(subsys,hour) trigger + magnitude. Gives realistic
         * over-dispersion (Fano >> 1) instead of a smooth Poisson stream. */
        if (inten > (ONE * 7 / 10)) {
            uint64_t bh = h3(seed, (uint64_t)subsys + 0x100, b);
            if ((bh & 7) < 5) cnt += 4 + (uint32_t)((bh >> 8) % 12);
        }
        for (uint32_t k = 0; k < cnt; k++){
            if (n >= max) return n;
            uint64_t he = h4(seed, (uint64_t)subsys, b, k);
            out[n].time_sec = b * 3600ULL + (he % 3600ULL);         /* deterministic offset in the hour */
            out[n].subsys   = (uint8_t)subsys;
            out[n].detail   = (uint32_t)(he >> 32);                 /* e.g. which user/port/pid */
            n++;
        }
    }
    return n;
}
