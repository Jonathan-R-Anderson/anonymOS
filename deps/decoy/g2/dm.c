/* deps/decoy/g2 — honey-hashed, typo-tolerant decoy boot matcher (§G2.2). See dm.h. */
#include "dm.h"
#include "decoy.h"

static uint64_t mix(uint64_t x){
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}
/* exact salted hash of a password (test: fast; production: PBKDF2 from §E) */
static uint64_t verify_hash(const char *pw, uint64_t salt){
    uint64_t h = salt ^ 0xCBF29CE484222325ULL;
    for (const char *p = pw; *p; p++){ h ^= (uint8_t)*p; h *= 0x100000001B3ULL; }
    for (int i = 0; i < 4; i++) h = mix(h);    /* a few rounds; prod = many KDF iterations */
    return h;
}

void dm_init(DecoyMatcher *m){ m->n = 0; }

int dm_register_decoy(DecoyMatcher *m, const char *password){
    if (m->n >= 64) return -1;
    uint64_t salt = mix(0xD3C0DE00ULL + (uint64_t)m->n);
    m->v[m->n] = (DecoyVerifier){ salt, verify_hash(password, salt), 1 };
    return m->n++;
}
void dm_register_chaff(DecoyMatcher *m, int count){
    for (int i = 0; i < count && m->n < 64; i++){
        uint64_t salt = mix(0xD3C0DE00ULL + (uint64_t)m->n);
        m->v[m->n] = (DecoyVerifier){ salt, mix(salt ^ 0xC4AFFULL ^ (uint64_t)i), 0 };  /* no pw maps here */
        m->n++;
    }
}

static char swapcase(char c){ if(c>='a'&&c<='z')return c-32; if(c>='A'&&c<='Z')return c+32; return c; }
static void cp(char *d, const char *s){ while((*d++=*s++)); }
static int  len(const char *s){ int n=0; while(s[n])n++; return n; }

/* bounded typo-correction candidates of the INPUT (Chatterjee common typos + cheap edits):
 * as-is, caps-lock toggle, first-char case, adjacent transpositions, single deletions.
 * Deliberately NOT general insertions/substitutions — that widens the accept set + costs a
 * slow hash each (the documented usability<->security tradeoff). */
static int candidates(const char *in, char out[][128], int max){
    int n = 0, L = len(in);
    if (L >= 128) return 0;
    cp(out[n++], in);                                                   /* as-is */
    { char b[128]; for(int i=0;i<L;i++)b[i]=swapcase(in[i]); b[L]=0; cp(out[n++],b); }   /* caps lock */
    if (L>0 && n<max){ char b[128]; cp(b,in); b[0]=swapcase(b[0]); cp(out[n++],b); }     /* first char */
    for (int i=0;i+1<L && n<max;i++){ char b[128]; cp(b,in); char t=b[i];b[i]=b[i+1];b[i+1]=t; cp(out[n++],b); } /* transpose */
    for (int i=0;i<L && n<max;i++){ char b[128]; int k=0; for(int j=0;j<L;j++) if(j!=i) b[k++]=in[j]; b[k]=0; cp(out[n++],b); } /* delete */
    return n;
}

int dm_match(const DecoyMatcher *m, const char *typed, int *idx, uint64_t *seed){
    char cand[64][128];
    int nc = candidates(typed, cand, 64);
    for (int c = 0; c < nc; c++){
        for (int i = 0; i < m->n; i++){
            if (!m->v[i].is_real) continue;                            /* never match chaff */
            if (verify_hash(cand[c], m->v[i].salt) == m->v[i].hash){
                if (idx)  *idx  = i;
                if (seed) *seed = decoy_seed(cand[c]);                 /* snap to the canonical decoy */
                return 1;
            }
        }
    }
    return 0;                                                          /* reject — reveal nothing */
}
