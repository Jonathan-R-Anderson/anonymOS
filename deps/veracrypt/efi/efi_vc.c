/* deps/veracrypt/efi — self-contained VeraCrypt header-open for the EFI pre-boot loader
 * (roadmap/INSTALLER.md §E5b). No libc, no VeraCrypt headers (the PE/EFI target can't use
 * either). AES-256 enc+dec, SHA-512, HMAC/PBKDF2, XTS-decrypt, vc_open_header,
 * preboot_authenticate — the same algorithms as veracrypt_impl.d / vcheader.c, validated
 * by the OVMF self-test opening the kernel-written headers. */
#include "efi_vc.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

static void *vc_memcpy(void *d, const void *s, u64 n){ u8*a=d; const u8*b=s; while(n--)*a++=*b++; return d; }
static int   vc_memcmp(const void *x, const void *y, u64 n){ const u8*a=x,*b=y; while(n--){ if(*a!=*b) return *a-*b; a++;b++; } return 0; }
static u64   vc_strlen(const char *s){ u64 n=0; while(s[n]) n++; return n; }

/* ── AES-256 (enc + dec, single block, key schedule per call) ── */
static const u8 SB[256]={
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};
static u8 ISB[256];
static int isb_ready=0;
static void mk_isb(void){ for(int i=0;i<256;i++) ISB[SB[i]]=(u8)i; isb_ready=1; }

static u8 xt(u8 x){ return (u8)((x<<1) ^ (((x>>7)&1)*0x1b)); }
static u8 gm(u8 a,u8 b){ u8 p=0; for(int i=0;i<8;i++){ if(b&1)p^=a; u8 hi=a&0x80; a<<=1; if(hi)a^=0x1b; b>>=1; } return p; }

static const u8 RC[7]={0x01,0x02,0x04,0x08,0x10,0x20,0x40};
static void expand(const u8*key, u8*rk){
    for(int i=0;i<32;i++) rk[i]=key[i];
    u32 n=32; u8 ri=0, t[4];
    while(n<240){
        for(int i=0;i<4;i++) t[i]=rk[n-4+i];
        if(n%32==0){ u8 tmp=t[0]; t[0]=t[1];t[1]=t[2];t[2]=t[3];t[3]=tmp; for(int i=0;i<4;i++)t[i]=SB[t[i]]; t[0]^=RC[ri++]; }
        else if(n%32==16){ for(int i=0;i<4;i++)t[i]=SB[t[i]]; }
        for(int i=0;i<4;i++){ rk[n]=(u8)(rk[n-32]^t[i]); n++; }
    }
}
static void srows(u8*s){ u8 t;
    t=s[1];s[1]=s[5];s[5]=s[9];s[9]=s[13];s[13]=t;
    t=s[2];s[2]=s[10];s[10]=t; t=s[6];s[6]=s[14];s[14]=t;
    t=s[15];s[15]=s[11];s[11]=s[7];s[7]=s[3];s[3]=t; }
static void isrows(u8*s){ u8 t;
    t=s[13];s[13]=s[9];s[9]=s[5];s[5]=s[1];s[1]=t;
    t=s[2];s[2]=s[10];s[10]=t; t=s[6];s[6]=s[14];s[14]=t;
    t=s[3];s[3]=s[7];s[7]=s[11];s[11]=s[15];s[15]=t; }
static void mcol(u8*s){ for(int c=0;c<4;c++){ u8*p=s+c*4,a=p[0],b=p[1],cc=p[2],d=p[3];
    p[0]=(u8)(xt(a)^(xt(b)^b)^cc^d); p[1]=(u8)(a^xt(b)^(xt(cc)^cc)^d);
    p[2]=(u8)(a^b^xt(cc)^(xt(d)^d)); p[3]=(u8)((xt(a)^a)^b^cc^xt(d)); } }
static void imcol(u8*s){ for(int c=0;c<4;c++){ u8*p=s+c*4,a=p[0],b=p[1],cc=p[2],d=p[3];
    p[0]=(u8)(gm(a,14)^gm(b,11)^gm(cc,13)^gm(d,9)); p[1]=(u8)(gm(a,9)^gm(b,14)^gm(cc,11)^gm(d,13));
    p[2]=(u8)(gm(a,13)^gm(b,9)^gm(cc,14)^gm(d,11)); p[3]=(u8)(gm(a,11)^gm(b,13)^gm(cc,9)^gm(d,14)); } }

static void aes_enc(u8*blk,const u8*key){ u8 rk[240],s[16]; expand(key,rk);
    for(int i=0;i<16;i++) s[i]=(u8)(blk[i]^rk[i]);
    for(int r=1;r<14;r++){ for(int i=0;i<16;i++)s[i]=SB[s[i]]; srows(s); mcol(s); for(int i=0;i<16;i++)s[i]^=rk[r*16+i]; }
    for(int i=0;i<16;i++)s[i]=SB[s[i]]; srows(s); for(int i=0;i<16;i++)blk[i]=(u8)(s[i]^rk[224+i]); }
static void aes_dec(u8*blk,const u8*key){ if(!isb_ready)mk_isb(); u8 rk[240],s[16]; expand(key,rk);
    for(int i=0;i<16;i++) s[i]=(u8)(blk[i]^rk[224+i]);
    for(int r=13;r>=1;r--){ isrows(s); for(int i=0;i<16;i++)s[i]=ISB[s[i]]; for(int i=0;i<16;i++)s[i]^=rk[r*16+i]; imcol(s); }
    isrows(s); for(int i=0;i<16;i++)s[i]=ISB[s[i]]; for(int i=0;i<16;i++)blk[i]=(u8)(s[i]^rk[i]); }

/* ── SHA-512 ── */
static const u64 K[80]={
0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL};
static u64 ror(u64 x,u32 n){ return (x>>n)|(x<<(64-n)); }
static void sha_blk(u64 h[8], const u8*p){ u64 w[80];
    for(int i=0;i<16;i++){ u64 v=0; for(int j=0;j<8;j++) v=(v<<8)|p[i*8+j]; w[i]=v; }
    for(int i=16;i<80;i++){ u64 s0=ror(w[i-15],1)^ror(w[i-15],8)^(w[i-15]>>7), s1=ror(w[i-2],19)^ror(w[i-2],61)^(w[i-2]>>6); w[i]=w[i-16]+s0+w[i-7]+s1; }
    u64 a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for(int i=0;i<80;i++){ u64 S1=ror(e,14)^ror(e,18)^ror(e,41),ch=(e&f)^(~e&g),t1=hh+S1+ch+K[i]+w[i],S0=ror(a,28)^ror(a,34)^ror(a,39),mj=(a&b)^(a&c)^(b&c),t2=S0+mj;
        hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2; }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh; }
static void sha512(const u8*data,u64 len,u8*out){
    u64 h[8]={0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL};
    u64 full=len/128; for(u64 b=0;b<full;b++) sha_blk(h,data+b*128);
    u8 buf[256]; for(int i=0;i<256;i++)buf[i]=0; u64 rem=len-full*128; for(u64 i=0;i<rem;i++)buf[i]=data[full*128+i];
    buf[rem]=0x80; u64 blocks=(rem>=112)?2:1, tot=blocks*128, lo=len<<3, hi=len>>61;
    for(int i=0;i<8;i++)buf[tot-16+i]=(u8)(hi>>(56-8*i)); for(int i=0;i<8;i++)buf[tot-8+i]=(u8)(lo>>(56-8*i));
    for(u64 b=0;b<blocks;b++) sha_blk(h,buf+b*128);
    for(int i=0;i<8;i++) for(int j=0;j<8;j++) out[i*8+j]=(u8)(h[i]>>(56-8*j)); }

/* ── HMAC-SHA512 + PBKDF2 ── */
static void hmac(const u8*key,u64 kl,const u8*data,u64 dl,u8*out){
    u8 ip[128],op[128],ih[64],ib[256],ob[192];
    for(int i=0;i<128;i++){ u8 k=(i<(int)kl)?key[i]:0; ip[i]=k^0x36; op[i]=k^0x5c; }
    vc_memcpy(ib,ip,128); vc_memcpy(ib+128,data,dl); sha512(ib,128+dl,ih);
    vc_memcpy(ob,op,128); vc_memcpy(ob+128,ih,64); sha512(ob,192,out); }
static void pbkdf2(const char*pw,const u8*salt,u32 iters,u8*out,u32 ol){
    u64 pl=vc_strlen(pw); u32 blocks=(ol+63)/64; u8 sb[68],U[64],T[64];
    for(u32 b=1;b<=blocks;b++){ for(int i=0;i<64;i++)sb[i]=salt[i]; sb[64]=b>>24;sb[65]=b>>16;sb[66]=b>>8;sb[67]=b;
        hmac((const u8*)pw,pl,sb,68,U); vc_memcpy(T,U,64);
        for(u32 i=1;i<iters;i++){ u8 up[64]; vc_memcpy(up,U,64); hmac((const u8*)pw,pl,up,64,U); for(int k=0;k<64;k++)T[k]^=U[k]; }
        u32 off=(b-1)*64,cp=(ol-off<64)?ol-off:64; for(u32 k=0;k<cp;k++)out[off+k]=T[k]; } }

static u32 crc32_(const u8*d,u64 n){ u32 c=0xFFFFFFFFu; for(u64 i=0;i<n;i++){ c^=d[i]; for(int j=0;j<8;j++) c=(c&1)?(c>>1)^0xEDB88320u:(c>>1);} return ~c; }
static u32 rbe32(const u8*p){ return (u32)p[0]<<24|(u32)p[1]<<16|(u32)p[2]<<8|p[3]; }

/* XTS-decrypt one data unit (tweak via AES-encrypt, data via AES-decrypt) */
static void xts_dec(u8*buf,u64 len,u64 unit,const u8*k1,const u8*k2){
    u8 tw[16]; for(int i=0;i<16;i++)tw[i]=0; for(int i=0;i<8;i++)tw[i]=(u8)(unit>>(8*i)); aes_enc(tw,k2);
    for(u64 o=0;o<len;o+=16){ for(int j=0;j<16;j++)buf[o+j]^=tw[j]; aes_dec(buf+o,k1); for(int j=0;j<16;j++)buf[o+j]^=tw[j];
        u8 carry=0; for(int j=0;j<16;j++){ u8 nc=tw[j]>>7; tw[j]=(u8)(tw[j]<<1)|carry; carry=nc; } if(carry)tw[0]^=0x87; } }

int vc_open_header(const char*pw,const unsigned char header[512],unsigned char outKey[256]){
    u8 h[512]; vc_memcpy(h,header,512);
    u8 hk[64]; pbkdf2(pw,h,VC_HEADER_ITERATIONS,hk,64);
    xts_dec(h+64,448,0,hk,hk+32);
    if(h[64]!='V'||h[65]!='E'||h[66]!='R'||h[67]!='A') return -1;
    if(rbe32(h+252)!=crc32_(h+64,188)) return -2;
    if(rbe32(h+72)!=crc32_(h+256,256)) return -3;
    vc_memcpy(outKey,h+256,256);
    return 0;
}

/* §G2.2 typo tolerance — fuzz the INPUT (caps-lock / first-char / transposition / single
 * deletion), the same bounded model as deps/decoy/g2/dm.c. The VeraCrypt header is the
 * exact verifier, so a typo whose correction equals the real password opens the volume. */
static char vc_swapcase(char c){ if(c>='a'&&c<='z')return c-32; if(c>='A'&&c<='Z')return c+32; return c; }
static int vc_typo_candidates(const char *in, char out[][128], int max){
    int n=0, L=0; while(in[L]) L++;
    if (L>=128){ if(max>0){ vc_memcpy(out[0],in,L+1); return 1; } return 0; }
    vc_memcpy(out[n++], in, L+1);                                                       /* as-is */
    if(n<max){ for(int i=0;i<L;i++) out[n][i]=vc_swapcase(in[i]); out[n][L]=0; n++; }   /* caps lock */
    if(L>0 && n<max){ vc_memcpy(out[n],in,L+1); out[n][0]=vc_swapcase(out[n][0]); n++; } /* first char */
    for(int i=0;i+1<L && n<max;i++){ vc_memcpy(out[n],in,L+1); char t=out[n][i]; out[n][i]=out[n][i+1]; out[n][i+1]=t; n++; } /* transpose */
    for(int i=0;i<L && n<max;i++){ int k=0; for(int j=0;j<L;j++) if(j!=i) out[n][k++]=in[j]; out[n][k]=0; n++; } /* delete */
    return n;
}

int preboot_authenticate(const char*pw,const unsigned char decoy[512],const unsigned char hidden[512],unsigned char outKey[256]){
    static char cand[64][128];      /* static: keep the 8 KB off the stack (no __chkstk in freestanding EFI) */
    int nc = vc_typo_candidates(pw, cand, 64);
    int v = PREBOOT_REJECT;
    /* no early-out: try every candidate against both headers so a wrong password takes the
     * same work as a right one (a typo opens whichever header its correction matches). */
    for (int c=0;c<nc;c++){
        u8 kd[256], kh[256];
        int okd = (vc_open_header(cand[c], decoy,  kd)==0);
        int okh = (vc_open_header(cand[c], hidden, kh)==0);
        if (okd && v==PREBOOT_REJECT){ vc_memcpy(outKey,kd,256); v=PREBOOT_DECOY;  }
        if (okh && v==PREBOOT_REJECT){ vc_memcpy(outKey,kh,256); v=PREBOOT_HIDDEN; }
    }
    return v;
}
