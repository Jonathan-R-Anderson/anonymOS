/**
 * D port of BSD compress_zopen.c
 *
 * Provides a FILE-like stream interface for LZW "compress(1)" format
 * with header 0x1f 0x9d and flags.
 *
 * Exports (C ABI):
 *   void*  compress_zopen (const char* fname, const char* mode, int bits);
 *   size_t compress_zread (void* cookie, void* rbp, size_t num);
 *   size_t compress_zwrite(void* cookie, const void* wbp, size_t num);
 *   int    compress_zclose(void* cookie);
 */

module zopen_d;

import core.stdc.stdint : uint32_t, uint16_t, int32_t;
import core.stdc.stdlib : calloc, free;
import core.stdc.string : memcmp, memset, strncpy, strlen;
import core.stdc.errno : errno, EINVAL;
import core.stdc.stdio : FILE, fopen, fread, fwrite, fclose;
import core.sys.posix.sys.stat : stat, stat_t = stat;
import core.stdc.ctype : isspace;

// -------------------- Constants & types (match original) --------------------

enum BITS  = 16;
enum HSIZE = 69001; // 95% occupancy

alias code_int  = long;   // matches original signed usage
alias count_int = long;
alias char_type = ubyte;

// magic header 0x1f 0x9d
immutable(char_type[2]) MAGIC = [0x1F, 0x9D];

enum BIT_MASK   = 0x1f;
enum BLOCK_MASK = 0x80;
enum INIT_BITS  = 9;

// MAXCODE macro -> D function (not C ABI)
@safe pure nothrow @nogc
code_int MAXCODE(uint n_bits)
{
  return (cast(code_int)1 << n_bits) - 1;
}

enum CHECK_GAP = 10000;
enum FIRST = 257;
enum CLEAR = 256;

enum ZStateTag { S_START, S_MIDDLE, S_EOF }

// ------------------------------ State struct --------------------------------

struct ZState {
  FILE*        fp;           // underlying stdio file
  char         zmode;        // 'r' or 'w'
  ZStateTag    state;

  uint         n_bits;       // current bit width
  uint         maxbits;      // user-chosen max
  code_int     maxcode;      // = MAXCODE(n_bits)
  code_int     maxmaxcode;   // = 1L << maxbits

  count_int[HSIZE] htab;
  ushort[HSIZE]    codetab;
  code_int         hsize;    // table size
  code_int         free_ent;

  int          block_compress;
  int          clear_flg;
  long         ratio;
  count_int    checkpoint;
  uint         offset;       // bit offset into output buffer

  long         in_count;
  long         bytes_out;
  long         out_count;

  char_type[BITS] buf;       // output buffer for bit packing (write)

  // Writer fields
  long         fcode;
  code_int     ent;
  code_int     hsize_reg;
  int          hshift;

  // Reader fields
  char_type*   stackp;
  int          finchar;
  code_int     code, oldcode, incode;
  int          roffset, size;
  char_type[BITS] gbuf;
}

// Accessors (keep original style; ref to allow assignments like maxbits(z)=…)
private @property FILE*       fp(ZState* z)            { return z.fp; }
private @property ref uint    n_bits(ZState* z)        { return z.n_bits; }
private @property ref uint    maxbits(ZState* z)       { return z.maxbits; }
private @property ref code_int maxcode(ZState* z)      { return z.maxcode; }
private @property ref code_int maxmaxcode(ZState* z)   { return z.maxmaxcode; }
private @property ref count_int[HSIZE] htab(ZState* z) { return z.htab; }
private @property ref ushort[HSIZE] codetab(ZState* z) { return z.codetab; }
private @property ref code_int hsize(ZState* z)        { return z.hsize; }
private @property ref code_int free_ent(ZState* z)     { return z.free_ent; }
private @property ref int block_compress(ZState* z)    { return z.block_compress; }
private @property ref int clear_flg(ZState* z)         { return z.clear_flg; }
private @property ref long ratio(ZState* z)            { return z.ratio; }
private @property ref count_int checkpoint(ZState* z)  { return z.checkpoint; }
private @property ref uint offset(ZState* z)           { return z.offset; }
private @property ref long in_count(ZState* z)         { return z.in_count; }
private @property ref long bytes_out(ZState* z)        { return z.bytes_out; }
private @property ref long out_count(ZState* z)        { return z.out_count; }
private @property ref char_type[BITS] buf(ZState* z)   { return z.buf; }

private @property ref long fcode(ZState* z)            { return z.fcode; }
private @property ref code_int ent(ZState* z)          { return z.ent; }
private @property ref code_int hsize_reg(ZState* z)    { return z.hsize_reg; }
private @property ref int hshift(ZState* z)            { return z.hshift; }

private @property ref char_type* stackp(ZState* z)     { return z.stackp; }
private @property ref int finchar(ZState* z)           { return z.finchar; }
private @property ref code_int code(ZState* z)         { return z.code; }
private @property ref code_int oldcode(ZState* z)      { return z.oldcode; }
private @property ref code_int incode(ZState* z)       { return z.incode; }
private @property ref int roffset(ZState* z)           { return z.roffset; }
private @property ref int size(ZState* z)              { return z.size; }
private @property ref char_type[BITS] gbuf(ZState* z)  { return z.gbuf; }

// Suffix table views and helpers
private void set_tab_suffix(ZState* z, size_t i, char_type v)
{
  auto base = cast(char_type*)(&z.htab[0]); // view htab storage as bytes
  base[i] = v;
}
private char_type get_tab_suffix(ZState* z, size_t i)
{
  auto base = cast(char_type*)(&z.htab[0]);
  return base[i];
}
private char_type* de_stack(ZState* z)
{
  auto base = cast(char_type*)(&z.htab[0]);
  return base + (1 << BITS);
}

// Bit masks for output/getcode
__gshared char_type[9] lmask = [0xff,0xfe,0xfc,0xf8,0xf0,0xe0,0xc0,0x80,0x00];
__gshared char_type[9] rmask = [0x00,0x01,0x03,0x07,0x0f,0x1f,0x3f,0x7f,0xff];

// ------------------------------ Prototypes ----------------------------------

static int  cl_block(ZState* zs);
static void cl_hash (ZState* zs, count_int cl_hsize);
static int  output  (ZState* zs, code_int ocode);
static code_int getcode(ZState* zs);
char* endptr = null;
// ------------------------------ Writer API ----------------------------------

// Return size_t to match compress.d; on error, set errno and return 0.
extern(C) size_t compress_zwrite(void* cookie, const void* wbp, size_t num)
{
  if (num == 0) return 0;
  auto zs = cast(ZState*)cookie;
  size_t count = num;
  auto bp = cast(const(char_type)*)wbp;

  if (zs.state == ZStateTag.S_MIDDLE) goto middle;
  zs.state = ZStateTag.S_MIDDLE;

  maxmaxcode(zs) = cast(code_int)1 << maxbits(zs);
  // write magic header
  if (fwrite(MAGIC.ptr, 1, MAGIC.length, fp(zs)) != MAGIC.length) {
    errno = EINVAL; return 0;
  }

  // third header byte: (maxbits | block_compress)
  char_type tmp = cast(char_type)((maxbits(zs)) | block_compress(zs));
  if (fwrite(&tmp, 1, 1, fp(zs)) != 1) { errno = EINVAL; return 0; }

  offset(zs)     = 0;
  bytes_out(zs)  = 3; // header bytes count
  out_count(zs)  = 0;
  clear_flg(zs)  = 0;
  ratio(zs)      = 0;
  in_count(zs)   = 1;
  checkpoint(zs) = CHECK_GAP;
  maxcode(zs)    = MAXCODE(n_bits(zs) = INIT_BITS);
  free_ent(zs)   = (block_compress(zs) != 0) ? FIRST : 256;

  ent(zs) = *bp++;
  --count;

  hshift(zs) = 0;
  for (fcode(zs) = cast(long)hsize(zs); fcode(zs) < 65536; fcode(zs) *= 2)
    hshift(zs)++;
  hshift(zs) = 8 - hshift(zs);

  hsize_reg(zs) = hsize(zs);
  cl_hash(zs, cast(count_int)hsize_reg(zs)); // clear hash

middle:
  for (code_int i = 0; count--; )
  {
    int c = *bp++;
    in_count(zs)++;
    fcode(zs) = ((cast(long)c) << maxbits(zs)) + ent(zs);
    i = ((c << hshift(zs)) ^ ent(zs)); // xor hashing

    if (htab(zs)[i] == fcode(zs)) {
      ent(zs) = codetab(zs)[i];
      continue;
    } else if (htab(zs)[i] < 0) {
      // empty slot
      goto nomatch;
    }
    int disp = cast(int)hsize_reg(zs) - cast(int)i;
    if (i == 0) disp = 1;
probe:
    if ((i -= disp) < 0) i += hsize_reg(zs);
    if (htab(zs)[i] == fcode(zs)) {
      ent(zs) = codetab(zs)[i];
      continue;
    }
    if (htab(zs)[i] >= 0) goto probe;

nomatch:
    if (output(zs, ent(zs)) == -1) { errno = EINVAL; return 0; }
    out_count(zs)++;
    ent(zs) = c;
    if (free_ent(zs) < maxmaxcode(zs)) {
      codetab(zs)[i] = cast(ushort)free_ent(zs)++;
      htab(zs)[i]    = fcode(zs);
    } else if (cast(count_int)in_count(zs) >= checkpoint(zs) && block_compress(zs)) {
      if (cl_block(zs) == -1) { errno = EINVAL; return 0; }
    }
  }
  return num;
}

extern(C) int compress_zclose(void* cookie)
{
  auto zs = cast(ZState*)cookie;
  if (zs is null) return 0;

  if (zs.zmode == 'w') {
    if (output(zs, ent(zs)) == -1) {
      fclose(fp(zs));
      free(zs);
      return -1;
    }
    out_count(zs)++;
    if (output(zs, cast(code_int)-1) == -1) {
      fclose(fp(zs));
      free(zs);
      return -1;
    }
  }

  auto rc = fclose(fp(zs));
  free(zs);
  return (rc != 0) ? -1 : 0;
}

// Pack and flush codes to file
static int output(ZState* zs, code_int ocode)
{
  int r_off = cast(int)offset(zs);
  uint bits = n_bits(zs);
  char_type* bp = &buf(zs)[0];

  if (ocode >= 0) {
    bp += (r_off >> 3);
    r_off &= 7;

    *bp = cast(char_type)((*bp & rmask[r_off]) | ((ocode << r_off) & lmask[r_off]));
    bp++;
    bits -= (8 - cast(uint)r_off);
    ocode >>= (8 - r_off);

    if (bits >= 8) {
      *bp++ = cast(char_type)ocode;
      ocode >>= 8;
      bits -= 8;
    }
    if (bits)
      *bp = cast(char_type)ocode;

    offset(zs) += n_bits(zs);

    if (offset(zs) == (n_bits(zs) << 3)) {
      bp   = &buf(zs)[0];
      bits = n_bits(zs);
      bytes_out(zs) += bits;
      if (fwrite(bp, 1, bits, fp(zs)) != bits)
        return -1;
      bp      += bits;
      bits     = 0;
      offset(zs) = 0;
    }

    if (free_ent(zs) > maxcode(zs) || (clear_flg(zs) > 0)) {
      if (offset(zs) > 0) {
        if (fwrite(&buf(zs)[0], 1, n_bits(zs), fp(zs)) != n_bits(zs))
          return -1;
        bytes_out(zs) += n_bits(zs);
      }
      offset(zs) = 0;

      if (clear_flg(zs) != 0) {
        maxcode(zs) = MAXCODE(n_bits(zs) = INIT_BITS);
        clear_flg(zs) = 0;
      } else {
        n_bits(zs)++;
        if (n_bits(zs) == maxbits(zs))
          maxcode(zs) = maxmaxcode(zs);
        else
          maxcode(zs) = MAXCODE(n_bits(zs));
      }
    }
  } else {
    // EOF: flush remainder
    if (offset(zs) > 0) {
      offset(zs) = (offset(zs) + 7) / 8;
      if (fwrite(&buf(zs)[0], 1, offset(zs), fp(zs)) != offset(zs))
        return -1;
      bytes_out(zs) += offset(zs);
    }
    offset(zs) = 0;
  }
  return 0;
}

// Clear-table logic (block compression)
static int cl_block(ZState* zs)
{
  long rat;
  checkpoint(zs) = in_count(zs) + CHECK_GAP;

  if (in_count(zs) > 0x007fffff) {
    rat = bytes_out(zs) >> 8;
    if (rat == 0) rat = 0x7fffffff;
    else          rat = in_count(zs) / rat;
  } else {
    rat = (in_count(zs) << 8) / bytes_out(zs);
  }

  if (rat > ratio(zs)) {
    ratio(zs) = rat;
  } else {
    ratio(zs) = 0;
    cl_hash(zs, cast(count_int)hsize(zs));
    free_ent(zs) = FIRST;
    clear_flg(zs) = 1;
    if (output(zs, CLEAR) == -1) return -1;
  }
  return 0;
}

static void cl_hash(ZState* zs, count_int cl_hsize)
{
  // Clear htab with -1 values in chunks of 16 (like original)
  long m1 = -1;
  count_int* htab_p = &htab(zs)[0] + cl_hsize;
  long i = cl_hsize - 16;
  do {
    *(htab_p - 16) = m1; *(htab_p - 15) = m1; *(htab_p - 14) = m1; *(htab_p - 13) = m1;
    *(htab_p - 12) = m1; *(htab_p - 11) = m1; *(htab_p - 10) = m1; *(htab_p -  9) = m1;
    *(htab_p -  8) = m1; *(htab_p -  7) = m1; *(htab_p -  6) = m1; *(htab_p -  5) = m1;
    *(htab_p -  4) = m1; *(htab_p -  3) = m1; *(htab_p -  2) = m1; *(htab_p -  1) = m1;
    htab_p -= 16;
  } while ((i -= 16) >= 0);
  for (i += 16; i > 0; i--) *--htab_p = m1;
}

// ------------------------------ Reader API ----------------------------------

// Return size_t to match compress.d; on error, set errno and return 0.
extern(C) size_t compress_zread(void* cookie, void* rbp, size_t num)
{
  if (num == 0) return 0;
  auto zs = cast(ZState*)cookie;
  size_t count = num;
  auto bp = cast(char_type*)rbp;

  final switch (zs.state) {
    case ZStateTag.S_START: zs.state = ZStateTag.S_MIDDLE; break;
    case ZStateTag.S_MIDDLE: goto middle;
    case ZStateTag.S_EOF: goto eof;
  }

  // read & check header
  char_type[3] hdr;
  if (fread(hdr.ptr, 1, hdr.length, fp(zs)) != hdr.length ||
      memcmp(hdr.ptr, MAGIC.ptr, MAGIC.length) != 0) {
    errno = EINVAL;
    return 0;
  }
  maxbits(zs)        = hdr[2];
  block_compress(zs) = (maxbits(zs) & BLOCK_MASK);
  maxbits(zs)       &= BIT_MASK;
  maxmaxcode(zs)     = cast(code_int)1 << maxbits(zs);
  if (maxbits(zs) > BITS) { errno = EINVAL; return 0; }

  maxcode(zs) = MAXCODE(n_bits(zs) = INIT_BITS);
  for (code(zs) = 255; code(zs) >= 0; code(zs)--) {
    codetab(zs)[code(zs)] = 0; // prefix
    set_tab_suffix(zs, code(zs), cast(char_type)code(zs)); // suffix
  }
  free_ent(zs) = (block_compress(zs) != 0) ? FIRST : 256;

  finchar(zs) = oldcode(zs) = getcode(zs);
  if (oldcode(zs) == -1) return 0; // EOF early

  *bp++ = cast(char_type)finchar(zs);
  count--;
  stackp(zs) = de_stack(zs);

  while ((code(zs) = getcode(zs)) > -1) {
    if ((code(zs) == CLEAR) && block_compress(zs)) {
      for (code(zs) = 255; code(zs) >= 0; code(zs)--)
        codetab(zs)[code(zs)] = 0; // reset prefix
      clear_flg(zs) = 1;
      free_ent(zs)  = FIRST - 1;
      if ((code(zs) = getcode(zs)) == -1) break;
    }

    incode(zs) = code(zs);

    if (code(zs) >= free_ent(zs)) {
      *stackp(zs)++ = cast(char_type)finchar(zs);
      code(zs) = oldcode(zs);
    }

    while (code(zs) >= 256) {
      *stackp(zs)++ = get_tab_suffix(zs, code(zs));
      code(zs) = codetab(zs)[code(zs)];
    }
    *stackp(zs)++ = finchar(zs) = get_tab_suffix(zs, code(zs));

middle:
    do {
      if (count-- == 0) return num;
      *bp++ = *--stackp(zs);
    } while (stackp(zs) > de_stack(zs));

    if ((code(zs) = free_ent(zs)) < maxmaxcode(zs)) {
      codetab(zs)[code(zs)] = cast(ushort)oldcode(zs);
      set_tab_suffix(zs, code(zs), cast(char_type)finchar(zs));
      free_ent(zs) = code(zs) + 1;
    }
    oldcode(zs) = incode(zs);
  }

  zs.state = ZStateTag.S_EOF;
eof:
  return num - count;
}

static code_int getcode(ZState* zs)
{
  code_int gcode;
  int r_off, bits;
  auto bp = &gbuf(zs)[0];

  if (clear_flg(zs) > 0 || roffset(zs) >= size(zs) || free_ent(zs) > maxcode(zs)) {
    if (free_ent(zs) > maxcode(zs)) {
      n_bits(zs)++;
      if (n_bits(zs) == maxbits(zs))
        maxcode(zs) = maxmaxcode(zs);
      else
        maxcode(zs) = MAXCODE(n_bits(zs));
    }
    if (clear_flg(zs) > 0) {
      maxcode(zs) = MAXCODE(n_bits(zs) = INIT_BITS);
      clear_flg(zs) = 0;
    }
    size(zs) = cast(int)fread(gbuf(zs).ptr, 1, n_bits(zs), fp(zs));
    if (size(zs) <= 0) return -1;
    roffset(zs) = 0;
    size(zs)    = (size(zs) << 3) - (cast(int)n_bits(zs) - 1);
  }

  r_off = roffset(zs);
  bits  = cast(int)n_bits(zs);

  bp += (r_off >> 3);
  r_off &= 7;

  gcode  = (*bp++ >> r_off);
  bits  -= (8 - r_off);
  r_off  = 8 - r_off;

  if (bits >= 8) {
    gcode |= (*bp++ << r_off);
    r_off += 8;
    bits  -= 8;
  }
  gcode |= ((*bp) & rmask[bits]) << r_off;
  roffset(zs) += n_bits(zs);

  return gcode;
}

// ------------------------------ Open/Close ----------------------------------

extern(C) void* compress_zopen(const char* fname, const char* mode, int bits)
{
  if ((mode[0] != 'r' && mode[0] != 'w') || mode[1] != '\0' ||
      bits < 0 || bits > BITS) {
    errno = EINVAL;
    return null;
  }

  auto zs = cast(ZState*)calloc(1, ZState.sizeof);
  if (zs is null) return null;

  zs.zmode      = mode[0];
  maxbits(zs)   = bits ? cast(uint)bits : BITS;
  maxmaxcode(zs)= cast(code_int)1 << maxbits(zs);
  hsize(zs)     = HSIZE;
  free_ent(zs)  = 0;
  block_compress(zs) = BLOCK_MASK;
  clear_flg(zs) = 0;
  ratio(zs)     = 0;
  checkpoint(zs)= CHECK_GAP;
  in_count(zs)  = 1;
  out_count(zs) = 0;
  zs.state      = ZStateTag.S_START;
  roffset(zs)   = 0;
  size(zs)      = 0;

  fp(zs) = fopen(fname, mode);
  if (fp(zs) is null) {
    free(zs);
    return null;
  }
  return zs;
}
