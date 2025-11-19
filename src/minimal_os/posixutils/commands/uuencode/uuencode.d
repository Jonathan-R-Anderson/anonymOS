// uuencode.d — D translation of the provided C source
//
// Usage:
//   uuencode [-m|--base64] [file] decode_pathname
//
// - Traditional uuencode (default) uses the 64-char table from the original code,
//   emits "begin %03o <name>", length-char per line, '`' line, and "end".
// - Base64 (-m/--base64) emits "begin-base64 %03o <name>", 4-char padded blocks,
//   and ends with "====".
//
// Notes:
// - We keep a manual output buffer (4096 bytes) like the C code and flush to stdout.
// - We track the first column for traditional lines and fill the length char at line end.
// - LN_MAX = 45 source bytes per line (like the original).
//
// Build:
//   dmd -O -release uuencode.d -of=uuencode
//   # or: ldc2 -O3 -release uuencode.d -of=uuencode

import core.sys.posix.unistd : read, write, close, STDIN_FILENO;
import core.sys.posix.fcntl : open, O_RDONLY;
import core.sys.posix.sys.stat : fstat, stat_t, S_IRWXU, S_IRWXG, S_IRWXO,
                                 S_IRUSR, S_IWUSR, S_IRGRP, S_IROTH;
import core.stdc.string : memset, memcpy, strlen;
import core.stdc.stdio : snprintf;
import core.stdc.errno : errno;
import std.getopt : getopt;
import std.exception : enforce;
import std.string : toStringz;
import std.conv : to;
import std.stdio : stderr, writefln, writeln;
import std.algorithm : clamp;

enum UUE_BUF_SZ = 4096;
enum CHUNK_SZ   = 3;
enum LN_MAX     = 45;  // bytes of source per line
enum S_IXALL    = S_IRWXU | S_IRWXG | S_IRWXO;

__gshared ubyte[UUE_BUF_SZ] outbuf;
__gshared size_t outbufLen = 0;

// For traditional, we store the index of the first column of the current line.
// We set that byte to the encoded length at line end.
__gshared size_t lineStartIdx = size_t.max;

__gshared int lineLen   = 0; // encoded chars on the current output line (not counting leading len char)
__gshared int lineBytes = 0; // source bytes accumulated for this line

__gshared ubyte[4] spill;
__gshared int nSpill = 0;

__gshared bool optBase64 = false;
__gshared const(ubyte)* tbl;

immutable ubyte[64] TBL_BASE64 = [
    'A','B','C','D','E','F','G','H','I','J',
    'K','L','M','N','O','P','Q','R','S','T',
    'U','V','W','X','Y','Z','a','b','c','d',
    'e','f','g','h','i','j','k','l','m','n',
    'o','p','q','r','s','t','u','v','w','x',
    'y','z','0','1','2','3','4','5','6','7',
    '8','9','+','/'
];

immutable ubyte[64] TBL_TRAD = [
    '`',
    '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*',
    '+', ',', '-', '.', '/', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', ':', ';', '<', '=', '>',
    '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
    'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\',
    ']', '^', '_'
];

// write all to fd=1 (stdout), retry on partial
int writeAll(const(void)* p, size_t n) {
    auto ptr = cast(const(ubyte)*)p;
    size_t left = n;
    while (left > 0) {
        auto rc = write(1, ptr, left);
        if (rc < 0) return -1;
        ptr  += rc;
        left -= rc;
    }
    return 0;
}

void flushOutbuf() {
    if (outbufLen == 0) return;
    if (writeAll(outbuf.ptr, outbufLen) != 0) {
        // On write error, we abort similarly to C's perror() path (returning 1 upstream).
        // Here we just throw to unwind; main catches and returns non-zero.
        enforce(false, "write failed");
    }
    outbufLen = 0;
}

// Push into out buffer; flush if needed first. Returns starting index within buffer.
size_t pushOutbuf(const(void)* s, size_t len) {
    if (outbufLen + len > UUE_BUF_SZ) {
        flushOutbuf();
    }
    // If len itself exceeds UUE_BUF_SZ (won't happen here), we would write directly.
    memcpy(outbuf.ptr + outbufLen, s, len);
    auto start = outbufLen;
    outbufLen += len;
    return start;
}

// Push a single byte (small helper)
size_t pushByte(ubyte b) {
    return pushOutbuf(&b, 1);
}

void pushLine() {
    // For traditional mode, set the first byte of the line to the encoded length
    if (!optBase64 && lineStartIdx != size_t.max) {
        // length char encodes number of source bytes on the line
        outbuf[lineStartIdx] = TBL_TRAD[clamp(lineBytes, 0, LN_MAX)];
    }

    // newline
    immutable char nl = '\n';
    pushOutbuf(&nl, 1);

    // reset counters
    lineLen   = 0;
    lineBytes = 0;

    if (!optBase64) {
        // reserve a leading byte for length; fill at end
        lineStartIdx = pushByte(cast(ubyte)' ');
    } else {
        lineStartIdx = size_t.max;
    }
}

void encodeChunk(const(ubyte)* s) {
    int[4] ci;
    ubyte[4] c;

    // Split 3 bytes into four 6-bit chunks
    ci[0] = (s[0] >> 2) & 0x3f;
    ci[1] = (((s[0] << 4) & 0x3f) | ((s[1] >> 4) & 0x0f)) & 0x3f;
    ci[2] = (((s[1] << 2) & 0x3f) | ((s[2] >> 6) & 0x03)) & 0x3f;
    ci[3] =  s[2]        & 0x3f;

    foreach (i; 0 .. 4) c[i] = tbl[ci[i]];

    pushOutbuf(c.ptr, c.length);
    lineLen   += c.length;
    lineBytes += CHUNK_SZ;

    if (lineBytes >= LN_MAX) {
        pushLine();
    }
}

void finalizeBase64() {
    // Handle leftover (1 or 2 bytes) and pad with '='
    ubyte[4] c;
    c[0] = TBL_BASE64[ spill[0] >> 2 ];

    if (nSpill == 1) {
        c[1] = TBL_BASE64[ ( (spill[0] & 0x03) << 4 ) ];
        c[2] = '=';
        c[3] = '=';
    } else { // nSpill == 2
        c[1] = TBL_BASE64[ ( (spill[0] & 0x03) << 4 ) | (spill[1] >> 4) ];
        c[2] = TBL_BASE64[ ( (spill[1] & 0x0f) << 2 ) ];
        c[3] = '=';
    }

    pushOutbuf(c.ptr, c.length);
    lineLen   += cast(int)c.length;
    lineBytes += nSpill;
    nSpill     = 0;
}

void finalizeTraditional() {
    // Zero-pad spill to 3 bytes and encode one chunk
    ubyte[CHUNK_SZ] tmp;
    memset(tmp.ptr, 0, tmp.length);
    memcpy(tmp.ptr, spill.ptr, nSpill);
    encodeChunk(tmp.ptr);
    nSpill = 0;
}

void flushLastLine() {
    if (nSpill != 0) {
        if (optBase64) finalizeBase64();
        else           finalizeTraditional();
    }

    // Finish the current line
    pushLine();

    if (!optBase64) {
        // Traditional uuencode emits a line starting with '`' (zero-length)
        // The C code sets *line_start='`' then newline; here we just output "`\n".
        immutable ubyte[2] backtick = [cast(ubyte)'`', cast(ubyte)'\n'];
        pushOutbuf(backtick.ptr, backtick.length);
    }
}

void pushBytes(const(ubyte)* buf, size_t len) {
    auto s = buf;
    auto L = len;

    if (nSpill != 0) {
        while (nSpill < CHUNK_SZ && L > 0) {
            spill[nSpill] = *s;
            ++s; --L; ++nSpill;
        }
        if (nSpill < CHUNK_SZ) return;
        encodeChunk(spill.ptr);
        nSpill = 0;
    }

    while (L >= CHUNK_SZ) {
        encodeChunk(s);
        s += CHUNK_SZ;
        L -= CHUNK_SZ;
    }

    if (L > 0) {
        memcpy(spill.ptr, s, L);
        nSpill = cast(int)L;
    }
}

void doHeader(int fd, const(char)* fnString) {
    stat_t st;
    if (fstat(fd, &st) == 0) {
        st.st_mode &= S_IXALL;
    } else {
        st.st_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    }

    // "begin[-base64] %03o %s\n"
    char[4096] linebuf;
    if (optBase64) {
        auto n = snprintf(linebuf.ptr, linebuf.length, "begin-base64 %03o %s\n",
                          st.st_mode, fnString);
        pushOutbuf(linebuf.ptr, cast(size_t)n);
    } else {
        auto n = snprintf(linebuf.ptr, linebuf.length, "begin %03o %s\n",
                          st.st_mode, fnString);
        pushOutbuf(linebuf.ptr, cast(size_t)n);
    }
}

int doEncode(int fd, const(char)* fnString) {
    ubyte[UUE_BUF_SZ] inbuf;

    tbl = optBase64 ? TBL_BASE64.ptr : TBL_TRAD.ptr;

    doHeader(fd, fnString);

    // Initialize first line
    if (!optBase64) {
        lineStartIdx = pushByte(cast(ubyte)' ');
    } else {
        lineStartIdx = size_t.max;
    }
    lineLen   = 0;
    lineBytes = 0;
    nSpill    = 0;

    // Read/process
    while (true) {
        auto rc = read(fd, inbuf.ptr, inbuf.length);
        if (rc == 0) break;
        if (rc < 0) {
            // perror(fnString)-like
            stderr.writefln("%s: read failed (errno=%s)", fnString, errno);
            return 1;
        }
        pushBytes(inbuf.ptr, cast(size_t)rc);
    }

    // Finalize
    flushLastLine();

    if (optBase64) {
        immutable char[] tail = "====\n";
        pushOutbuf(tail.ptr, tail.length);
    } else {
        immutable char[] tail = "end\n";
        pushOutbuf(tail.ptr, tail.length);
    }

    flushOutbuf();
    return 0;
}

struct Cli {
    bool base64 = false;
    string inputFn; // optional
    string fnName;  // required (decode pathname)
}

Cli parseArgs(ref string[] args) {
    Cli cli;
    getopt(args,
        "m|base64", &cli.base64,
    );

    // Remaining: [file] decode_pathname
    // (exactly 1 or 2 positional args)
    enforce(args.length >= 2, "uuencode: invalid arguments");
    // args[0] is program name
    auto rem = args[1 .. $];
    enforce(rem.length == 1 || rem.length == 2, "uuencode: invalid arguments");

    if (rem.length == 1) {
        cli.fnName = rem[0];
    } else { // 2
        cli.inputFn = rem[0];
        cli.fnName  = rem[1];
    }

    return cli;
}

int main(string[] argv) {
    try {
        auto cli = parseArgs(argv);
        optBase64 = cli.base64;

        int fd;
        if (cli.inputFn.length) {
            fd = open(cli.inputFn.toStringz, O_RDONLY);
            if (fd < 0) {
                stderr.writefln("%s: open failed (errno=%s)", cli.inputFn, errno);
                return 1;
            }
        } else {
            fd = STDIN_FILENO;
        }

        scope(exit) {
            if (cli.inputFn.length) {
                // best-effort close
                close(fd);
            }
        }

        return doEncode(fd, cli.fnName.toStringz);
    } catch (Exception e) {
        stderr.writeln(e.msg);
        return 1;
    }
}
