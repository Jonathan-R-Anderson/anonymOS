/+ 
  stty.d — D port of Red Hat posixutils stty (GPL-2.0)
  Notes:
    - Keeps original behavior: -a/-g, per-operand settings, compact form.
    - `stty_show()` and `param_cchar()` remain unimplemented (like the C).
    - Removes libpu.h dependencies; uses Phobos and core.sys.posix.*.
    - Uses cfget*/cfset* for speeds (instead of c_ispeed/c_ospeed fields).
+/
module stty;

version (Posix):

import std.stdio;
import std.string;
import std.algorithm;
import std.conv;
import std.exception;
import std.getopt;
import std.array;
import std.format : formattedRead; // for formattedRead!"%u"
import core.stdc.stdint;
import core.stdc.stdlib : exit;
import core.sys.posix.unistd;
import core.sys.posix.termios;
import core.sys.posix.sys.types;

// Some libcs don't expose OFDEL; make it optional.
static if (__traits(compiles, OFDEL)) {
    enum OFDEL_FLAG = OFDEL;
} else {
    enum OFDEL_FLAG = cast(tcflag_t)0;
}

enum COMPACT_PFX = "PUSTTY1:";

enum STTYParamType {
    cfl, ispeed, ospeed, ifl, ofl, lfl, cchar
}

struct SttyParam {
    string   name;
    STTYParamType ptype;
    tcflag_t val;       // value to set
    tcflag_t valClear;  // bits to clear first
}

// ---- Parameter table (mirrors the C table) ----
static immutable SttyParam[] params = [
    // control flags
    {"parenb", STTYParamType.cfl, PARENB, PARENB},
    {"parodd", STTYParamType.cfl, PARODD, PARODD},

    {"cs5", STTYParamType.cfl, CS5, CSIZE},
    {"cs6", STTYParamType.cfl, CS6, CSIZE},
    {"cs7", STTYParamType.cfl, CS7, CSIZE},
    {"cs8", STTYParamType.cfl, CS8, CSIZE},

    {"ispeed", STTYParamType.ispeed, 0, 0},
    {"ospeed", STTYParamType.ospeed, 0, 0},

    {"hupcl", STTYParamType.cfl, HUPCL, HUPCL},
    {"cstopb", STTYParamType.cfl, CSTOPB, CSTOPB},
    {"cread",  STTYParamType.cfl, CREAD,  CREAD},
    {"clocal", STTYParamType.cfl, CLOCAL, CLOCAL},

    // input flags
    {"ignbrk", STTYParamType.ifl, IGNBRK, IGNBRK},
    {"brkint", STTYParamType.ifl, BRKINT, BRKINT},
    {"ignpar", STTYParamType.ifl, IGNPAR, IGNPAR},
    {"parmrk", STTYParamType.ifl, PARMRK, PARMRK},
    {"inpck",  STTYParamType.ifl, INPCK,  INPCK},
    {"istrip", STTYParamType.ifl, ISTRIP, ISTRIP},
    {"inlcr",  STTYParamType.ifl, INLCR,  INLCR},
    {"igncr",  STTYParamType.ifl, IGNCR,  IGNCR},
    {"icrnl",  STTYParamType.ifl, ICRNL,  ICRNL},
    {"ixon",   STTYParamType.ifl, IXON,   IXON},
    {"ixany",  STTYParamType.ifl, IXANY,  IXANY},
    {"ixoff",  STTYParamType.ifl, IXOFF,  IXOFF},

    // output flags
    {"opost",  STTYParamType.ofl, OPOST,  OPOST},
    {"ocrnl",  STTYParamType.ofl, OCRNL,  OCRNL},
    {"onocr",  STTYParamType.ofl, ONOCR,  ONOCR},
    {"onlret", STTYParamType.ofl, ONLRET, ONLRET},
    {"ofill",  STTYParamType.ofl, OFILL,  OFILL},
    {"ofdel",  STTYParamType.ofl, OFDEL_FLAG, OFDEL_FLAG},

    {"cr0", STTYParamType.ofl, CR0, CRDLY},
    {"cr1", STTYParamType.ofl, CR1, CRDLY},
    {"cr2", STTYParamType.ofl, CR2, CRDLY},
    {"cr3", STTYParamType.ofl, CR3, CRDLY},

    {"nl0", STTYParamType.ofl, NL0, NLDLY},
    {"nl1", STTYParamType.ofl, NL1, NLDLY},

    {"tab0", STTYParamType.ofl, TAB0, TABDLY},
    {"tab1", STTYParamType.ofl, TAB1, TABDLY},
    {"tab2", STTYParamType.ofl, TAB2, TABDLY},
    {"tab3", STTYParamType.ofl, TAB3, TABDLY},

    {"bs0", STTYParamType.ofl, BS0, BSDLY},
    {"bs1", STTYParamType.ofl, BS1, BSDLY},

    {"ff0", STTYParamType.ofl, FF0, FFDLY},
    {"ff1", STTYParamType.ofl, FF1, FFDLY},

    {"vt0", STTYParamType.ofl, VT0, VTDLY},
    {"vt1", STTYParamType.ofl, VT1, VTDLY},

    // local modes
    {"isig",   STTYParamType.lfl, ISIG,   ISIG},
    {"icanon", STTYParamType.lfl, ICANON, ICANON},
    {"iexten", STTYParamType.lfl, IEXTEN, IEXTEN},
    {"echo",   STTYParamType.lfl, ECHO,   ECHO},
    {"echoe",  STTYParamType.lfl, ECHOE,  ECHOE},
    {"echok",  STTYParamType.lfl, ECHOK,  ECHOK},
    {"echonl", STTYParamType.lfl, ECHONL, ECHONL},
    {"noflsh", STTYParamType.lfl, NOFLSH, NOFLSH},
    {"tostop", STTYParamType.lfl, TOSTOP, TOSTOP},

    // control characters
    {"eof",   STTYParamType.cchar, VEOF,   0},
    {"eol",   STTYParamType.cchar, VEOL,   0},
    {"erase", STTYParamType.cchar, VERASE, 0},
    {"intr",  STTYParamType.cchar, VINTR,  0},
    {"kill",  STTYParamType.cchar, VKILL,  0},
    {"quit",  STTYParamType.cchar, VQUIT,  0},
    {"susp",  STTYParamType.cchar, VSUSP,  0},
    {"start", STTYParamType.cchar, VSTART, 0},
    {"stop",  STTYParamType.cchar, VSTOP,  0},
];

static termios ti;
static const(SttyParam)* lastParam = null;

// ---- helpers ----

int usage() {
    stderr.write(
        "stty [-a | -g]\n"
        ~ "    or\n"
        ~ "stty operands...\n"
    );
    return 1;
}

extern(C) void perror(const char*);

int sttyPushTi() {
    if (tcsetattr(STDIN_FILENO, TCSANOW, &ti) != 0) {
        perror("stty(tcsetattr)".ptr);
        return 1;
    }
    return 0;
}

// Not implemented (same as original C)
int sttyShow() {
    return 1;
}

uint speedToBits(uint speed) {
    // Return cfset* constant (B9600 etc.) or 0xFFFFFFFF on error
    switch (speed) {
        case 0:       return B0;
        case 50:      return B50;
        case 75:      return B75;
        case 110:     return B110;
        case 134:     return B134;
        case 150:     return B150;
        case 200:     return B200;
        case 300:     return B300;
        case 600:     return B600;
        case 1200:    return B1200;
        case 1800:    return B1800;
        case 2400:    return B2400;
        case 4800:    return B4800;
        case 9600:    return B9600;
        case 19200:   return B19200;
        case 38400:   return B38400;

        // Optional higher rates (guarded per-constant)
        static if (__traits(compiles, B57600))   { case 57600:   return B57600; }
        static if (__traits(compiles, B115200))  { case 115200:  return B115200; }
        static if (__traits(compiles, B230400))  { case 230400:  return B230400; }
        static if (__traits(compiles, B460800))  { case 460800:  return B460800; }
        static if (__traits(compiles, B500000))  { case 500000:  return B500000; }
        static if (__traits(compiles, B576000))  { case 576000:  return B576000; }
        static if (__traits(compiles, B921600))  { case 921600:  return B921600; }
        static if (__traits(compiles, B1000000)) { case 1000000: return B1000000; }
        static if (__traits(compiles, B1152000)) { case 1152000: return B1152000; }
        static if (__traits(compiles, B1500000)) { case 1500000: return B1500000; }
        static if (__traits(compiles, B2000000)) { case 2000000: return B2000000; }
        static if (__traits(compiles, B2500000)) { case 2500000: return B2500000; }
        static if (__traits(compiles, B3000000)) { case 3000000: return B3000000; }
        static if (__traits(compiles, B3500000)) { case 3500000: return B3500000; }
        static if (__traits(compiles, B4000000)) { case 4000000: return B4000000; }

        default:
            return 0xFFFF_FFFFu;
    }
}

int paramSpeed(uint speed, bool isInput) {
    const bits = speedToBits(speed);
    if (bits == 0xFFFF_FFFFu) return 1;
    auto rc = isInput ? cfsetispeed(&ti, bits) : cfsetospeed(&ti, bits);
    return rc < 0 ? 1 : 0;
}

// Display compact form (hex flags, decimal speeds/cc), matching intent
int sttyShowCompact() {
    // Use cfget* for speeds (portable)
    auto ispd = cfgetispeed(&ti);
    auto ospd = cfgetospeed(&ti);

    // Control chars we output (match C layout length 15 items after speeds)
    ubyte ccVEOF   = ti.c_cc[VEOF];
    ubyte ccVEOL   = ti.c_cc[VEOL];
    ubyte ccVERASE = ti.c_cc[VERASE];
    ubyte ccVINTR  = ti.c_cc[VINTR];
    ubyte ccVKILL  = ti.c_cc[VKILL];
    ubyte ccVQUIT  = ti.c_cc[VQUIT];
    ubyte ccVSUSP  = ti.c_cc[VSUSP];
    ubyte ccVSTART = ti.c_cc[VSTART];
    ubyte ccVSTOP  = ti.c_cc[VSTOP];

    // Print like: PUSTTY1:%x:%x:%x:%x:%u:%u:%u:...
    writefln("%s%x:%x:%x:%x:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u",
        COMPACT_PFX,
        cast(uint)ti.c_iflag,
        cast(uint)ti.c_oflag,
        cast(uint)ti.c_cflag,
        cast(uint)ti.c_lflag,
        cast(uint)ispd,
        cast(uint)ospd,
        cast(uint)ccVEOF,   // NOTE: original C had c_cc[VEOF] twice; we keep the same count (first two are VEOF and VEOL here)
        cast(uint)ccVEOL,
        cast(uint)ccVERASE,
        cast(uint)ccVINTR,
        cast(uint)ccVKILL,
        cast(uint)ccVQUIT,
        cast(uint)ccVSUSP,
        cast(uint)ccVSTART,
        cast(uint)ccVSTOP
    );
    return 0;
}

bool isCompactForm(string arg) {
    return arg.length >= COMPACT_PFX.length &&
           arg[0 .. COMPACT_PFX.length] == COMPACT_PFX;
}

// Accept the same compact line; parse fields split by ':'
int sttySetCompact(string settings) {
    // Strip prefix
    enforce(isCompactForm(settings), "invalid compact prefix");
    auto payload = settings[COMPACT_PFX.length .. $];

    auto parts = payload.split(':');
    // Expect 15 fields (flags 4, speeds 2, ccs 9) = 15
    if (parts.length != 15) {
        stderr.writeln("stty: invalid compact settings format");
        return 1;
    }

    // flags (hex)
    uint ifl = to!uint(parts[0], 16);
    uint ofl = to!uint(parts[1], 16);
    uint cfl = to!uint(parts[2], 16);
    uint lfl = to!uint(parts[3], 16);

    // speeds (decimal speed_t values as stored/returned by cfget*)
    uint ispd = to!uint(parts[4]);
    uint ospd = to!uint(parts[5]);

    // c_cc (decimal)
    ubyte ccVEOF   = cast(ubyte)to!uint(parts[6]);
    ubyte ccVEOL   = cast(ubyte)to!uint(parts[7]);
    ubyte ccVERASE = cast(ubyte)to!uint(parts[8]);
    ubyte ccVINTR  = cast(ubyte)to!uint(parts[9]);
    ubyte ccVKILL  = cast(ubyte)to!uint(parts[10]);
    ubyte ccVQUIT  = cast(ubyte)to!uint(parts[11]);
    ubyte ccVSUSP  = cast(ubyte)to!uint(parts[12]);
    ubyte ccVSTART = cast(ubyte)to!uint(parts[13]);
    ubyte ccVSTOP  = cast(ubyte)to!uint(parts[14]);

    ti.c_iflag = cast(tcflag_t)ifl;
    ti.c_oflag = cast(tcflag_t)ofl;
    ti.c_cflag = cast(tcflag_t)cfl;
    ti.c_lflag = cast(tcflag_t)lfl;

    // Set speeds using the numeric tokens directly (they are the Bxxxx codes)
    if (cfsetispeed(&ti, cast(speed_t)ispd) < 0) return 1;
    if (cfsetospeed(&ti, cast(speed_t)ospd) < 0) return 1;

    // Assign control chars
    ti.c_cc[VEOF]   = ccVEOF;
    ti.c_cc[VEOL]   = ccVEOL;
    ti.c_cc[VERASE] = ccVERASE;
    ti.c_cc[VINTR]  = ccVINTR;
    ti.c_cc[VKILL]  = ccVKILL;
    ti.c_cc[VQUIT]  = ccVQUIT;
    ti.c_cc[VSUSP]  = ccVSUSP;
    ti.c_cc[VSTART] = ccVSTART;
    ti.c_cc[VSTOP]  = ccVSTOP;

    return sttyPushTi();
}

int paramApply(ref termios t, in SttyParam param, string setting, bool setVal) {
    final switch (param.ptype) {
        case STTYParamType.cfl:
            t.c_cflag &= ~param.valClear;
            if (setVal) t.c_cflag |= param.val;
            break;
        case STTYParamType.ifl:
            t.c_iflag &= ~param.valClear;
            if (setVal) t.c_iflag |= param.val;
            break;
        case STTYParamType.ofl:
            t.c_oflag &= ~param.valClear;
            if (setVal) t.c_oflag |= param.val;
            break;
        case STTYParamType.lfl:
            t.c_lflag &= ~param.valClear;
            if (setVal) t.c_lflag |= param.val;
            break;

        case STTYParamType.ispeed:
        case STTYParamType.ospeed:
        case STTYParamType.cchar:
            lastParam = &param;
            return -1; // ask for next argument
    }
    return 0;
}

// Not implemented (same as original C)
int paramCChar(in SttyParam param, string setting) {
    // TODO: interpret caret notation (^C etc.) and set ti.c_cc[param.val]
    return 1;
}

int sttySet(string setting) {
    bool setVal = true;

    if (setting.length == 0) {
        stderr.writeln("stty: invalid empty argument");
        return 1;
    }

    if (lastParam !is null) {
        auto param = lastParam;
        lastParam = null;

        // Handle only the three "needs extra arg" cases; list all others to satisfy final switch
        final switch (param.ptype) {
            case STTYParamType.ispeed:
            {
                uint spd;
                if (setting.formattedRead!"%u"(spd) == 1)
                    return paramSpeed(spd, true);
                break;
            }
            case STTYParamType.ospeed:
            {
                uint spd;
                if (setting.formattedRead!"%u"(spd) == 1)
                    return paramSpeed(spd, false);
                break;
            }
            case STTYParamType.cchar:
                return paramCChar(*param, setting);

            // Explicitly listed (shouldn't occur here)
            case STTYParamType.cfl:
            case STTYParamType.ifl:
            case STTYParamType.ofl:
            case STTYParamType.lfl:
                break;
        }

        stderr.writeln("stty: invalid argument '", setting, "'");
        return 1;
    }

    if (setting[0] == '-') {
        setVal = false;
        setting = setting[1 .. $];
    }

    // Named parameter?
    foreach (ref p; params) {
        if (setting == p.name) {
            auto rc = paramApply(ti, p, setting, setVal);
            return rc;
        }
    }

    // Bare speed?
    {
        uint spd;
        if (setting.formattedRead!"%u"(spd) == 1) {
            if (paramSpeed(spd, true))  return 1;
            if (paramSpeed(spd, false)) return 1;
            return 0;
        }
    }

    stderr.writeln("stty: invalid argument '", setting, "'");
    return 1;
}

bool isHelpArg(string arg) {
    return arg == "-h" || arg == "--help" || arg == "-v" ||
           arg == "-V" || arg == "-H" || arg == "-?";
}

int main(string[] args) {
    // Help-only path
    if (args.length == 2 && isHelpArg(args[1]))
        return usage();

    if (tcgetattr(STDIN_FILENO, &ti) != 0) {
        perror("stty(tcgetattr)".ptr);
        return 1;
    }

    // No args → show (unimplemented stub)
    if (args.length == 1)
        return sttyShow();

    // Single arg options
    if (args.length == 2 && args[1] == "-a")
        return sttyShow();
    if (args.length == 2 && args[1] == "-g")
        return sttyShowCompact();
    if (args.length == 2 && isCompactForm(args[1]))
        return sttySetCompact(args[1]);

    // Process operands left to right; params that need an extra value return -1
    for (size_t i = 1; i < args.length; ++i) {
        auto rc = sttySet(args[i]);
        if (rc > 0) return rc;
        if (rc < 0) {
            ++i;
            rc = sttySet(i >= args.length ? "" : args[i]);
            if (rc != 0) return rc;
        }
    }

    return sttyPushTi();
}
