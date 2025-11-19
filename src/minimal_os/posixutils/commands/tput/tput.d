// tput.d — minimal D port of posixutils "tput" (clear/init/reset)
// Build (link against terminfo/ncurses):
//   ldc2 -O2 -release tput.d -ltinfo
//   # or on some systems: -lncurses

version (Posix) {} else static assert(0, "POSIX required.");

import core.stdc.stdlib : EXIT_FAILURE, EXIT_SUCCESS, system;
import core.stdc.stdio  : fprintf, stderr, fopen, fclose, getc, EOF;
import core.stdc.string : strlen;
import core.sys.posix.unistd : write;
import std.string : toStringz, startsWith;

extern(C) {
    // terminfo APIs
    int setupterm(const(char)* term, int fildes, int* errret);
    const(char)* tigetstr(const(char)* capname);
    int tigetnum(const(char)* capname);
}

enum PFX = "tput: ";
enum STDOUT_FILENO = 1;

// tigetstr returns (char*)-1 on error, null if missing
static bool isValidStrCap(const(char)* p)
{
    return p !is null && p != cast(const(char)*)-1;
}

// Write a C string to stdout
static void writeCString(const(char)* s)
{
    if (s is null) return;
    auto n = strlen(s);
    if (n > 0) write(STDOUT_FILENO, s, n);
}

// tput clear
static void tput_clear()
{
    const(char)* clearCap = tigetstr(toStringz("clear"));
    if (!isValidStrCap(clearCap)) return;
    writeCString(clearCap);
}

// init/reset capability name lists (D-style arrays)
static __gshared string[] init_names = [
    "iprog", // program to run
    "is1",   // string 1
    "is2",   // string 2
    "if",    // file to cat
    "is3",   // string 3
];

static __gshared string[] reset_names = [
    "rprog", // program to run
    "rs1",   // string 1
    "rs2",   // string 2
    "rf",    // file to cat
    "rs3",   // string 3
];

// Emit init/reset sequences
static void tput_reset(bool is_init)
{
    auto caps = is_init ? init_names : reset_names;

    // [0] *prog: run program if present
    const(char)* v0 = tigetstr(toStringz(caps[0]));
    if (isValidStrCap(v0))
        system(v0);

    // [1] s1
    const(char)* v1 = tigetstr(toStringz(caps[1]));
    if (isValidStrCap(v1))
        writeCString(v1);

    // [2] s2
    const(char)* v2 = tigetstr(toStringz(caps[2]));
    if (isValidStrCap(v2))
        writeCString(v2);

    // [3] f: dump file contents
    const(char)* vf = tigetstr(toStringz(caps[3]));
    if (isValidStrCap(vf))
    {
        auto f = fopen(vf, "r");
        if (f !is null)
        {
            for (;;)
            {
                int ch = getc(f);
                if (ch == EOF) break;
                char c = cast(char) ch;
                write(STDOUT_FILENO, &c, 1);
            }
            fclose(f);
        }
    }

    // [4] s3
    const(char)* v3 = tigetstr(toStringz(caps[4]));
    if (isValidStrCap(v3))
        writeCString(v3);
}

// Set up terminal based on -T or $TERM
static int pre_setup(const(char)* termPtr)
{
    int err = 0;
    if (setupterm(termPtr, STDOUT_FILENO, &err) != 0)
    {
        fprintf(stderr, "%ssetupterm failed\n".ptr, PFX.ptr);
        return 1;
    }
    return 0;
}

int main(string[] args)
{
    // Parse args: supports -T xterm and -Txterm
    string termOpt;
    string[] cmds;

    size_t i = 1;
    while (i < args.length)
    {
        auto a = args[i];
        if (a == "-T")
        {
            if (i + 1 >= args.length) {
                fprintf(stderr, "%smissing argument to -T\n".ptr, PFX.ptr);
                return EXIT_FAILURE;
            }
            termOpt = args[i + 1];
            i += 2;
        }
        else if (a.startsWith("-T") && a.length > 2)
        {
            termOpt = a[2 .. $];
            ++i;
        }
        else
        {
            // remaining tokens are subcommands
            cmds = args[i .. $];
            break;
        }
    }

    const(char)* termPtr = termOpt.length ? toStringz(termOpt) : null;
    if (pre_setup(termPtr) != 0)
        return EXIT_FAILURE;

    if (cmds.length == 0)
        return EXIT_SUCCESS; // nothing to do

    int rc = 0;
    foreach (cmd; cmds)
    {
        if (cmd == "clear")
            tput_clear();
        else if (cmd == "init")
            tput_reset(true);
        else if (cmd == "reset")
            tput_reset(false);
        else
            rc = 1; // unknown token
    }

    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
