// tput.d — D port of posixutils "tput" (clear/init/reset)
// Build examples (link against terminfo/ncurses):
//   ldc2 -O -release tput.d -ltinfo
//   # or, depending on your system:
//   ldc2 -O -release tput.d -lncurses
//
// Without Phobos/GC:
//   ldc2 -O -release -betterC tput.d -ltinfo
//
// Usage (mirrors the C tool’s handled subcommands):
//   tput [-T type] clear
//   tput [-T type] init
//   tput [-T type] reset

extern(C):
version (Posix) {} else static assert(0, "POSIX required.");

import core.stdc.config;
import core.stdc.stdlib : exit, EXIT_FAILURE, EXIT_SUCCESS, system, getenv;
import core.stdc.stdio  : fprintf, stderr, fopen, fclose, getc, EOF, putchar;
import core.stdc.string : strcmp, strlen;
import core.stdc.errno  : errno;
import core.stdc.getopt : getopt, optarg, optind, opterr;
import core.sys.posix.unistd : write;
import core.sys.posix.sys.stat : stat_t, stat as c_stat;

// terminfo / curses APIs
extern(C) int setupterm(const(char)* term, int fildes, int* errret);
extern(C) int tputs(const(char)* str, int affcnt, int function (int));
extern(C) const(char)* tigetstr(const(char)* capname);
extern(C) int tigetnum(const(char)* capname);

enum PFX = "tput: ";
enum STDOUT_FILENO = 1;

__gshared char* optTerm;

//
// Helpers to work with terminfo safely
//
@nogc nothrow
static bool isValidStrCap(const(char)* p)
{
    // tigetstr returns (char*)-1 on error/canceled; 0 if missing.
    return p !is null && cast(size_t)p != cast(size_t)(-1);
}

extern(C) @nogc nothrow
static int putc_cb(int ch)
{
    return putchar(ch);
}

//
// tput clear
//
static void tput_clear()
{
    const(char)* clearCap = tigetstr("clear"); // same as clear_screen var
    if (!isValidStrCap(clearCap))
        return;

    int lines = tigetnum("lines");
    if (lines <= 0) lines = 1;
    tputs(clearCap, lines, &putc_cb);
}

//
// init/reset capability name lists
//
static __gshared const(char)* init_names[] = [
    "iprog",
    "is1",
    "is2",
    "if",
    "is3",
];

static __gshared const(char)* reset_names[] = [
    "rprog",
    "rs1",
    "rs2",
    "rf",
    "rs3",
];

//
// Emit init/reset sequences (mirrors your C logic):
//  - *prog: run via system()
//  - s1/s2/s3: write the string to stdout
//  - f (if/rf): interpret as filename; dump its contents to stdout
//
static void tput_reset(bool is_init)
{
    auto caps = is_init ? init_names : reset_names;

    // [0] *prog: run program
    const(char)* val = tigetstr(caps[0]);
    if (isValidStrCap(val))
        system(val);

    // [1] s1: write string
    val = tigetstr(caps[1]);
    if (isValidStrCap(val))
        write(STDOUT_FILENO, val, strlen(val));

    // [2] s2: write string
    val = tigetstr(caps[2]);
    if (isValidStrCap(val))
        write(STDOUT_FILENO, val, strlen(val));

    // [3] f: dump file contents if present
    val = tigetstr(caps[3]);
    if (isValidStrCap(val))
    {
        auto f = fopen(val, "r");
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

    // [4] s3: write string
    val = tigetstr(caps[4]);
    if (isValidStrCap(val))
        write(STDOUT_FILENO, val, strlen(val));
}

//
// Set up terminal based on -T or $TERM
//
static int pre_setup()
{
    int err = 0;
    const(char)* term = optTerm;
    // If not specified with -T, let setupterm read $TERM (pass null).
    if (setupterm(term, STDOUT_FILENO, &err) != 0)
    {
        fprintf(stderr, PFX ~ "setupterm failed\n");
        return 1;
    }
    return 0;
}

int main(int argc, char** argv)
{
    opterr = 0;
    optTerm = null;

    // Parse options (only -T type)
    for (;;)
    {
        int c = getopt(argc, argv, "T:");
        if (c == -1) break;
        final switch (c)
        {
        case 'T':
            optTerm = optarg;
            break;
        default:
            fprintf(stderr, PFX ~ "invalid option\n");
            return EXIT_FAILURE;
        }
    }

    // If no -T, try $TERM (setupterm with null uses env)
    if (optTerm is null)
    {
        // nothing needed; setupterm(NULL, ...) uses TERM
    }

    if (pre_setup() != 0)
        return EXIT_FAILURE;

    if (optind >= argc)
    {
        // No subcommand provided; do nothing (like minimal tput),
        // or you could print a small usage message.
        return EXIT_SUCCESS;
    }

    int rc = 0;
    for (int i = optind; i < argc; ++i)
    {
        auto cmd = argv[i];
        if (strcmp(cmd, "clear") == 0)
            tput_clear();
        else if (strcmp(cmd, "init") == 0)
            tput_reset(true);
        else if (strcmp(cmd, "reset") == 0)
            tput_reset(false);
        else
        {
            // Unrecognized token (original walker accepted only those three)
            // Silently ignore (to match minimal behavior), or set rc = 1.
            rc = 1;
        }
    }

    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
