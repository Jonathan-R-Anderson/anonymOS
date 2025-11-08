// tsort.d — D port of posixutils "tsort"
// Build (POSIX):
//   ldc2 -O -release -betterC tsort.d
//
// Run:
//   ./a.out [file]
// If no file is given, reads from stdin.
//
// Notes:
// - No Phobos or druntime features are used (betterC-safe).
// - Uses qsort + a recursive precedence check with a large guard like the C code.
// - Keeps linear dictionary search and simple dynamic-array growth like the original intent.

extern(C):
version (Posix) {} else static assert(0, "POSIX required.");

import core.stdc.config;
import core.stdc.stdlib : malloc, free, realloc, exit, EXIT_FAILURE, EXIT_SUCCESS, qsort;
import core.stdc.stdio  : fprintf, stderr, fopen, fclose, fgets, stdin, FILE, printf, perror;
import core.stdc.string : strlen, strcmp, memcmp, memcpy;
import core.stdc.ctype  : isspace;
import core.sys.posix.sys.types : size_t;
import core.sys.posix.sys.utsname : utsname; // (unused, kept for parity)
import core.sys.posix.limits : LINE_MAX;

// ------------------ Small portability helpers ------------------

@nogc nothrow
private char* my_strndup(const char* s, size_t n)
{
    auto p = cast(char*) malloc(n + 1);
    if (p is null) return null;
    if (n) memcpy(p, s, n);
    p[n] = 0;
    return p;
}

enum size_t LINEBUF_SZ =
    LINE_MAX > 0 ? (LINE_MAX + 1) : 4096; // Fallback if LINE_MAX not defined

// ------------------ Structures and dynamic arrays ------------------

struct Order {
    char* pred;
    char* succ;
}

__gshared:
char[LINEBUF_SZ] linebuf;
char* extra_token;

struct PtrVec {
    char** data;
    size_t len;
    size_t cap;
}

struct OrderVec {
    Order* data;
    size_t len;
    size_t cap;
}

PtrVec dict;     // vector<char*>
OrderVec order;  // vector<Order>

@nogc nothrow
private void reservePtrVec(ref PtrVec v, size_t need)
{
    if (v.cap >= need) return;
    size_t ncap = v.cap ? v.cap : 8;
    while (ncap < need) ncap *= 2;
    auto nd = cast(char**) realloc(v.data, ncap * (char*).sizeof);
    if (nd is null) {
        fprintf(stderr, "tsort: out of memory\n");
        exit(EXIT_FAILURE);
    }
    v.data = nd;
    v.cap  = ncap;
}

@nogc nothrow
private void pushPtrVec(ref PtrVec v, char* p)
{
    reservePtrVec(v, v.len + 1);
    v.data[v.len++] = p;
}

@nogc nothrow
private void reserveOrderVec(ref OrderVec v, size_t need)
{
    if (v.cap >= need) return;
    size_t ncap = v.cap ? v.cap : 8;
    while (ncap < need) ncap *= 2;
    auto nd = cast(Order*) realloc(v.data, ncap * Order.sizeof);
    if (nd is null) {
        fprintf(stderr, "tsort: out of memory\n");
        exit(EXIT_FAILURE);
    }
    v.data = nd;
    v.cap  = ncap;
}

@nogc nothrow
private void pushOrderVec(ref OrderVec v, Order o)
{
    reserveOrderVec(v, v.len + 1);
    v.data[v.len++] = o;
}

// ------------------ Core logic (ported) ------------------

@nogc nothrow
static char* add_token(const char* buf, size_t buflen, bool ok_add)
{
    // linear search in dict
    for (size_t i = 0; i < dict.len; ++i) {
        auto s = dict.data[i];
        auto slen = strlen(s);
        if (slen == buflen && memcmp(buf, s, slen) == 0)
            return s;
    }

    if (!ok_add) return null;

    // not found: add
    auto new_str = my_strndup(buf, buflen);
    if (new_str is null) return null;

    pushPtrVec(dict, new_str);
    return new_str;
}

@nogc nothrow
static void push_pair(char* a, char* b)
{
    Order o;
    o.pred = a;
    o.succ = b;
    pushOrderVec(order, o);
}

@nogc nothrow
static int push_token(const char* s, size_t slen)
{
    auto id = add_token(s, slen, true);
    if (id is null) return 1;

    if (extra_token is null) {
        extra_token = id;
    } else {
        push_pair(extra_token, id);
        extra_token = null;
    }
    return 0;
}

@nogc nothrow
static int process_line()
{
    auto p = &linebuf[0];

    while (*p) {
        // skip spaces
        while (*p && isspace(*p)) ++p;

        auto end = p;
        while (*end && !isspace(*end)) ++end;

        size_t mlen = cast(size_t)(end - p);
        if (mlen > 0) {
            if (push_token(p, mlen) != 0)
                return 1;
            p = end;
        } else if (*p) {
            ++p;
        }
    }
    return 0;
}

__gshared int max_recurse;

@nogc nothrow
static bool item_precedes(const char* a, const char* b)
{
    max_recurse--; // crude guard like original
    if (max_recurse <= 0) {
        fprintf(stderr, "tsort: max recursion limit reached\n");
        exit(1);
    }

    for (size_t i = 0; i < order.len; ++i) {
        auto o = order.data[i];
        if (o.pred != a) continue;
        if (o.succ == b) return true;
        if ((o.succ != a) && item_precedes(o.succ, b))
            return true;
    }
    return false;
}

extern(C) @nogc nothrow
static int compare_items(const void* _a, const void* _b)
{
    auto a = *cast(const(char*)*) _a;
    auto b = *cast(const(char*)*) _b;

    if (a == b) return 0;

    max_recurse = 4_000_000; // crude hack like C version
    if (item_precedes(a, b))
        return -1;
    return 1;
}

@nogc nothrow
static void sort_and_write_vals()
{
    // Build a temporary array of pointers
    auto n = dict.len;
    auto out_vals = cast(char**) malloc((n + 1) * (char*).sizeof);
    if (out_vals is null && n != 0) {
        fprintf(stderr, "tsort: out of memory\n");
        exit(EXIT_FAILURE);
    }
    for (size_t i = 0; i < n; ++i)
        out_vals[i] = dict.data[i];

    qsort(out_vals, n, (char*).sizeof, &compare_items);

    for (size_t i = 0; i < n; ++i)
        printf("%s\n", out_vals[i]);

    if (out_vals !is null) free(out_vals);
}

// ------------------ Main ------------------

int main(int argc, char** argv)
{
    // Simple CLI: zero or one positional filename, like your argp instance did.
    char* opt_filename = null;
    if (argc > 2) {
        fprintf(stderr, "tsort: too many arguments\n");
        return EXIT_FAILURE;
    }
    if (argc == 2)
        opt_filename = argv[1];

    FILE* f = null;
    if (opt_filename is null) {
        f = stdin;
    } else {
        f = fopen(opt_filename, "r");
        if (f is null) {
            perror(opt_filename);
            return EXIT_FAILURE;
        }
    }

    // Read lines
    while (fgets(linebuf.ptr, cast(int)linebuf.length, f) !is null) {
        if (process_line() != 0) {
            if (f !is stdin) fclose(f);
            return EXIT_FAILURE;
        }
    }

    if (f !is stdin) fclose(f);

    // If there was an odd dangling token, it’s a singleton—keep it in dict already.
    // Now sort & print
    sort_and_write_vals();

    return EXIT_SUCCESS;
}
