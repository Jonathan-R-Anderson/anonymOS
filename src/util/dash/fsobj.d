// dash's object commands: ls, stat, find, cat, mkdir, rmdir, rm, cp, mv, touch, ps, kill, env -- run
// in the shell over the native object ABI (dash.native) and answering with dash values (File and
// Process objects, records), not text.  At the end of a statement the answer prints as a table; through
// `|>` it flows on as a value (`ls |> filter (.size > 1000)`); into an external command it becomes text
// (a File is its name).  A flag a command does not implement hands the line to the external program
// of the same name, so nothing typed stops working -- and `linux` is always there.
module dash.fsobj;

import dash.rt;
import dash.value;
import dash.eval;
import dash.native : dirList, NDirEnt, NStat, nstat;

@nogc nothrow:

// ── File objects ────────────────────────────────────────────────────────────────────────────────
private immutable char[16] g_typeCh = "?pc?d?b?-?l?s???";
private void modeText(ref Buf b, uint m) {
    b.put(g_typeCh[(m >> 12) & 0xF]);
    immutable char[3] rwx = "rwx";
    foreach (k; 0 .. 9) {
        const bit = 1u << (8 - k);
        char c = (m & bit) ? rwx[k % 3] : '-';
        if (k == 2 && (m & 0x800)) c = (m & bit) ? 's' : 'S';
        if (k == 5 && (m & 0x400)) c = (m & bit) ? 's' : 'S';
        if (k == 8 && (m & 0x200)) c = (m & bit) ? 't' : 'T';
        b.put(c);
    }
}
private const(char)[] kindOf(uint m) {
    switch (m & 0xF000) {
        case 0x4000: return "dir";  case 0x8000: return "file"; case 0xA000: return "link";
        case 0x2000: return "char"; case 0x6000: return "block"; case 0x1000: return "fifo";
        case 0xC000: return "socket"; default: return "other";
    }
}
// seconds since 1970 (UTC) -> "YYYY-MM-DD HH:MM"
private void dateText(ref Buf b, ulong secs) {
    long days = cast(long)(secs / 86400);
    const long rem = cast(long)(secs % 86400);
    days += 719468;
    const long era = days / 146097;
    const long doe = days - era * 146097;
    const long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    long y = yoe + era * 400;
    const long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const long mp = (5 * doy + 2) / 153;
    const long d = doy - (153 * mp + 2) / 5 + 1;
    const long m = mp < 10 ? mp + 3 : mp - 9;
    if (m <= 2) ++y;
    char[24] t;
    const n = snprintf(t.ptr, t.length, "%04ld-%02ld-%02ld %02ld:%02ld", y, m, d, rem / 3600, (rem % 3600) / 60);
    b.put(t[0 .. n]);
}
private __gshared Sym S_File;
// A File object: `shown` is the name it prints as (a listing's entry name, find's relative path).
Value* fileObj(const(char)[] path, const(char)[] shown, ref NStat st) {
    auto o = mkObj(S_File, 0);
    Buf mb; modeText(mb, st.mode); o = withField(o, intern("mode"), mkStr(mb.str())); mb.dispose();
    o = withField(o, intern("size"), mkInt(cast(long)st.size));
    Buf db; if (st.mtime) dateText(db, st.mtime); else db.put("-");   // a time the filesystem does not keep
    o = withField(o, intern("modified"), mkStr(db.str())); db.dispose();
    o = withField(o, intern("name"), mkStr(shown));
    o = withField(o, intern("kind"), mkStr(kindOf(st.mode)));
    o = withField(o, intern("path"), mkStr(path));
    o = withField(o, intern("owner"), mkInt(st.uid));
    o.t = VT.Obj; o.name = S_File;
    return o;
}
private const(char)[] joinPath(ref Buf b, const(char)[] dir, const(char)[] name) {
    b.clear(); b.put(dir);
    if (b.n && b.p[b.n - 1] != '/') b.put('/');
    b.put(name);
    return b.str();
}
// The entries of directory `dir` as File objects, sorted by name (dotfiles only with `all`).
private void listDir(const(char)[] dir, bool all, bool qualify, ref ListB lb) {
    auto z = cz(dir);
    size_t len;
    auto buf = dirList(z, len);
    free(z);
    if (buf is null) { setErr("ls: ", dir, ": ", strerror(*__errno_location())[0 .. strlen(strerror(*__errno_location()))]); return; }
    Vec!(Value*) items;
    Buf pb;
    for (size_t pos = 0; pos + NDirEnt.sizeof <= len; ) {
        auto e = cast(NDirEnt*)(buf + pos);
        auto name = (cast(char*)(buf + pos + NDirEnt.sizeof))[0 .. e.namelen];
        pos += e.reclen;
        if (!all && name.length && name[0] == '.') continue;
        const full = joinPath(pb, dir, name);
        items.push(fileObj(full, qualify ? full : name, e.st));
    }
    pb.dispose();
    free(buf);
    // insertion sort by name
    foreach (k; 1 .. items.n) {
        auto x = items.p[k]; size_t j = k;
        while (j > 0 && valCmp(fieldS(items.p[j - 1], "name"), fieldS(x, "name")) > 0) { items.p[j] = items.p[j - 1]; --j; }
        items.p[j] = x;
    }
    foreach (v; items[]) lb.push(v);
    items.dispose();
}
private extern (C) int* __errno_location();
private const(char)[] errText_() { auto e = strerror(*__errno_location()); return e[0 .. strlen(e)]; }

// ── the commands ────────────────────────────────────────────────────────────────────────────────
// Which names are object commands (the shell asks before running a command line).
bool isObjCommand(const(char)[] n) {
    switch (n) {
        case "ls", "stat", "find", "cat", "mkdir", "rmdir", "rm", "cp", "mv", "touch", "ps", "kill", "env": return true;
        default: return false;
    }
}
// Flags: every letter of every "-xyz" argument must be in `known`; otherwise the external program runs.
private bool flagsOk(const(char)[][] args, const(char)[] known, ref bool[128] on, out size_t firstArg) {
    on[] = false;
    size_t k = 0;
    for (; k < args.length; ++k) {
        const a = args[k];
        if (a == "--") { ++k; break; }
        if (a.length < 2 || a[0] != '-') break;
        foreach (c; a[1 .. $]) {
            bool ok = false; foreach (kc; known) if (kc == c) ok = true;
            if (!ok || c >= 128) return false;
            on[c] = true;
        }
    }
    firstArg = k;
    return true;
}

// Run object command argv[0] with arguments argv[1..].  handled = false: let the external program
// run instead (an unsupported flag, or a form only it has).  The result is null on an error (set).
Value* objCommand(const(char)[][] argv, out bool handled) {
    handled = false;
    if (argv.length == 0 || !isObjCommand(argv[0])) return null;
    const name = argv[0];
    auto args = argv[1 .. $];
    bool[128] on; size_t fa;
    switch (name) {
        case "ls": {
            if (!flagsOk(args, "aAld1hF", on, fa)) return null;
            handled = true;
            auto paths = args[fa .. $];
            ListB lb;
            if (paths.length == 0) { listDir(".", on['a'] || on['A'], false, lb); return g_errSet ? null : lb.done(); }
            foreach (p; paths) {
                NStat st;
                auto z = cz(p); const r = nstat(z, st); free(z);
                if (r < 0) { setErr("ls: ", p, ": ", errText_()); return null; }
                if ((st.mode & 0xF000) == 0x4000 && !on['d']) listDir(p, on['a'] || on['A'], paths.length > 1, lb);
                else lb.push(fileObj(p, p, st));
                if (g_errSet) return null;
            }
            return lb.done();
        }
        case "stat": {
            if (!flagsOk(args, "L", on, fa) || fa == args.length) return null;
            handled = true;
            ListB lb;
            foreach (p; args[fa .. $]) {
                NStat st; auto z = cz(p); const r = nstat(z, st, !on['L']); free(z);
                if (r < 0) { setErr("stat: ", p, ": ", errText_()); return null; }
                lb.push(fileObj(p, p, st));
            }
            auto l = lb.done();
            return l.n == 1 ? l.items[0] : l;
        }
        case "find": {
            // find [path...] [-name PAT] [-type f|d|l] [-maxdepth N]
            Vec!(const(char)[]) roots; const(char)[] pat; char type = 0; long maxd = long.max;
            size_t k = 0;
            while (k < args.length && args[k].length && args[k][0] != '-') roots.push(args[k++]);
            while (k < args.length) {
                const a = args[k];
                if (a == "-name" && k + 1 < args.length) { pat = args[k + 1]; k += 2; continue; }
                if (a == "-type" && k + 1 < args.length && args[k + 1].length == 1) { type = args[k + 1][0]; k += 2; continue; }
                if (a == "-maxdepth" && k + 1 < args.length) { Buf t; t.put(args[k + 1]); maxd = strtoll(t.cstr(), null, 10); t.dispose(); k += 2; continue; }
                roots.dispose(); return null;                 // anything else: the real find
            }
            handled = true;
            if (roots.n == 0) roots.push(".");
            ListB lb;
            foreach (rt; roots[]) findWalk(rt, 0, pat, type, maxd, lb);
            roots.dispose();
            return g_errSet ? null : lb.done();
        }
        case "cat": {
            if (args.length == 0) return null;               // stdin: the real cat
            foreach (a; args) if (a.length > 1 && a[0] == '-') return null;
            handled = true;
            Buf all;
            foreach (p; args) {
                auto v = readWholeFileQuiet(p);
                if (v is null) { setErr("cat: ", p, ": ", errText_()); all.dispose(); return null; }
                all.put(str(v));
            }
            auto r = mkStr(all.str()); all.dispose();
            return r;
        }
        case "mkdir": {
            if (!flagsOk(args, "p", on, fa) || fa == args.length) return null;
            handled = true;
            foreach (p; args[fa .. $]) if (!mkdirPath(p, on['p'])) return null;
            return g_unit;
        }
        case "rmdir": {
            if (!flagsOk(args, "", on, fa) || fa == args.length) return null;
            handled = true;
            foreach (p; args[fa .. $]) { auto z = cz(p); const r = rmdir(z); free(z); if (r < 0) { setErr("rmdir: ", p, ": ", errText_()); return null; } }
            return g_unit;
        }
        case "rm": {
            if (!flagsOk(args, "rRfdv", on, fa) || fa == args.length) return null;
            handled = true;
            foreach (p; args[fa .. $]) if (!removePath(p, on['r'] || on['R'], on['f'])) return null;
            return g_unit;
        }
        case "cp": {
            if (!flagsOk(args, "rRapv", on, fa) || args.length - fa < 2) return null;
            handled = true;
            auto srcs = args[fa .. $ - 1];
            const dst = args[$ - 1];
            NStat dst_; auto zd = cz(dst); const dstDir = nstat(zd, dst_) == 0 && (dst_.mode & 0xF000) == 0x4000; free(zd);
            if (srcs.length > 1 && !dstDir) { setErr("cp: ", dst, ": not a directory"); return null; }
            Buf tb;
            foreach (s_; srcs) {
                const target = dstDir ? joinPath(tb, dst, baseName(s_)) : dst;
                if (!copyPath(s_, target, on['r'] || on['R'] || on['a'])) { tb.dispose(); return null; }
            }
            tb.dispose();
            return g_unit;
        }
        case "mv": {
            if (!flagsOk(args, "fv", on, fa) || args.length - fa < 2) return null;
            handled = true;
            auto srcs = args[fa .. $ - 1];
            const dst = args[$ - 1];
            NStat dst_; auto zd = cz(dst); const dstDir = nstat(zd, dst_) == 0 && (dst_.mode & 0xF000) == 0x4000; free(zd);
            if (srcs.length > 1 && !dstDir) { setErr("mv: ", dst, ": not a directory"); return null; }
            Buf tb;
            foreach (s_; srcs) {
                const target = dstDir ? joinPath(tb, dst, baseName(s_)) : dst;
                auto za = cz(s_), zb = cz(target);
                int r = rename(za, zb);
                if (r < 0 && *__errno_location() == 18) {         // EXDEV: copy, then remove
                    r = (copyPath(s_, target, true) && removePath(s_, true, false)) ? 0 : -1;
                }
                free(za); free(zb);
                if (r < 0) { if (!g_errSet) setErr("mv: ", s_, ": ", errText_()); tb.dispose(); return null; }
            }
            tb.dispose();
            return g_unit;
        }
        case "touch": {
            if (!flagsOk(args, "c", on, fa) || fa == args.length) return null;
            handled = true;
            foreach (p; args[fa .. $]) {
                NStat st; auto z = cz(p);
                if (nstat(z, st) == 0 || on['c']) { free(z); continue; }
                const fd = open(z, O_WRONLY | O_CREAT, 0x1A4); free(z);
                if (fd < 0) { setErr("touch: ", p, ": ", errText_()); return null; }
                close(fd);
            }
            return g_unit;
        }
        case "ps": {
            handled = true;                                    // any flags: every process, as objects
            import dash.objects : procsList;
            return procsList();
        }
        case "kill": {
            int sig = 15; size_t k = 0;
            if (k < args.length && args[k].length > 1 && args[k][0] == '-') {
                const s_ = args[k][1 .. $];
                if (s_ == "l" || s_ == "L") return null;
                sig = signalNumber(s_);
                if (sig < 0) return null;
                ++k;
            }
            if (k == args.length) return null;
            handled = true;
            foreach (a; args[k .. $]) {
                Buf t; t.put(a); char* e; const pid = strtoll(t.cstr(), &e, 10); const ok = *e == 0; t.dispose();
                if (!ok) { setErr("kill: ", a, ": not a process id"); return null; }
                if (kill(cast(int)pid, sig) < 0) { setErr("kill: ", a, ": ", errText_()); return null; }
            }
            return g_unit;
        }
        case "env": {
            if (args.length != 0) return null;                 // env VAR=x cmd: the real env
            handled = true;
            ListB lb;
            for (auto e = environ; *e; ++e) {
                const t = (*e)[0 .. strlen(*e)];
                size_t eq = t.length; foreach (q, c; t) if (c == '=') { eq = q; break; }
                auto r = mkRecord(0);
                r = withField(r, intern("name"), mkStr(t[0 .. eq]));
                r = withField(r, intern("value"), mkStr(eq < t.length ? t[eq + 1 .. $] : ""));
                lb.push(r);
            }
            return lb.done();
        }
        default: return null;
    }
}

private int signalNumber(const(char)[] s_) {
    if (s_.length && isDigit(s_[0])) { Buf t; t.put(s_); const n = strtoll(t.cstr(), null, 10); t.dispose(); return cast(int)n; }
    if (s_.length > 3 && s_[0 .. 3] == "SIG") s_ = s_[3 .. $];
    switch (s_) {
        case "HUP": return 1; case "INT": return 2; case "QUIT": return 3; case "KILL": return 9;
        case "USR1": return 10; case "USR2": return 12; case "PIPE": return 13; case "ALRM": return 14;
        case "TERM": return 15; case "CONT": return 18; case "STOP": return 19; case "TSTP": return 20;
        default: return -1;
    }
}
private const(char)[] baseName(const(char)[] p) {
    while (p.length > 1 && p[$ - 1] == '/') p = p[0 .. $ - 1];
    size_t k = p.length; while (k > 0 && p[k - 1] != '/') --k;
    return p[k .. $];
}
private Value* readWholeFileQuiet(const(char)[] path) {
    auto z = cz(path);
    const fd = open(z, O_RDONLY); free(z);
    if (fd < 0) return null;
    Buf b; char[8192] t;
    for (;;) { const r = read(fd, t.ptr, t.length); if (r <= 0) break; b.put(t[0 .. cast(size_t)r]); }
    close(fd);
    auto v = mkStr(b.str()); b.dispose();
    return v;
}
private bool mkdirPath(const(char)[] p, bool parents) {
    auto z = cz(p);
    scope (exit) free(z);
    if (mkdir(z, 0x1ED) == 0) return true;
    const e = *__errno_location();
    if (parents && e == 17) return true;                         // exists
    if (parents && e == 2) {
        const parent = p[0 .. p.length - baseName(p).length];
        if (parent.length && parent != p && mkdirPath(parent[0 .. parent.length > 1 && parent[$ - 1] == '/' ? parent.length - 1 : parent.length], true)
            && mkdir(z, 0x1ED) == 0) return true;
    }
    setErr("mkdir: ", p, ": ", errText_());
    return false;
}
private bool removePath(const(char)[] p, bool recursive, bool force) {
    NStat st; auto z = cz(p);
    scope (exit) free(z);
    if (nstat(z, st, true) < 0) {
        if (force) return true;
        setErr("rm: ", p, ": ", errText_()); return false;
    }
    if ((st.mode & 0xF000) == 0x4000) {
        if (!recursive) { setErr("rm: ", p, ": is a directory (rm -r removes it)"); return false; }
        size_t len; auto buf = dirList(z, len);
        if (buf) {
            Buf pb;
            for (size_t pos = 0; pos + NDirEnt.sizeof <= len; ) {
                auto e = cast(NDirEnt*)(buf + pos);
                auto name = (cast(char*)(buf + pos + NDirEnt.sizeof))[0 .. e.namelen];
                pos += e.reclen;
                Buf cb; joinPath(cb, p, name);
                const ok = removePath(cb.str(), true, force);
                cb.dispose();
                if (!ok) { free(buf); pb.dispose(); return false; }
            }
            pb.dispose(); free(buf);
        }
        if (rmdir(z) < 0) { setErr("rm: ", p, ": ", errText_()); return false; }
        return true;
    }
    if (unlink(z) < 0 && !force) { setErr("rm: ", p, ": ", errText_()); return false; }
    return true;
}
private bool copyFile(const(char)[] src, const(char)[] dst, uint mode) {
    auto zs = cz(src), zd = cz(dst);
    scope (exit) { free(zs); free(zd); }
    const in_ = open(zs, O_RDONLY);
    if (in_ < 0) { setErr("cp: ", src, ": ", errText_()); return false; }
    const out_ = open(zd, O_WRONLY | O_CREAT | O_TRUNC, mode & 0xFFF);
    if (out_ < 0) { close(in_); setErr("cp: ", dst, ": ", errText_()); return false; }
    char[16384] t;
    bool ok = true;
    for (;;) {
        const r = read(in_, t.ptr, t.length);
        if (r == 0) break;
        if (r < 0) { ok = false; break; }
        size_t o = 0;
        while (o < cast(size_t)r) { const w = write(out_, t.ptr + o, cast(size_t)r - o); if (w <= 0) { ok = false; break; } o += cast(size_t)w; }
        if (!ok) break;
    }
    close(in_); close(out_);
    if (!ok) setErr("cp: ", src, ": ", errText_());
    return ok;
}
private bool copyPath(const(char)[] src, const(char)[] dst, bool recursive) {
    NStat st; auto zs = cz(src); const r = nstat(zs, st);
    if (r < 0) { free(zs); setErr("cp: ", src, ": ", errText_()); return false; }
    if ((st.mode & 0xF000) != 0x4000) { free(zs); return copyFile(src, dst, st.mode); }
    if (!recursive) { free(zs); setErr("cp: ", src, ": is a directory (cp -r copies it)"); return false; }
    auto zd = cz(dst); mkdir(zd, st.mode & 0xFFF); free(zd);
    size_t len; auto buf = dirList(zs, len); free(zs);
    if (buf is null) return true;
    bool ok = true;
    for (size_t pos = 0; pos + NDirEnt.sizeof <= len && ok; ) {
        auto e = cast(NDirEnt*)(buf + pos);
        auto name = (cast(char*)(buf + pos + NDirEnt.sizeof))[0 .. e.namelen];
        pos += e.reclen;
        Buf sb, db; joinPath(sb, src, name); joinPath(db, dst, name);
        ok = copyPath(sb.str(), db.str(), true);
        sb.dispose(); db.dispose();
    }
    free(buf);
    return ok;
}
private void findWalk(const(char)[] path, long depth, const(char)[] pat, char type, long maxd, ref ListB lb) {
    NStat st; auto z = cz(path); const r = nstat(z, st, true);
    if (r < 0) { free(z); return; }
    bool want = true;
    if (pat.length) { auto zp = cz(pat), zn = cz(baseName(path)); want = fnmatch(zp, zn, 0) == 0; free(zp); free(zn); }
    if (type) {
        const k = st.mode & 0xF000;
        want = want && ((type == 'f' && k == 0x8000) || (type == 'd' && k == 0x4000) || (type == 'l' && k == 0xA000));
    }
    if (want) lb.push(fileObj(path, path, st));
    if ((st.mode & 0xF000) == 0x4000 && depth < maxd) {
        size_t len; auto buf = dirList(z, len);
        if (buf) {
            for (size_t pos = 0; pos + NDirEnt.sizeof <= len; ) {
                auto e = cast(NDirEnt*)(buf + pos);
                auto name = (cast(char*)(buf + pos + NDirEnt.sizeof))[0 .. e.namelen];
                pos += e.reclen;
                Buf cb; joinPath(cb, path, name);
                findWalk(cb.str(), depth + 1, pat, type, maxd, lb);
                cb.dispose();
            }
            free(buf);
        }
    }
    free(z);
}

// ── File methods and `file "path"` ──────────────────────────────────────────────────────────────
private const(char)[] pathOf(Value* f) { auto p = fieldS(f, "path"); return p ? str(p) : ""; }
private Value* f_read(Value** a, void* c) {
    auto v = readWholeFileQuiet(pathOf(a[0]));
    return v ? v : err("read: ", pathOf(a[0]), ": ", errText_());
}
private Value* f_lines(Value** a, void* c) {
    auto v = readWholeFileQuiet(pathOf(a[0]));
    return v ? linesToList(str(v)) : err("lines: ", pathOf(a[0]), ": ", errText_());
}
private Value* writeTo(Value* f, Value* text, bool append) {
    if (g_pure) return err("(write has effects)");
    Buf t; textOf(t, text);
    auto z = cz(pathOf(f));
    const fd = open(z, O_WRONLY | O_CREAT | (append ? O_APPEND : O_TRUNC), 0x1A4); free(z);
    if (fd < 0) { t.dispose(); return err("write: ", pathOf(f), ": ", errText_()); }
    size_t o = 0;
    while (o < t.n) { const w = write(fd, t.p + o, t.n - o); if (w <= 0) break; o += cast(size_t)w; }
    close(fd); t.dispose();
    return g_unit;
}
private Value* f_write(Value** a, void* c) { return writeTo(a[0], a[1], false); }
private Value* f_append(Value** a, void* c) { return writeTo(a[0], a[1], true); }
private Value* f_delete(Value** a, void* c) {
    if (g_pure) return err("(delete has effects)");
    return removePath(pathOf(a[0]), true, false) ? g_unit : null;
}
private Value* f_rename(Value** a, void* c) {
    if (g_pure) return err("(rename has effects)");
    Buf t; textOf(t, a[1]);
    auto za = cz(pathOf(a[0])), zb = cz(t.str());
    const r = rename(za, zb); free(za); free(zb);
    auto res = r == 0 ? g_unit : err("rename: ", t.str(), ": ", errText_());
    t.dispose();
    return res;
}
private Value* f_copy(Value** a, void* c) {
    if (g_pure) return err("(copy has effects)");
    Buf t; textOf(t, a[1]);
    const ok = copyPath(pathOf(a[0]), t.str(), true);
    t.dispose();
    return ok ? g_unit : null;
}
private Value* f_children(Value** a, void* c) {
    ListB lb; listDir(pathOf(a[0]), true, false, lb);
    return g_errSet ? null : lb.done();
}
private Value* f_parent(Value** a, void* c) {
    const p = pathOf(a[0]);
    const b = baseName(p);
    const(char)[] par = p.length > b.length ? p[0 .. p.length - b.length] : ".";
    while (par.length > 1 && par[$ - 1] == '/') par = par[0 .. $ - 1];
    NStat st; auto z = cz(par); const r = nstat(z, st); free(z);
    return r == 0 ? fileObj(par, par, st) : err("parent: ", par, ": ", errText_());
}
private Value* f_exists(Value** a, void* c) {
    NStat st; auto z = cz(pathOf(a[0])); const r = nstat(z, st, true); free(z);
    return mkBool(r == 0);
}
private Value* c_file(Value** a, void* c) {
    Buf t; textOf(t, a[0]);
    NStat st; auto z = cz(t.str()); const r = nstat(z, st, true); free(z);
    auto res = r == 0 ? fileObj(t.str(), t.str(), st) : err("file: ", t.str(), ": ", errText_());
    t.dispose();
    return res;
}

void fsobjInit() {
    S_File = intern("File");
    defPrim("file", 1, &c_file, "String -> File", "the file (or directory) at a path, as an object");
    defFieldDoc("File", "mode", "String", "type and permissions, as ls writes them");
    defFieldDoc("File", "size", "Int", "size in bytes");
    defFieldDoc("File", "modified", "String", "last modification (UTC)");
    defFieldDoc("File", "name", "String", "its name (find: its path from the search root)");
    defFieldDoc("File", "kind", "String", "file / dir / link / char / block / fifo / socket");
    defFieldDoc("File", "path", "String", "where it is");
    defFieldDoc("File", "owner", "Int", "owner's user id");
    defMethod("File", "read", 0, &f_read, "String", "its contents");
    defMethod("File", "lines", 0, &f_lines, "[String]", "its contents, line by line");
    defMethod("File", "write", 1, &f_write, "String -> ()", "replace its contents", true);
    defMethod("File", "append", 1, &f_append, "String -> ()", "add to its end", true);
    defMethod("File", "delete", 0, &f_delete, "()", "remove it (a directory with everything in it)", true);
    defMethod("File", "rename", 1, &f_rename, "String -> ()", "move it to a new path", true);
    defMethod("File", "copy", 1, &f_copy, "String -> ()", "copy it (a directory recursively)", true);
    defMethod("File", "children", 0, &f_children, "[File]", "a directory's entries");
    defMethod("File", "parent", 0, &f_parent, "File", "the directory it is in");
    defMethod("File", "exists", 0, &f_exists, "Bool", "is it still there");
}
