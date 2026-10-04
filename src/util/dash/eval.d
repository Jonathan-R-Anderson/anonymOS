// dash evaluator: environments, application (partial, over-, tail calls), patterns, definitions,
// do blocks that run commands, and members (fields, type methods, user extensions).
module dash.eval;

import dash.rt;
import dash.value;
import dash.ast;
import dash.parser;
import dash.exec;

struct Env { Env* parent; Sym* keys; Value** vals; uint n, cap; }

// A global function built from equations (possibly entered over several statements).
struct FunDef { Sym name; uint arity; Vec!(Decl*) clauses; Sym extType; }
struct CtorInfo { Sym name; Sym type; uint arity; Sym[] fields; }
struct Method { Sym type; Sym name; uint arity; PrimFn fn; const(char)[] sig; const(char)[] doc; bool impure; }
struct FieldDoc { Sym type; Sym name; const(char)[] sig; const(char)[] doc; }

enum GF : ubyte { None = 0, User = 1, Lib = 2, Ext = 4, ShellVar = 8 }

__gshared Value** g_glob; __gshared ubyte* g_globFlags; __gshared size_t g_globCap;
__gshared FunDef** g_funDef;          // by symbol
__gshared const(char)[]* g_sigs;      // declared signature text, by symbol
__gshared const(char)[]* g_docs;      // library documentation, by symbol
__gshared CtorInfo** g_ctors;         // by constructor symbol
__gshared Vec!Method g_methods;
__gshared Vec!FieldDoc g_fieldDocs;
__gshared Vec!Sym g_typeNames;        // object types with members (for Type.<Tab>)
__gshared bool g_pure;                // completion: evaluate without effects
__gshared Sym g_lastDefined = uint.max;

@nogc nothrow:

private void traceEnv(void* p) {
    auto e = cast(Env*)p;
    if (e.parent) gcMark(e.parent);
    if (e.keys) gcMark(e.keys);
    if (e.vals) gcMark(e.vals);
}

void evalInit() {
    g_traceEnv = &traceEnv;
    g_ctorType = &ctorTypeOf;
    g_sigOf = &sigOfFunc;
    g_lookupVar = &lookupForCmd;
    g_evalText = &evalTextHook;
    g_setShellVar = &setShellVar;
    g_nameClass = &nameClass;
    foreach (n; ["Just", "Left", "Right"]) defCtor(intern(n), intern(n == "Just" ? "Maybe" : "Either"), 1, null);
    defCtor(S_Nothing, intern("Maybe"), 0, null);
}

// ── globals ─────────────────────────────────────────────────────────────────────────────────────
private void ensureGlob(Sym s) {
    if (s < g_globCap) return;
    size_t nc = g_globCap ? g_globCap : 1024;
    while (nc <= s) nc *= 2;
    g_glob = cast(Value**)realloc(g_glob, nc * (Value*).sizeof);
    g_globFlags = cast(ubyte*)realloc(g_globFlags, nc);
    g_funDef = cast(FunDef**)realloc(g_funDef, nc * (FunDef*).sizeof);
    g_sigs = cast(const(char)[]*)realloc(g_sigs, nc * (const(char)[]).sizeof);
    g_docs = cast(const(char)[]*)realloc(g_docs, nc * (const(char)[]).sizeof);
    g_ctors = cast(CtorInfo**)realloc(g_ctors, nc * (CtorInfo*).sizeof);
    foreach (k; g_globCap .. nc) { g_glob[k] = null; g_globFlags[k] = 0; g_funDef[k] = null; g_sigs[k] = null; g_docs[k] = null; g_ctors[k] = null; }
    g_globCap = nc;
}
Value* getGlobal(Sym s) { return s < g_globCap ? g_glob[s] : null; }
ubyte globalFlags(Sym s) { return s < g_globCap ? g_globFlags[s] : 0; }
void setGlobal(Sym s, Value* v, ubyte flags) { ensureGlob(s); g_glob[s] = v; g_globFlags[s] = flags; }
const(char)[] sigOf(Sym s) { return s < g_globCap ? g_sigs[s] : null; }
const(char)[] docOf(Sym s) { return s < g_globCap ? g_docs[s] : null; }

void defPrim(const(char)[] name, uint arity, PrimFn fn, const(char)[] sig, const(char)[] doc, void* ctx = null) {
    const s = intern(name);
    ensureGlob(s);
    auto v = mkPrim(name, arity, fn, ctx);
    g_glob[s] = v; g_globFlags[s] = GF.Lib; g_sigs[s] = sig; g_docs[s] = doc;
}
void defValue(const(char)[] name, Value* v, const(char)[] sig, const(char)[] doc) {
    const s = intern(name); ensureGlob(s);
    g_glob[s] = v; g_globFlags[s] = GF.Lib; g_sigs[s] = sig; g_docs[s] = doc;
}
void defMethod(const(char)[] type, const(char)[] name, uint arity, PrimFn fn, const(char)[] sig, const(char)[] doc, bool impure = false) {
    Method m; m.type = intern(type); m.name = intern(name); m.arity = arity; m.fn = fn; m.sig = sig; m.doc = doc; m.impure = impure;
    g_methods.push(m);
    addTypeName(m.type);
}
void defFieldDoc(const(char)[] type, const(char)[] name, const(char)[] sig, const(char)[] doc) {
    FieldDoc f; f.type = intern(type); f.name = intern(name); f.sig = sig; f.doc = doc;
    g_fieldDocs.push(f);
    addTypeName(f.type);
}
void addTypeName(Sym t) { foreach (x; g_typeNames[]) if (x == t) return; g_typeNames.push(t); }
Method* findMethod(Sym type, Sym name) {
    foreach (ref m; g_methods[]) if (m.type == type && m.name == name) return &m;
    return null;
}
void defCtor(Sym name, Sym type, uint arity, Sym[] fields) {
    ensureGlob(name);
    auto c = cast(CtorInfo*)calloc(1, CtorInfo.sizeof);
    c.name = name; c.type = type; c.arity = arity; c.fields = fields;
    g_ctors[name] = c;
}
private const(char)[] ctorTypeOf(Sym c) { return (c < g_globCap && g_ctors[c]) ? symName(g_ctors[c].type) : symName(c); }
private const(char)[] sigOfFunc(Value* v) {
    if (v.t != VT.Func) return null;
    const s = sigOf(v.name);
    return s;
}

// Mark every root: the globals and the constants.
void markRoots() {
    markConstants();
    foreach (k; 0 .. g_globCap) if (g_glob[k]) gcMark(g_glob[k]);
}
void collectIfNeeded(bool force = false) {
    if (!force && g_heapSinceGc < 8 * 1024 * 1024) return;
    markRoots();
    gcSweep();
}

// ── environments ────────────────────────────────────────────────────────────────────────────────
Env* newEnv(Env* parent) { auto e = cast(Env*)gcAlloc(Env.sizeof, Kind.Env); e.parent = parent; return e; }
void bind(Env* e, Sym k, Value* v) {
    if (e is null) { setGlobal(k, v, GF.User); return; }
    foreach (i; 0 .. e.n) if (e.keys[i] == k) { e.vals[i] = v; return; }
    if (e.n == e.cap) {
        const nc = e.cap ? e.cap * 2 : 4;
        auto nk = cast(Sym*)gcAlloc(nc * Sym.sizeof, Kind.Raw);
        auto nv = cast(Value**)gcAlloc(nc * (Value*).sizeof, Kind.Ptrs);
        if (e.n) { memcpy(nk, e.keys, e.n * Sym.sizeof); memcpy(nv, e.vals, e.n * (Value*).sizeof); }
        e.keys = nk; e.vals = nv; e.cap = nc;
    }
    e.keys[e.n] = k; e.vals[e.n] = v; ++e.n;
}
Value* lookup(Sym k, Env* e) {
    for (auto x = e; x; x = x.parent) foreach (i; 0 .. x.n) if (x.keys[i] == k) return x.vals[i];
    return getGlobal(k);
}
bool boundLocally(Sym k, Env* e) {
    for (auto x = e; x; x = x.parent) foreach (i; 0 .. x.n) if (x.keys[i] == k) return true;
    return false;
}

private Value* lookupForCmd(const(char)[] name, void* env) {
    const s = intern(name);
    auto e = cast(Env*)env;
    if (boundLocally(s, e)) return lookup(s, e);
    if (globalFlags(s) & (GF.User | GF.ShellVar)) return getGlobal(s);
    if (globalFlags(s) & GF.Lib) {                     // $cwd, $now: zero-argument library values
        auto v = getGlobal(s);
        if (v && v.t == VT.Func && v.fk == FK.Prim && v.arity == 0) return v.prim(null, v.ctx);
    }
    return null;
}
// A plain integer ("42", "-7"; no leading zeros) is kept as an Int, so bash arithmetic works --
// `n=$((n + 1))` -- while $n still expands to the same text.
private bool plainInt(const(char)[] v) {
    size_t k = (v.length && v[0] == '-') ? 1 : 0;
    if (k == v.length || v.length - k > 18) return false;
    if (v[k] == '0' && v.length - k > 1) return false;
    foreach (c; v[k .. $]) if (c < '0' || c > '9') return false;
    return true;
}
private void setShellVar(const(char)[] name, const(char)[] value) {
    const s = intern(name);
    if (plainInt(value)) { Buf b; b.put(value); setGlobal(s, mkInt(strtoll(b.cstr(), null, 10)), GF.ShellVar); b.dispose(); }
    else setGlobal(s, mkStr(value), GF.ShellVar);
    auto zn = cz(name);
    if (getenv(zn)) { auto zv = cz(value); setenv(zn, zv, 1); free(zv); }   // an exported variable stays in sync
    free(zn);
}

// First-word classification: 3 user-defined dash name, 2 command/shell builtin, 1 library name, 0 unknown.
int nameClass(const(char)[] name) {
    const s = intern(name);
    const f = globalFlags(s);
    if (f & GF.User) return 3;
    if (isShellBuiltin(name)) return 2;
    if (g_isDashCommand && g_isDashCommand(name)) return 2;
    if (commandExists(name)) return 2;
    if (f & (GF.Lib | GF.ShellVar)) return 1;
    return 0;
}
// $PATH lookups are cached per symbol (the PATH itself is part of the key).
private __gshared ubyte* g_pathCache; private __gshared size_t g_pathCacheCap; private __gshared uint g_pathGen;
private __gshared char[512] g_pathSeen = 0;
bool commandExists(const(char)[] name) {
    auto path = getenv("PATH");
    if (path && strcmp(path, g_pathSeen.ptr) != 0) {
        const l = strlen(path); if (l < g_pathSeen.length) { memcpy(g_pathSeen.ptr, path, l + 1); }
        if (g_pathCache) memset(g_pathCache, 0, g_pathCacheCap);
    }
    const s = intern(name);
    if (s >= g_pathCacheCap) {
        size_t nc = g_pathCacheCap ? g_pathCacheCap : 1024; while (nc <= s) nc *= 2;
        g_pathCache = cast(ubyte*)realloc(g_pathCache, nc); memset(g_pathCache + g_pathCacheCap, 0, nc - g_pathCacheCap);
        g_pathCacheCap = nc;
    }
    if (g_pathCache[s] == 0) { auto p = findInPath(name); g_pathCache[s] = p ? 2 : 1; free(p); }
    return g_pathCache[s] == 2;
}

// ── evaluation ──────────────────────────────────────────────────────────────────────────────────
Value* err(const(char)[] a, const(char)[] b = null, const(char)[] c = null, const(char)[] d = null,
           const(char)[] e = null, const(char)[] f = null) { setErr(a, b, c, d, e, f); return null; }

Value* evalConst(Node* n) {
    switch (n.k) {
        case NK.Int: return mkInt(n.i);
        case NK.Float: return mkFloat(n.f);
        case NK.Str: return mkStr(n.s);
        case NK.Char: return mkChar(cast(char)n.i);
        case NK.Unit: return g_unit;
        default: return null;
    }
}

Value* conValue(Sym c) {
    if (c == S_True) return g_true;
    if (c == S_False) return g_false;
    auto ci = c < g_globCap ? g_ctors[c] : null;
    if (ci is null) return err("unknown constructor: ", symName(c));
    if (ci.arity == 0) return mkCtor(c, 0);
    auto f = mkPrim(symName(c), ci.arity, &ctorBuild, ci);
    return f;
}
private Value* ctorBuild(Value** a, void* ctx) {
    auto ci = cast(CtorInfo*)ctx;
    if (ci.fields.length) {                        // record syntax: an object of the data type
        auto o = mkObj(ci.type, ci.arity);
        foreach (k; 0 .. ci.arity) { o.keys[k] = ci.fields[k]; o.items[k] = a[k]; }
        return o;
    }
    auto v = mkCtor(ci.name, ci.arity);
    foreach (k; 0 .. ci.arity) v.items[k] = a[k];
    return v;
}

Value* eval(Node* n, Env* env) {
    for (;;) {
        if (g_interrupted) return err("interrupted");
        switch (n.k) {
            case NK.Int, NK.Float, NK.Str, NK.Char, NK.Unit: return evalConst(n);
            case NK.Var: {
                auto v = lookup(n.sym, env);
                // a zero-argument library value (domains, me, cwd, now...) is computed when used
                if (v && v.t == VT.Func && v.fk == FK.Prim && v.arity == 0) return v.prim(null, v.ctx);
                if (v is null) {
                    // an environment variable referenced as a name is not a dash binding: say so
                    return err("not in scope: ", symName(n.sym), commandExists(symName(n.sym)) ? " (it is a command -- run it at the start of a line, or use run \"...\")" : "");
                }
                return v;
            }
            case NK.Con: return conValue(n.sym);
            case NK.Lam: {
                auto v = newValue(VT.Func); v.fk = FK.Lambda; v.def = n; v.env = env;
                v.arity = cast(uint)n.pats.length; v.name = intern("lambda");
                return v;
            }
            case NK.App: {
                // lazy boolean operators
                if (n.a.k == NK.Var && n.kids.length == 2) {
                    const op = symName(n.a.sym);
                    if ((op == "&&" || op == "||") && !boundLocally(n.a.sym, env) && !(globalFlags(n.a.sym) & GF.User)) {
                        auto l = eval(n.kids[0], env); if (!l) return null;
                        if (l.t != VT.Bool) return err("'", op, "' needs Bools");
                        if (op == "&&" ? l.i == 0 : l.i != 0) return l;
                        n = n.kids[1]; continue;
                    }
                }
                auto f = eval(n.a, env); if (!f) return null;
                const na = n.kids.length;
                auto args = cast(Value**)gcAlloc(na * (Value*).sizeof, Kind.Ptrs);
                foreach (k; 0 .. na) { args[k] = eval(n.kids[k], env); if (!args[k]) return null; }
                // tail call into a user function with exactly the arguments it needs
                if (f.t == VT.Func && f.fk != FK.Prim && f.arity - f.n == na) {
                    Node* body; Env* benv;
                    if (!enter(f, args, na, body, benv)) return null;
                    n = body; env = benv; continue;
                }
                return apply(f, args, na);
            }
            case NK.Let: {
                auto e2 = newEnv(env);
                if (!bindDecls(n.decls, e2)) return null;
                n = n.a; env = e2; continue;
            }
            case NK.If: {
                auto c = eval(n.a, env); if (!c) return null;
                if (c.t != VT.Bool) return err("if: the condition is not a Bool");
                n = c.i ? n.b : n.c; continue;
            }
            case NK.Case: {
                auto v = eval(n.a, env); if (!v) return null;
                bool found = false;
                foreach (al; n.alts) {
                    auto e2 = newEnv(env);
                    if (!match(al.pat, v, e2)) { if (g_errSet) return null; continue; }
                    if (al.wheres.length && !bindDecls(al.wheres, e2)) return null;
                    if (al.guards.length) {
                        Node* chosen = null;
                        foreach (g; al.guards) {
                            auto c = eval(g.cond, e2); if (!c) return null;
                            if (truthy(c)) { chosen = g.body; break; }
                        }
                        if (chosen is null) continue;
                        n = chosen; env = e2; found = true; break;
                    }
                    n = al.body; env = e2; found = true; break;
                }
                if (!found) { Buf b; showValue(b, v); auto r = err("case: no alternative matches ", b.str()); b.dispose(); return r; }
                continue;
            }
            case NK.Do: {
                auto e2 = newEnv(env);
                const ns = n.stmts.length;
                if (ns == 0) return g_unit;
                foreach (k; 0 .. ns - 1) if (!execStmt(n.stmts[k], e2)) return null;
                auto last = n.stmts[ns - 1];
                if (last.k == SK.Expr) { n = last.e; env = e2; continue; }
                if (!execStmt(last, e2)) return null;
                return last.k == SK.Cmd ? g_unit : g_unit;
            }
            default: return evalOther(n, env);
        }
    }
}

private Value* evalOther(Node* n, Env* env) {
    switch (n.k) {
        case NK.List: {
            auto l = mkList(n.kids.length);
            foreach (k, c; n.kids) { l.items[k] = eval(c, env); if (!l.items[k]) return null; }
            return l;
        }
        case NK.Tuple: {
            auto t = mkTuple(n.kids.length);
            foreach (k, c; n.kids) { t.items[k] = eval(c, env); if (!t.items[k]) return null; }
            return t;
        }
        case NK.Range: return evalRange(n, env);
        case NK.Comp: { ListB lb; if (!comp(n, 0, env, lb)) return null; return lb.done(); }
        case NK.Rec: {
            auto r = mkRecord(n.keys.length);
            foreach (k; 0 .. n.keys.length) { r.keys[k] = n.keys[k]; r.items[k] = eval(n.kids[k], env); if (!r.items[k]) return null; }
            return r;
        }
        case NK.RecUpd: {
            if (n.a.k == NK.Con) {                                  // Ctor { f = e }: build a record-syntax value
                auto ci = n.a.sym < g_globCap ? g_ctors[n.a.sym] : null;
                if (ci is null || ci.fields.length == 0) return err(symName(n.a.sym), " has no named fields");
                auto o = mkObj(ci.type, ci.fields.length);
                foreach (k, fname; ci.fields) { o.keys[k] = fname; o.items[k] = g_unit; }
                foreach (k; 0 .. n.keys.length) {
                    auto v = eval(n.kids[k], env); if (!v) return null;
                    bool ok = false;
                    foreach (j; 0 .. o.n) if (o.keys[j] == n.keys[k]) { o.items[j] = v; ok = true; }
                    if (!ok) return err(symName(n.a.sym), " has no field ", symName(n.keys[k]));
                }
                return o;
            }
            auto r = eval(n.a, env); if (!r) return null;
            if (r.t != VT.Record && r.t != VT.Obj) return err("record update of a value that is not a record");
            foreach (k; 0 .. n.keys.length) {
                auto v = eval(n.kids[k], env); if (!v) return null;
                r = withField(r, n.keys[k], v);
            }
            return r;
        }
        case NK.Field: {
            auto v = eval(n.a, env); if (!v) return null;
            return member(v, n.sym);
        }
        case NK.FieldSel: {
            auto f = mkPrim(symName(n.sym), 1, &fieldSelPrim, cast(void*)cast(size_t)n.sym);
            return f;
        }
        case NK.TypeMember: {
            auto f = mkPrim(symName(n.keys[0]), 1, &typeMemberPrim, cast(void*)n);
            return f;
        }
        case NK.OpFn: {
            auto v = lookup(n.sym, env);
            if (!v) return err("unknown operator ", symName(n.sym));
            return v;
        }
        case NK.SectionR: case NK.SectionL: {
            auto op = lookup(n.sym, env);
            if (!op) return err("unknown operator ", symName(n.sym));
            auto x = eval(n.a, env); if (!x) return null;
            if (n.k == NK.SectionL) { auto a = newItems(1); a[0] = x; return apply(op, a, 1); }
            auto f = mkPrim(symName(n.sym), 1, &sectionRPrim, null);
            // the context carries (op, x): keep both reachable through the applied-args slot
            f.arity = 3; f.n = 2; f.items = newItems(3); f.items[0] = op; f.items[1] = x;
            return f;
        }
        case NK.Neg: {
            auto v = eval(n.a, env); if (!v) return null;
            if (v.t == VT.Int) return mkInt(-v.i);
            if (v.t == VT.Float) return mkFloat(-v.f);
            return err("negation of a non-number");
        }
        case NK.Cmd: {
            if (g_pure) return err("(a command is not run while completing)");
            const st = runCommandText(n.s, env);
            if (g_errSet) return null;
            return st == 0 ? g_unit : g_unit;
        }
        case NK.CmdSub: {
            if (g_pure) return err("(a command is not run while completing)");
            Buf o; runCapture(n.s, env, o);
            auto l = linesToList(o.str()); o.dispose();
            return l;
        }
        default: return err("cannot evaluate this expression");
    }
}

private Value* fieldSelPrim(Value** a, void* ctx) { return member(a[0], cast(Sym)cast(size_t)ctx); }
private Value* typeMemberPrim(Value** a, void* ctx) { auto n = cast(Node*)ctx; return member(a[0], n.keys[0]); }
private Value* sectionRPrim(Value** a, void* ctx) {
    // a[0] = op, a[1] = right operand, a[2] = the argument:  (op x) y = y `op` x
    auto args = newItems(2); args[0] = a[2]; args[1] = a[1];
    return apply(a[0], args, 2);
}

Value* linesToList(const(char)[] s) {
    ListB lb; size_t st = 0;
    foreach (k; 0 .. s.length) if (s[k] == '\n') { lb.push(mkStr(s[st .. k])); st = k + 1; }
    if (st < s.length) lb.push(mkStr(s[st .. $]));
    return lb.done();
}

private Value* evalRange(Node* n, Env* env) {
    auto a = eval(n.a, env); if (!a) return null;
    auto c = eval(n.c, env); if (!c) return null;
    Value* b = null;
    if (n.b) { b = eval(n.b, env); if (!b) return null; }
    if (a.t == VT.Char && c.t == VT.Char) {
        const step = b ? b.i - a.i : 1;
        if (step == 0) return err("a range with step 0");
        ListB lb;
        for (long x = a.i; step > 0 ? x <= c.i : x >= c.i; x += step) lb.push(mkChar(cast(char)x));
        return lb.done();
    }
    if (a.t == VT.Float || c.t == VT.Float || (b && b.t == VT.Float)) {
        const x0 = numF(a), x1 = numF(c), st = b ? numF(b) - x0 : 1.0;
        if (st == 0) return err("a range with step 0");
        ListB lb;
        for (double x = x0; st > 0 ? x <= x1 + st / 2 : x >= x1 + st / 2; x += st) lb.push(mkFloat(x));
        return lb.done();
    }
    if (a.t != VT.Int || c.t != VT.Int || (b && b.t != VT.Int)) return err("a range needs numbers or characters");
    const step = b ? b.i - a.i : 1;
    if (step == 0) return err("a range with step 0");
    const count = step > 0 ? (c.i >= a.i ? (c.i - a.i) / step + 1 : 0) : (a.i >= c.i ? (a.i - c.i) / -step + 1 : 0);
    if (count > 50_000_000) return err("that range is too large to build");
    auto l = mkList(cast(size_t)count);
    long x = a.i;
    foreach (k; 0 .. cast(size_t)count) { l.items[k] = mkInt(x); x += step; }
    return l;
}

private bool comp(Node* n, size_t qi, Env* env, ref ListB lb) {
    if (qi == n.quals.length) { auto v = eval(n.a, env); if (!v) return false; lb.push(v); return true; }
    auto q = n.quals[qi];
    final switch (q.k) {
        case QK.Guard: {
            auto c = eval(q.e, env); if (!c) return false;
            if (!truthy(c)) return true;
            return comp(n, qi + 1, env, lb);
        }
        case QK.Let: {
            auto e2 = newEnv(env);
            if (!bindDecls(q.decls, e2)) return false;
            return comp(n, qi + 1, e2, lb);
        }
        case QK.Gen: {
            auto src = eval(q.e, env); if (!src) return false;
            auto xs = asList(src); if (!xs) return false;
            foreach (k; 0 .. xs.n) {
                auto e2 = newEnv(env);
                if (!match(q.pat, xs.items[k], e2)) { if (g_errSet) return false; continue; }
                if (!comp(n, qi + 1, e2, lb)) return false;
            }
            return true;
        }
    }
}

// Strings are lists of characters wherever a list is expected.
Value* asList(Value* v) {
    if (v.t == VT.List) return v;
    if (v.t == VT.Str) { auto l = mkList(v.n); foreach (k; 0 .. v.n) l.items[k] = mkChar(v.s[k]); return l; }
    return err("expected a list, got a value of type ", typeName(v));
}
const(char)[] typeName(Value* v) {
    Buf b; typeOf(b, v);
    auto r = permDup(b.str()); b.dispose();   // (small; error paths only)
    return r;
}

// ── statements inside do blocks ────────────────────────────────────────────────────────────────
bool execStmt(Stmt* st, Env* env) {
    final switch (st.k) {
        case SK.Let: return bindDecls(st.decls, env);
        case SK.Cmd: {
            if (g_pure) { setErr("(a command is not run while completing)"); return false; }
            runCommandText(st.e.s, env);
            return !g_errSet && !g_interrupted;
        }
        case SK.Expr: {
            auto v = eval(st.e, env);
            if (!v) return false;
            // a bare IO-ish value (a function awaiting no more arguments) is not run implicitly
            return true;
        }
        case SK.Bind: {
            Value* v;
            if (st.e.k == NK.Cmd) {
                if (g_pure) { setErr("(a command is not run while completing)"); return false; }
                Buf o; runCapture(st.e.s, env, o);
                v = linesToList(o.str()); o.dispose();
            } else { v = eval(st.e, env); if (!v) return false; }
            if (!match(st.pat, v, env)) { if (!g_errSet) setErr("pattern in '<-' does not match"); return false; }
            return true;
        }
    }
}

// ── application ─────────────────────────────────────────────────────────────────────────────────
// Bind a user function's parameters for a full call; returns the body to evaluate and its env.
bool enter(Value* f, Value** args, size_t na, out Node* body, out Env* benv) {
    // all arguments: the ones already applied, then these
    const total = f.n + na;
    Value** all;
    if (f.n) { all = newItems(total); memcpy(all, f.items, f.n * (Value*).sizeof); memcpy(all + f.n, args, na * (Value*).sizeof); }
    else all = args;
    if (f.fk == FK.Lambda) {
        auto lam = cast(Node*)f.def;
        auto e2 = newEnv(cast(Env*)f.env);
        foreach (k, p; lam.pats) {
            if (!match(p, all[k], e2)) { if (!g_errSet) setErr("lambda: argument does not match its pattern"); return false; }
        }
        body = lam.a; benv = e2;
        return true;
    }
    auto fd = cast(FunDef*)f.def;
    foreach (d; fd.clauses[]) {
        auto e2 = newEnv(cast(Env*)f.env);
        bool ok = true;
        foreach (k, p; d.params) {
            if (!match(p, all[k], e2)) { ok = false; break; }
        }
        if (g_errSet) return false;
        if (!ok) continue;
        if (d.rhs.wheres.length && !bindDecls(d.rhs.wheres, e2)) return false;
        if (d.rhs.guards.length) {
            foreach (g; d.rhs.guards) {
                auto c = eval(g.cond, e2); if (!c) return false;
                if (truthy(c)) { body = g.body; benv = e2; return true; }
            }
            continue;
        }
        body = d.rhs.body; benv = e2;
        return true;
    }
    Buf b;
    foreach (k; 0 .. total) { b.put(' '); if (k == 3) { b.put("..."); break; } showShort(b, all[k]); }
    setErr("no equation of ", symName(fd.name), " matches the arguments", b.str());
    b.dispose();
    return false;
}
private void showShort(ref Buf b, Value* v) {
    Buf t; showValue(t, v);
    b.put(t.n > 30 ? t.str()[0 .. 30] : t.str());
    if (t.n > 30) b.put("..");
    t.dispose();
}

Value* apply(Value* f, Value** args, size_t na) {
    while (na > 0) {
        if (f.t != VT.Func) {
            Buf b; typeOf(b, f);
            auto r = err("cannot apply a value of type ", b.str(), " to an argument");
            b.dispose(); return r;
        }
        const need = f.arity - f.n;
        if (na < need) {                                     // partial application
            auto p = newValue(VT.Func);
            *p = *f;
            p.items = newItems(f.n + na);
            if (f.n) memcpy(p.items, f.items, f.n * (Value*).sizeof);
            memcpy(p.items + f.n, args, na * (Value*).sizeof);
            p.n = cast(uint)(f.n + na);
            return p;
        }
        Value* r;
        if (f.fk == FK.Prim) {
            Value** all;
            if (f.n) { all = newItems(f.arity); memcpy(all, f.items, f.n * (Value*).sizeof); memcpy(all + f.n, args, need * (Value*).sizeof); }
            else all = args;
            r = f.prim(all, f.ctx);
        } else {
            Node* body; Env* benv;
            if (!enter(f, args, need, body, benv)) return null;
            r = eval(body, benv);
        }
        if (r is null) return null;
        args += need; na -= need;
        f = r;
    }
    return f;
}
Value* apply1(Value* f, Value* x) { auto a = newItems(1); a[0] = x; return apply(f, a, 1); }
Value* apply2(Value* f, Value* x, Value* y) { auto a = newItems(2); a[0] = x; a[1] = y; return apply(f, a, 2); }

// ── patterns ────────────────────────────────────────────────────────────────────────────────────
bool match(Pat* p, Value* v, Env* env) {
    final switch (p.k) {
        case PK.Wild: return true;
        case PK.Var: bind(env, p.sym, v); return true;
        case PK.As: bind(env, p.sym, v); return match(p.kids[0], v, env);
        case PK.Int: return (v.t == VT.Int && v.i == p.i) || (v.t == VT.Float && v.f == p.i);
        case PK.Float: return (v.t == VT.Float && v.f == p.f) || (v.t == VT.Int && v.i == p.f);
        case PK.Char: return v.t == VT.Char && v.i == p.i;
        case PK.Str: return v.t == VT.Str && v.n == p.s.length && memcmp(v.s, p.s.ptr, v.n) == 0;
        case PK.Unit: return v.t == VT.Unit;
        case PK.Con: {
            if (p.sym == S_True) return v.t == VT.Bool && v.i == 1;
            if (p.sym == S_False) return v.t == VT.Bool && v.i == 0;
            if (v.t == VT.Obj) {                           // a record-syntax constructor pattern
                auto ci = p.sym < g_globCap ? g_ctors[p.sym] : null;
                if (ci is null || ci.type != v.name) return false;
                foreach (k, sp; p.kids) { if (k >= ci.fields.length) return false; auto fv = field(v, ci.fields[k]); if (!fv || !match(sp, fv, env)) return false; }
                return true;
            }
            if (v.t != VT.Ctor || v.name != p.sym) return false;
            if (p.kids.length != v.n) { setErr("constructor ", symName(p.sym), " has a different number of fields in this pattern"); return false; }
            foreach (k, sp; p.kids) if (!match(sp, v.items[k], env)) return false;
            return true;
        }
        case PK.Cons: {
            if (v.t == VT.Str) {
                if (v.n == 0) return false;
                return match(p.kids[0], mkChar(v.s[0]), env) && match(p.kids[1], mkStr(v.s[1 .. v.n]), env);
            }
            if (v.t != VT.List || v.n == 0) return false;
            if (!match(p.kids[0], v.items[0], env)) return false;
            auto rest = mkList(v.n - 1);
            if (v.n > 1) memcpy(rest.items, v.items + 1, (v.n - 1) * (Value*).sizeof);
            return match(p.kids[1], rest, env);
        }
        case PK.List: {
            if (v.t == VT.Str) {
                if (v.n != p.kids.length) return false;
                foreach (k, sp; p.kids) if (!match(sp, mkChar(v.s[k]), env)) return false;
                return true;
            }
            if (v.t != VT.List || v.n != p.kids.length) return false;
            foreach (k, sp; p.kids) if (!match(sp, v.items[k], env)) return false;
            return true;
        }
        case PK.Tuple: {
            if (v.t != VT.Tuple || v.n != p.kids.length) return false;
            foreach (k, sp; p.kids) if (!match(sp, v.items[k], env)) return false;
            return true;
        }
        case PK.Rec: {
            if (v.t != VT.Record && v.t != VT.Obj) return false;
            foreach (k, key; p.keys) { auto fv = member(v, key); if (!fv) { clearErr(); return false; } if (!match(p.kids[k], fv, env)) return false; }
            return true;
        }
    }
}

// ── definitions ─────────────────────────────────────────────────────────────────────────────────
// Bind a group of declarations into `env` (local) -- or into the globals when env is null.
bool bindDecls(Decl*[] ds, Env* env) {
    size_t k = 0;
    while (k < ds.length) {
        auto d = ds[k];
        final switch (d.k) {
            case DK.Sig: foreach (nm; d.names) { ensureGlob(nm); if (env is null) g_sigs[nm] = d.text; } ++k; break;
            case DK.Data: defineData(d); ++k; break;
            case DK.PatBind: {
                auto v = eval(d.rhs.body ? d.rhs.body : d.rhs.guards[0].body, env ? env : null); if (!v) return false;
                if (!match(d.pat, v, env ? env : null)) { if (!g_errSet) setErr("the pattern in a binding does not match"); return false; }
                ++k; break;
            }
            case DK.Ext: case DK.Fun: {
                // consecutive equations of the same name form one function
                size_t j = k + 1;
                while (j < ds.length && ds[j].k == d.k && ds[j].name == d.name && ds[j].type == d.type &&
                       ds[j].params.length == d.params.length) ++j;
                auto fd = cast(FunDef*)calloc(1, FunDef.sizeof);
                fd.name = d.k == DK.Ext ? extSym(d.type, d.name) : d.name;
                fd.arity = cast(uint)d.params.length;
                fd.extType = d.k == DK.Ext ? d.type : uint.max;
                foreach (q; k .. j) fd.clauses.push(ds[q]);
                if (fd.arity == 0 && d.k == DK.Fun) {
                    // a value definition: evaluate now (in its own scope, so it may refer to itself only if it is a function)
                    Node* body; Env* benv;
                    auto fv = mkFuncOf(fd, env);
                    if (!enter(fv, null, 0, body, benv)) return false;
                    auto v = eval(body, benv); if (!v) return false;
                    bind(env, d.name, v);
                } else {
                    bind(env, fd.name, mkFuncOf(fd, env));
                }
                k = j; break;
            }
        }
    }
    return true;
}
Value* mkFuncOf(FunDef* fd, Env* env) {
    auto v = newValue(VT.Func); v.fk = FK.Clauses; v.def = fd; v.env = env; v.arity = fd.arity; v.name = fd.name;
    return v;
}
Sym extSym(Sym type, Sym member) {
    Buf b; b.put(symName(type)); b.put('.'); b.put(symName(member));
    const s = intern(b.str()); b.dispose();
    return s;
}

// Top-level definitions: equations entered in successive statements extend the same function.
bool defineGlobal(Decl*[] ds) {
    foreach (d; ds) {
        if (d.k == DK.Fun || d.k == DK.Ext) {
            const name = d.k == DK.Ext ? extSym(d.type, d.name) : d.name;
            ensureGlob(name);
            auto fd = g_funDef[name];
            const extend = fd !is null && g_lastDefined == name && fd.arity == d.params.length && d.params.length > 0;
            if (!extend) {
                fd = cast(FunDef*)calloc(1, FunDef.sizeof);
                fd.name = name; fd.arity = cast(uint)d.params.length;
                fd.extType = d.k == DK.Ext ? d.type : uint.max;
                g_funDef[name] = fd;
            }
            fd.clauses.push(d);
            g_lastDefined = name;
            if (fd.arity == 0 && d.k == DK.Fun) {
                // a value: evaluated once, now
                auto fv = mkFuncOf(fd, null);
                Node* body; Env* benv;
                if (!enter(fv, null, 0, body, benv)) return false;
                auto v = eval(body, benv); if (!v) return false;
                setGlobal(name, v, GF.User);
            } else {
                setGlobal(name, mkFuncOf(fd, null), cast(ubyte)(GF.User | (d.k == DK.Ext ? GF.Ext : 0)));
                if (d.k == DK.Ext) addTypeName(d.type);
            }
        } else {
            g_lastDefined = uint.max;
            Decl*[1] one = [d];
            if (!bindDecls(one[], null)) return false;
        }
    }
    return true;
}
void defineData(Decl* d) {
    foreach (c; d.ctors) defCtor(c.name, d.name, c.arity, c.fields);
    ensureGlob(d.name);
    g_sigs[d.name] = d.text;
    if (d.ctors.length && d.ctors[0].fields.length) addTypeName(d.name);
}

// ── members: fields, type methods, extensions ───────────────────────────────────────────────────
// The type a value's members are looked up under.
Sym memberType(Value* v) {
    switch (v.t) {
        case VT.Obj: return v.name;
        case VT.Str: return intern("String");
        case VT.List: return intern("List");
        case VT.Int: return intern("Int");
        case VT.Float: return intern("Float");
        case VT.Bool: return intern("Bool");
        case VT.Char: return intern("Char");
        case VT.Record: return intern("Record");
        case VT.Tuple: return intern("Tuple");
        case VT.Ctor: { auto ci = v.name < g_globCap ? g_ctors[v.name] : null; return ci ? ci.type : v.name; }
        default: return intern("Function");
    }
}
Value* member(Value* v, Sym m) {
    if (v.t == VT.Record || v.t == VT.Obj) { auto f = field(v, m); if (f) return f; }
    const t = memberType(v);
    if (auto meth = findMethod(t, m)) return callMethod(meth, v);
    // strings and lists are also Lists / everything is Any
    if (v.t == VT.Str) { if (auto meth = findMethod(intern("List"), m)) return callMethod(meth, v); }
    // a user extension:  Type.member self ... = ...
    const es = extSym(t, m);
    auto ext = getGlobal(es);
    if (ext && ext.t == VT.Func) return ext.arity - ext.n == 1 ? apply1(ext, v) : apply1(ext, v);
    // a record-syntax data field
    Buf b; memberNames(v, b);
    auto r = err(symName(t), " has no member '", symName(m), b.n ? permDup(b.str()) : "' -- :m shows what it has");
    b.dispose();
    return r;
}
private Value* callMethod(Method* meth, Value* self) {
    if (g_pure && meth.impure) return err("(", symName(meth.name), " has effects: not run while completing)");
    if (meth.arity == 0) { auto a = newItems(1); a[0] = self; return meth.fn(a, null); }
    auto f = mkPrim(symName(meth.name), meth.arity + 1, meth.fn, null);
    f.items = newItems(meth.arity + 1); f.items[0] = self; f.n = 1;
    return f;
}
// "'; members: a, b, c" for error messages
void memberNames(Value* v, ref Buf b) {
    b.put("'; members: ");
    size_t cnt = 0;
    void add(const(char)[] s) { if (cnt < 24) { if (cnt) b.put(", "); b.put(s); } ++cnt; }
    if (v.t == VT.Record || v.t == VT.Obj) foreach (k; 0 .. v.n) add(symName(v.keys[k]));
    const t = memberType(v);
    foreach (ref m; g_methods[]) if (m.type == t) add(symName(m.name));
    if (cnt > 24) b.put(", ...");
}

// ── $(( expr )) inside a command ────────────────────────────────────────────────────────────────
private Value* evalTextHook(const(char)[] text, void* env) {
    Parser p;
    if (!p.init(text)) { p.dispose(); return null; }
    auto e = p.expr();
    if (e && !p.at(T_EOF())) { p.fail("unexpected text after the expression"); e = null; }
    p.dispose();
    if (!e) return null;
    return eval(e, cast(Env*)env);
}
import dash.lexer : T;
private T T_EOF() { return T.EOF; }
