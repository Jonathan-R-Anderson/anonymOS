// dash values: one tagged struct for everything the language computes.
module dash.value;

import dash.rt;

enum VT : ubyte { Unit, Bool, Int, Float, Char, Str, List, Tuple, Record, Ctor, Func, Obj }
enum FK : ubyte { Clauses, Lambda, Prim }

// A primitive: receives exactly `arity` evaluated arguments.
alias PrimFn = Value* function(Value** args, void* ctx) @nogc nothrow;

struct Value {
    VT t;
    FK fk;
    uint n;              // Str: byte length; List/Tuple/Ctor/Record/Obj: element count; Func: args applied
    long i;              // Int / Bool / Char
    double f;            // Float
    char* s;             // Str bytes (Raw block)
    Value** items;       // List/Tuple/Ctor args/Record+Obj values; Func: applied args
    Sym* keys;           // Record/Obj field names (Raw block)
    Sym name;            // Ctor constructor / Obj type / Func name
    uint arity;          // Func
    void* def;           // Func: the definition AST (permanent) -- Clauses/Lambda
    void* env;           // Func: the closure environment (Env*)
    PrimFn prim;         // Func: a primitive
    void* ctx;           // Func: primitive context (permanent data)
}

@nogc nothrow:

private void traceValue(void* p) {
    auto v = cast(Value*)p;
    if (v.s) gcMark(v.s);
    if (v.items) gcMark(v.items);
    if (v.keys) gcMark(v.keys);
    if (v.env) gcMark(v.env);
}

__gshared Value* g_unit, g_true, g_false, g_nothing, g_emptyList;
__gshared Sym S_Just, S_Nothing, S_Left, S_Right, S_True, S_False;

void valueInit() {
    g_traceValue = &traceValue;
    g_unit = newValue(VT.Unit);
    g_true = newValue(VT.Bool); g_true.i = 1;
    g_false = newValue(VT.Bool);
    S_Just = intern("Just"); S_Nothing = intern("Nothing"); S_Left = intern("Left"); S_Right = intern("Right");
    S_True = intern("True"); S_False = intern("False");
    g_nothing = mkCtor(S_Nothing, 0);
    g_emptyList = mkList(0);
}
// The singletons are roots of every collection.
void markConstants() { gcMark(g_unit); gcMark(g_true); gcMark(g_false); gcMark(g_nothing); gcMark(g_emptyList); }

Value* newValue(VT t) { auto v = cast(Value*)gcAlloc(Value.sizeof, Kind.Value); v.t = t; return v; }
Value** newItems(size_t n) { return n ? cast(Value**)gcAlloc(n * (Value*).sizeof, Kind.Ptrs) : null; }

Value* mkInt(long x) { auto v = newValue(VT.Int); v.i = x; return v; }
Value* mkFloat(double x) { auto v = newValue(VT.Float); v.f = x; return v; }
Value* mkChar(char c) { auto v = newValue(VT.Char); v.i = cast(ubyte)c; return v; }
Value* mkBool(bool b) { return b ? g_true : g_false; }
Value* mkStr(const(char)[] s) {
    auto v = newValue(VT.Str);
    v.s = cast(char*)gcAlloc(s.length + 1, Kind.Raw);
    memcpy(v.s, s.ptr, s.length); v.s[s.length] = 0;
    v.n = cast(uint)s.length;
    return v;
}
Value* mkStrZ(const(char)* z) { return mkStr(z ? z[0 .. strlen(z)] : ""); }
Value* mkList(size_t n) { auto v = newValue(VT.List); v.n = cast(uint)n; v.items = newItems(n); return v; }
Value* mkTuple(size_t n) { auto v = newValue(VT.Tuple); v.n = cast(uint)n; v.items = newItems(n); return v; }
Value* mkCtor(Sym name, size_t n) { auto v = newValue(VT.Ctor); v.name = name; v.n = cast(uint)n; v.items = newItems(n); return v; }
Value* mkJust(Value* x) { auto v = mkCtor(S_Just, 1); v.items[0] = x; return v; }
Value* mkRecord(size_t n) {
    auto v = newValue(VT.Record); v.n = cast(uint)n; v.items = newItems(n);
    v.keys = n ? cast(Sym*)gcAlloc(n * Sym.sizeof, Kind.Raw) : null;
    return v;
}
Value* mkObj(Sym type, size_t n) { auto v = mkRecord(n); v.t = VT.Obj; v.name = type; return v; }
Value* mkPrim(const(char)[] name, uint arity, PrimFn fn, void* ctx = null) {
    auto v = newValue(VT.Func); v.fk = FK.Prim; v.arity = arity; v.prim = fn; v.ctx = ctx; v.name = intern(name);
    return v;
}
const(char)[] str(Value* v) { return v.t == VT.Str ? v.s[0 .. v.n] : ""; }

// Growable list builder (heap-backed, so values stay reachable only through the result).
struct ListB {
    @nogc nothrow:
    Value** p; size_t n, cap;
    void push(Value* v) {
        if (n == cap) {
            const nc = cap ? cap * 2 : 8;
            auto np = newItems(nc);
            if (n) memcpy(np, p, n * (Value*).sizeof);
            p = np; cap = nc;
        }
        p[n++] = v;
    }
    Value* done() { auto l = mkList(n); if (n) memcpy(l.items, p, n * (Value*).sizeof); return l; }
}

// Record field lookup.
Value* field(Value* r, Sym k) {
    if (r.t != VT.Record && r.t != VT.Obj) return null;
    foreach (i; 0 .. r.n) if (r.keys[i] == k) return r.items[i];
    return null;
}
Value* fieldS(Value* r, const(char)[] k) { return field(r, intern(k)); }
// Record with one field replaced/added (records are immutable).
Value* withField(Value* r, Sym k, Value* v) {
    size_t at = r.n;
    foreach (i; 0 .. r.n) if (r.keys[i] == k) at = i;
    auto nr = mkRecord(at == r.n ? r.n + 1 : r.n);
    nr.t = r.t; nr.name = r.name;
    foreach (i; 0 .. r.n) { nr.keys[i] = r.keys[i]; nr.items[i] = r.items[i]; }
    nr.keys[at] = k; nr.items[at] = v;
    return nr;
}

bool truthy(Value* v) { return v.t == VT.Bool ? v.i != 0 : v.t != VT.Unit; }
bool isStrLike(Value* v) { return v.t == VT.Str; }

// ── equality and ordering ─────────────────────────────────────────────────────────────────────
bool valEq(Value* a, Value* b) {
    if (a is b) return true;
    if ((a.t == VT.Int || a.t == VT.Float) && (b.t == VT.Int || b.t == VT.Float)) return numF(a) == numF(b);
    if (a.t != b.t) return false;
    final switch (a.t) {
        case VT.Unit: return true;
        case VT.Bool: case VT.Int: case VT.Char: return a.i == b.i;
        case VT.Float: return a.f == b.f;
        case VT.Str: return a.n == b.n && memcmp(a.s, b.s, a.n) == 0;
        case VT.List: case VT.Tuple:
            if (a.n != b.n) return false;
            foreach (k; 0 .. a.n) if (!valEq(a.items[k], b.items[k])) return false;
            return true;
        case VT.Ctor:
            if (a.name != b.name || a.n != b.n) return false;
            foreach (k; 0 .. a.n) if (!valEq(a.items[k], b.items[k])) return false;
            return true;
        case VT.Record: case VT.Obj:
            if (a.name != b.name || a.n != b.n) return false;
            foreach (k; 0 .. a.n) { auto o = field(b, a.keys[k]); if (o is null || !valEq(a.items[k], o)) return false; }
            return true;
        case VT.Func: return false;
    }
}
double numF(Value* v) { return v.t == VT.Float ? v.f : cast(double)v.i; }
// -1 / 0 / 1; incomparable pairs order by type.
int valCmp(Value* a, Value* b) {
    if ((a.t == VT.Int || a.t == VT.Float) && (b.t == VT.Int || b.t == VT.Float)) {
        if (a.t == VT.Int && b.t == VT.Int) return a.i < b.i ? -1 : a.i > b.i;
        const x = numF(a), y = numF(b); return x < y ? -1 : x > y;
    }
    if (a.t != b.t) return a.t < b.t ? -1 : 1;
    switch (a.t) {
        case VT.Bool: case VT.Char: return a.i < b.i ? -1 : a.i > b.i;
        case VT.Str: {
            const m = a.n < b.n ? a.n : b.n;
            const c = memcmp(a.s, b.s, m);
            if (c) return c < 0 ? -1 : 1;
            return a.n < b.n ? -1 : a.n > b.n;
        }
        case VT.List: case VT.Tuple: {
            const m = a.n < b.n ? a.n : b.n;
            foreach (k; 0 .. m) { const c = valCmp(a.items[k], b.items[k]); if (c) return c; }
            return a.n < b.n ? -1 : a.n > b.n;
        }
        case VT.Ctor: {
            if (a.name != b.name) { const c = strcmpS(symName(a.name), symName(b.name)); return c; }
            foreach (k; 0 .. (a.n < b.n ? a.n : b.n)) { const c = valCmp(a.items[k], b.items[k]); if (c) return c; }
            return 0;
        }
        case VT.Record: case VT.Obj: {
            // objects/records order by their first field (usually the name)
            if (a.n && b.n) return valCmp(a.items[0], b.items[0]);
            return 0;
        }
        default: return 0;
    }
}
int strcmpS(const(char)[] a, const(char)[] b) {
    const m = a.length < b.length ? a.length : b.length;
    const c = memcmp(a.ptr, b.ptr, m);
    if (c) return c < 0 ? -1 : 1;
    return a.length < b.length ? -1 : a.length > b.length;
}

// ── show: the Haskell-style rendering (strings quoted) ─────────────────────────────────────────
void showValue(ref Buf b, Value* v, int depth = 0) {
    if (depth > 40) { b.put("..."); return; }
    final switch (v.t) {
        case VT.Unit: b.put("()"); break;
        case VT.Bool: b.put(v.i ? "True" : "False"); break;
        case VT.Int: b.puti(v.i); break;
        case VT.Float: showFloat(b, v.f); break;
        case VT.Char: b.put('\''); escChar(b, cast(char)v.i, '\''); b.put('\''); break;
        case VT.Str: b.put('"'); foreach (c; v.s[0 .. v.n]) escChar(b, c, '"'); b.put('"'); break;
        case VT.List: {
            bool chars = v.n > 0;
            foreach (k; 0 .. v.n) if (v.items[k].t != VT.Char) { chars = false; break; }
            if (chars) {                                   // a [Char] is a String
                b.put('"'); foreach (k; 0 .. v.n) escChar(b, cast(char)v.items[k].i, '"'); b.put('"'); break;
            }
            b.put('[');
            foreach (k; 0 .. v.n) { if (k) b.put(','); showValue(b, v.items[k], depth + 1); }
            b.put(']'); break;
        }
        case VT.Tuple:
            b.put('(');
            foreach (k; 0 .. v.n) { if (k) b.put(','); showValue(b, v.items[k], depth + 1); }
            b.put(')'); break;
        case VT.Ctor:
            b.put(symName(v.name));
            foreach (k; 0 .. v.n) {
                b.put(' ');
                auto a = v.items[k];
                const paren = (a.t == VT.Ctor && a.n) || (a.t == VT.Int && a.i < 0) || (a.t == VT.Float && a.f < 0);
                if (paren) b.put('(');
                showValue(b, a, depth + 1);
                if (paren) b.put(')');
            }
            break;
        case VT.Record: case VT.Obj:
            if (v.t == VT.Obj) { b.put(symName(v.name)); b.put(' '); }
            b.put("{");
            foreach (k; 0 .. v.n) {
                if (k) b.put(", ");
                b.put(symName(v.keys[k])); b.put(" = ");
                showValue(b, v.items[k], depth + 1);
            }
            b.put("}"); break;
        case VT.Func:
            b.put("<function ");
            b.put(symName(v.name));
            if (v.arity > v.n) { b.put('/'); b.puti(v.arity - v.n); }
            b.put('>'); break;
    }
}
void showFloat(ref Buf b, double d) {
    char[40] t;
    int k = snprintf(t.ptr, t.length, "%.15g", d);
    b.put(t[0 .. k]);
    bool dot = false;
    foreach (c; t[0 .. k]) if (c == '.' || c == 'e' || c == 'n' || c == 'i') dot = true;
    if (!dot) b.put(".0");
}
private void escChar(ref Buf b, char c, char q) {
    switch (c) {
        case '\n': b.put("\\n"); break;
        case '\t': b.put("\\t"); break;
        case '\r': b.put("\\r"); break;
        case '\\': b.put("\\\\"); break;
        default:
            if (c == q) { b.put('\\'); b.put(c); }
            else if (cast(ubyte)c < 32) { char[8] t; const n = snprintf(t.ptr, t.length, "\\%d", cast(int)c); b.put(t[0 .. n]); }
            else b.put(c);
    }
}

// ── text: what a value becomes when it meets the Unix world (a command argument, a pipe) ──────
void textOf(ref Buf b, Value* v) {
    switch (v.t) {
        case VT.Str: b.put(v.s[0 .. v.n]); break;
        case VT.Char: b.put(cast(char)v.i); break;
        case VT.Unit: break;
        default: showValue(b, v); break;
    }
}
// A value piped into a command: a list is one element per line.
void linesOf(ref Buf b, Value* v) {
    if (v.t == VT.List) {
        foreach (k; 0 .. v.n) { textOf(b, v.items[k]); b.put('\n'); }
    } else if (v.t != VT.Unit) { textOf(b, v); if (b.n == 0 || b.p[b.n - 1] != '\n') b.put('\n'); }
}

// ── the type of a value, as dash writes types ─────────────────────────────────────────────────
void typeOf(ref Buf b, Value* v, int depth = 0) {
    if (depth > 6) { b.put("a"); return; }
    final switch (v.t) {
        case VT.Unit: b.put("()"); break;
        case VT.Bool: b.put("Bool"); break;
        case VT.Int: b.put("Int"); break;
        case VT.Float: b.put("Float"); break;
        case VT.Char: b.put("Char"); break;
        case VT.Str: b.put("String"); break;
        case VT.List:
            b.put('[');
            if (v.n) typeOf(b, v.items[0], depth + 1); else b.put('a');
            b.put(']'); break;
        case VT.Tuple:
            b.put('(');
            foreach (k; 0 .. v.n) { if (k) b.put(", "); typeOf(b, v.items[k], depth + 1); }
            b.put(')'); break;
        case VT.Ctor:
            if (v.name == S_Just || v.name == S_Nothing) {
                b.put("Maybe ");
                if (v.n) { const par = v.items[0].t == VT.Ctor; if (par) b.put('('); typeOf(b, v.items[0], depth + 1); if (par) b.put(')'); }
                else b.put('a');
            } else if (v.name == S_Left || v.name == S_Right) b.put("Either a b");
            else b.put(ctorTypeName(v.name));
            break;
        case VT.Record:
            b.put("{");
            foreach (k; 0 .. v.n) { if (k) b.put(", "); b.put(symName(v.keys[k])); b.put(" :: "); typeOf(b, v.items[k], depth + 1); }
            b.put("}"); break;
        case VT.Obj: b.put(symName(v.name)); break;
        case VT.Func:
            if (v.def !is null && g_sigOf !is null) { auto sg = g_sigOf(v); if (sg.length) { b.put(sg); break; } }
            foreach (k; 0 .. (v.arity > v.n ? v.arity - v.n : 1)) b.put(k == 0 ? "a -> " : "_ -> ");
            b.put('b'); break;
    }
}
// Hooks filled in by the evaluator (user data types and declared signatures).
alias CtorTypeFn = const(char)[] function(Sym) @nogc nothrow;
alias SigFn = const(char)[] function(Value*) @nogc nothrow;
__gshared CtorTypeFn g_ctorType;
__gshared SigFn g_sigOf;
const(char)[] ctorTypeName(Sym c) { return g_ctorType ? g_ctorType(c) : symName(c); }
