// dash standard library: a Prelude subset, strings, records, Maybe, and the shell's IO.
module dash.lib;

import dash.rt;
import dash.value;
import dash.eval;
import dash.exec;

@nogc nothrow:

private const(char)[] tn(Value* v) { Buf b; typeOf(b, v); auto r = permDup(b.str()); b.dispose(); return r; }
private bool wantInt(Value* v, const(char)[] fn) { if (v.t == VT.Int) return true; setErr(fn, ": expected an Int, got ", tn(v)); return false; }
private bool wantNum(Value* v, const(char)[] fn) { if (v.t == VT.Int || v.t == VT.Float) return true; setErr(fn, ": expected a number, got ", tn(v)); return false; }
private bool wantStr(Value* v, const(char)[] fn) { if (v.t == VT.Str) return true; setErr(fn, ": expected a String, got ", tn(v)); return false; }
private bool wantFun(Value* v, const(char)[] fn) { if (v.t == VT.Func) return true; setErr(fn, ": expected a function, got ", tn(v)); return false; }
private Value* L(Value* v) { return asList(v); }
private Value* fromChars(Value* l) {       // a [Char] back into a String when every element is a Char
    if (l.t != VT.List) return l;
    foreach (k; 0 .. l.n) if (l.items[k].t != VT.Char) return l;
    Buf b; foreach (k; 0 .. l.n) b.put(cast(char)l.items[k].i);
    auto s = mkStr(b.str()); b.dispose(); return s;
}
private Value* sameKind(Value* orig, Value* l) { return orig.t == VT.Str ? fromChars(l) : l; }

// ── arithmetic ──────────────────────────────────────────────────────────────────────────────────
private Value* arith(Value** a, char op) {
    auto x = a[0], y = a[1];
    const(char)[] nm = op == '+' ? "(+)" : op == '-' ? "(-)" : op == '*' ? "(*)" : "(/)";
    if (!wantNum(x, nm) || !wantNum(y, nm)) return null;
    if (op != '/' && x.t == VT.Int && y.t == VT.Int) {
        switch (op) { case '+': return mkInt(x.i + y.i); case '-': return mkInt(x.i - y.i); default: return mkInt(x.i * y.i); }
    }
    const p = numF(x), q = numF(y);
    switch (op) {
        case '+': return mkFloat(p + q);
        case '-': return mkFloat(p - q);
        case '*': return mkFloat(p * q);
        default: if (q == 0) return err("division by zero"); return mkFloat(p / q);
    }
}
private Value* p_add(Value** a, void* c) { return arith(a, '+'); }
private Value* p_sub(Value** a, void* c) { return arith(a, '-'); }
private Value* p_mul(Value** a, void* c) { return arith(a, '*'); }
private Value* p_fdiv(Value** a, void* c) { return arith(a, '/'); }
private Value* p_div(Value** a, void* c) {
    if (!wantInt(a[0], "div") || !wantInt(a[1], "div")) return null;
    if (a[1].i == 0) return err("div: division by zero");
    long q = a[0].i / a[1].i; if ((a[0].i % a[1].i != 0) && ((a[0].i < 0) != (a[1].i < 0))) --q;
    return mkInt(q);
}
private Value* p_mod(Value** a, void* c) {
    if (!wantInt(a[0], "mod") || !wantInt(a[1], "mod")) return null;
    if (a[1].i == 0) return err("mod: division by zero");
    long r = a[0].i % a[1].i; if (r != 0 && ((r < 0) != (a[1].i < 0))) r += a[1].i;
    return mkInt(r);
}
private Value* p_rem(Value** a, void* c) { if (!wantInt(a[0], "rem") || !wantInt(a[1], "rem")) return null; if (a[1].i == 0) return err("rem: division by zero"); return mkInt(a[0].i % a[1].i); }
private Value* p_quot(Value** a, void* c) { if (!wantInt(a[0], "quot") || !wantInt(a[1], "quot")) return null; if (a[1].i == 0) return err("quot: division by zero"); return mkInt(a[0].i / a[1].i); }
extern (C) double pow(double, double);
extern (C) double sqrt(double);
extern (C) double exp(double);
extern (C) double log(double);
extern (C) double sin(double);
extern (C) double cos(double);
extern (C) double floor(double);
extern (C) double ceil(double);
extern (C) double round(double);
private Value* p_pow(Value** a, void* c) {
    if (!wantNum(a[0], "(^)") || !wantNum(a[1], "(^)")) return null;
    if (a[0].t == VT.Int && a[1].t == VT.Int && a[1].i >= 0) { long r = 1, b = a[0].i; long e = a[1].i; while (e) { if (e & 1) r *= b; b *= b; e >>= 1; } return mkInt(r); }
    return mkFloat(pow(numF(a[0]), numF(a[1])));
}
private Value* p_negate(Value** a, void* c) { if (!wantNum(a[0], "negate")) return null; return a[0].t == VT.Int ? mkInt(-a[0].i) : mkFloat(-a[0].f); }
private Value* p_abs(Value** a, void* c) { if (!wantNum(a[0], "abs")) return null; return a[0].t == VT.Int ? mkInt(a[0].i < 0 ? -a[0].i : a[0].i) : mkFloat(a[0].f < 0 ? -a[0].f : a[0].f); }
private Value* p_signum(Value** a, void* c) { if (!wantNum(a[0], "signum")) return null; const x = numF(a[0]); return mkInt(x > 0 ? 1 : x < 0 ? -1 : 0); }
private Value* p_toFloat(Value** a, void* c) { if (!wantNum(a[0], "fromIntegral")) return null; return mkFloat(numF(a[0])); }
private Value* p_round(Value** a, void* c) { if (!wantNum(a[0], "round")) return null; return mkInt(cast(long)round(numF(a[0]))); }
private Value* p_floor(Value** a, void* c) { if (!wantNum(a[0], "floor")) return null; return mkInt(cast(long)floor(numF(a[0]))); }
private Value* p_ceiling(Value** a, void* c) { if (!wantNum(a[0], "ceiling")) return null; return mkInt(cast(long)ceil(numF(a[0]))); }
private Value* p_truncate(Value** a, void* c) { if (!wantNum(a[0], "truncate")) return null; return mkInt(cast(long)numF(a[0])); }
private Value* p_sqrt(Value** a, void* c) { if (!wantNum(a[0], "sqrt")) return null; return mkFloat(sqrt(numF(a[0]))); }
private Value* p_exp(Value** a, void* c) { if (!wantNum(a[0], "exp")) return null; return mkFloat(exp(numF(a[0]))); }
private Value* p_log(Value** a, void* c) { if (!wantNum(a[0], "log")) return null; return mkFloat(log(numF(a[0]))); }
private Value* p_sin(Value** a, void* c) { if (!wantNum(a[0], "sin")) return null; return mkFloat(sin(numF(a[0]))); }
private Value* p_cos(Value** a, void* c) { if (!wantNum(a[0], "cos")) return null; return mkFloat(cos(numF(a[0]))); }
private Value* p_even(Value** a, void* c) { if (!wantInt(a[0], "even")) return null; return mkBool(a[0].i % 2 == 0); }
private Value* p_odd(Value** a, void* c) { if (!wantInt(a[0], "odd")) return null; return mkBool(a[0].i % 2 != 0); }
private Value* p_gcd(Value** a, void* c) { if (!wantInt(a[0], "gcd") || !wantInt(a[1], "gcd")) return null; long x = a[0].i < 0 ? -a[0].i : a[0].i, y = a[1].i < 0 ? -a[1].i : a[1].i; while (y) { const t = x % y; x = y; y = t; } return mkInt(x); }
private Value* p_min(Value** a, void* c) { return valCmp(a[0], a[1]) <= 0 ? a[0] : a[1]; }
private Value* p_max(Value** a, void* c) { return valCmp(a[0], a[1]) >= 0 ? a[0] : a[1]; }
private Value* p_subtract(Value** a, void* c) { auto b = newItems(2); b[0] = a[1]; b[1] = a[0]; return arith(b, '-'); }
private Value* p_succ(Value** a, void* c) { if (a[0].t == VT.Char) return mkChar(cast(char)(a[0].i + 1)); if (!wantInt(a[0], "succ")) return null; return mkInt(a[0].i + 1); }
private Value* p_pred(Value** a, void* c) { if (a[0].t == VT.Char) return mkChar(cast(char)(a[0].i - 1)); if (!wantInt(a[0], "pred")) return null; return mkInt(a[0].i - 1); }

// ── comparison and logic ────────────────────────────────────────────────────────────────────────
private Value* p_eq(Value** a, void* c) { return mkBool(valEq(a[0], a[1])); }
private Value* p_ne(Value** a, void* c) { return mkBool(!valEq(a[0], a[1])); }
private Value* p_lt(Value** a, void* c) { return mkBool(valCmp(a[0], a[1]) < 0); }
private Value* p_le(Value** a, void* c) { return mkBool(valCmp(a[0], a[1]) <= 0); }
private Value* p_gt(Value** a, void* c) { return mkBool(valCmp(a[0], a[1]) > 0); }
private Value* p_ge(Value** a, void* c) { return mkBool(valCmp(a[0], a[1]) >= 0); }
private Value* p_compare(Value** a, void* c) { const r = valCmp(a[0], a[1]); return mkCtor(intern(r < 0 ? "LT" : r > 0 ? "GT" : "EQ"), 0); }
private Value* p_not(Value** a, void* c) { if (a[0].t != VT.Bool) return err("not: expected a Bool"); return mkBool(a[0].i == 0); }
private Value* p_and2(Value** a, void* c) { return mkBool(truthy(a[0]) && truthy(a[1])); }
private Value* p_or2(Value** a, void* c) { return mkBool(truthy(a[0]) || truthy(a[1])); }

// ── functions ───────────────────────────────────────────────────────────────────────────────────
private Value* p_id(Value** a, void* c) { return a[0]; }
private Value* p_const(Value** a, void* c) { return a[0]; }
private Value* p_flip(Value** a, void* c) { return apply2(a[0], a[2], a[1]); }
private Value* p_compose(Value** a, void* c) { auto g = apply1(a[1], a[2]); if (!g) return null; return apply1(a[0], g); }
private Value* p_app(Value** a, void* c) { return apply1(a[0], a[1]); }
private Value* p_until(Value** a, void* c) {
    auto x = a[2];
    for (;;) { auto t = apply1(a[0], x); if (!t) return null; if (truthy(t)) return x; x = apply1(a[1], x); if (!x) return null; if (g_interrupted) return err("interrupted"); }
}

// ── lists (a String is a list of Char wherever a list is expected) ───────────────────────────────
private Value* p_map(Value** a, void* c) {
    if (!wantFun(a[0], "map")) return null;
    if (a[1].t == VT.Ctor && (a[1].name == S_Just || a[1].name == S_Nothing)) {   // fmap on Maybe
        if (a[1].name == S_Nothing) return a[1];
        auto r = apply1(a[0], a[1].items[0]); if (!r) return null; return mkJust(r);
    }
    auto xs = L(a[1]); if (!xs) return null;
    auto r = mkList(xs.n);
    foreach (k; 0 .. xs.n) { r.items[k] = apply1(a[0], xs.items[k]); if (!r.items[k]) return null; }
    return sameKind(a[1], r);
}
private Value* p_filter(Value** a, void* c) {
    if (!wantFun(a[0], "filter")) return null;
    auto xs = L(a[1]); if (!xs) return null;
    ListB lb;
    foreach (k; 0 .. xs.n) { auto t = apply1(a[0], xs.items[k]); if (!t) return null; if (truthy(t)) lb.push(xs.items[k]); }
    return sameKind(a[1], lb.done());
}
private Value* p_foldl(Value** a, void* c) {
    auto xs = L(a[2]); if (!xs) return null;
    auto acc = a[1];
    foreach (k; 0 .. xs.n) { acc = apply2(a[0], acc, xs.items[k]); if (!acc) return null; }
    return acc;
}
private Value* p_foldr(Value** a, void* c) {
    auto xs = L(a[2]); if (!xs) return null;
    auto acc = a[1];
    foreach_reverse (k; 0 .. xs.n) { acc = apply2(a[0], xs.items[k], acc); if (!acc) return null; }
    return acc;
}
private Value* p_foldl1(Value** a, void* c) {
    auto xs = L(a[1]); if (!xs) return null;
    if (xs.n == 0) return err("foldl1: empty list");
    auto acc = xs.items[0];
    foreach (k; 1 .. xs.n) { acc = apply2(a[0], acc, xs.items[k]); if (!acc) return null; }
    return acc;
}
private Value* p_foldr1(Value** a, void* c) {
    auto xs = L(a[1]); if (!xs) return null;
    if (xs.n == 0) return err("foldr1: empty list");
    auto acc = xs.items[xs.n - 1];
    foreach_reverse (k; 0 .. xs.n - 1) { acc = apply2(a[0], xs.items[k], acc); if (!acc) return null; }
    return acc;
}
private Value* p_scanl(Value** a, void* c) {
    auto xs = L(a[2]); if (!xs) return null;
    auto r = mkList(xs.n + 1); r.items[0] = a[1];
    foreach (k; 0 .. xs.n) { r.items[k + 1] = apply2(a[0], r.items[k], xs.items[k]); if (!r.items[k + 1]) return null; }
    return r;
}
private Value* p_head(Value** a, void* c) { auto xs = L(a[0]); if (!xs) return null; if (xs.n == 0) return err("head: empty list"); return xs.items[0]; }
private Value* p_last(Value** a, void* c) { auto xs = L(a[0]); if (!xs) return null; if (xs.n == 0) return err("last: empty list"); return xs.items[xs.n - 1]; }
private Value* slice(Value* orig, Value* xs, size_t from, size_t to) {
    if (from > to) from = to;
    if (orig.t == VT.Str) return mkStr(orig.s[from .. to]);
    auto r = mkList(to - from);
    if (to > from) memcpy(r.items, xs.items + from, (to - from) * (Value*).sizeof);
    return r;
}
private Value* p_tail(Value** a, void* c) { auto xs = L(a[0]); if (!xs) return null; if (xs.n == 0) return err("tail: empty list"); return slice(a[0], xs, 1, xs.n); }
private Value* p_init(Value** a, void* c) { auto xs = L(a[0]); if (!xs) return null; if (xs.n == 0) return err("init: empty list"); return slice(a[0], xs, 0, xs.n - 1); }
private Value* p_null(Value** a, void* c) { if (a[0].t == VT.Str) return mkBool(a[0].n == 0); auto xs = L(a[0]); if (!xs) return null; return mkBool(xs.n == 0); }
private Value* p_length(Value** a, void* c) {
    if (a[0].t == VT.Str) return mkInt(a[0].n);
    if (a[0].t == VT.Record || a[0].t == VT.Obj) return mkInt(a[0].n);
    auto xs = L(a[0]); if (!xs) return null; return mkInt(xs.n);
}
private Value* p_reverse(Value** a, void* c) {
    auto xs = L(a[0]); if (!xs) return null;
    auto r = mkList(xs.n); foreach (k; 0 .. xs.n) r.items[k] = xs.items[xs.n - 1 - k];
    return sameKind(a[0], r);
}
private Value* p_append(Value** a, void* c) {
    if (a[0].t == VT.Str && a[1].t == VT.Str) { Buf b; b.put(str(a[0])); b.put(str(a[1])); auto r = mkStr(b.str()); b.dispose(); return r; }
    if ((a[0].t == VT.Record || a[0].t == VT.Obj) && (a[1].t == VT.Record || a[1].t == VT.Obj)) {   // (<>) on records: merge
        auto r = a[0]; foreach (k; 0 .. a[1].n) r = withField(r, a[1].keys[k], a[1].items[k]); return r;
    }
    auto x = L(a[0]); if (!x) return null; auto y = L(a[1]); if (!y) return null;
    auto r = mkList(x.n + y.n);
    if (x.n) memcpy(r.items, x.items, x.n * (Value*).sizeof);
    if (y.n) memcpy(r.items + x.n, y.items, y.n * (Value*).sizeof);
    return (a[0].t == VT.Str || a[1].t == VT.Str) ? fromChars(r) : r;
}
private Value* p_cons(Value** a, void* c) {
    if (a[0].t == VT.Char && (a[1].t == VT.Str || (a[1].t == VT.List && a[1].n == 0))) { Buf b; b.put(cast(char)a[0].i); b.put(str(a[1])); auto r = mkStr(b.str()); b.dispose(); return r; }
    auto xs = L(a[1]); if (!xs) return null;
    auto r = mkList(xs.n + 1); r.items[0] = a[0];
    if (xs.n) memcpy(r.items + 1, xs.items, xs.n * (Value*).sizeof);
    return r;
}
private Value* p_index(Value** a, void* c) {
    auto xs = L(a[0]); if (!xs) return null;
    if (!wantInt(a[1], "(!!)")) return null;
    if (a[1].i < 0 || a[1].i >= xs.n) return err("(!!): index out of range");
    return xs.items[cast(size_t)a[1].i];
}
private Value* p_concat(Value** a, void* c) {
    auto xs = L(a[0]); if (!xs) return null;
    bool allStr = xs.n > 0;
    foreach (k; 0 .. xs.n) if (xs.items[k].t != VT.Str) allStr = false;
    if (allStr) { Buf b; foreach (k; 0 .. xs.n) b.put(str(xs.items[k])); auto r = mkStr(b.str()); b.dispose(); return r; }
    ListB lb;
    foreach (k; 0 .. xs.n) { auto ys = L(xs.items[k]); if (!ys) return null; foreach (j; 0 .. ys.n) lb.push(ys.items[j]); }
    return lb.done();
}
private Value* p_concatMap(Value** a, void* c) {
    auto m = p_map(a, c); if (!m) return null;
    auto b = newItems(1); b[0] = m.t == VT.Str ? asList(m) : m;
    return p_concat(b, c);
}
private Value* p_take(Value** a, void* c) {
    if (!wantInt(a[0], "take")) return null;
    auto xs = L(a[1]); if (!xs) return null;
    const n = a[0].i < 0 ? 0 : (a[0].i > xs.n ? xs.n : cast(size_t)a[0].i);
    return slice(a[1], xs, 0, n);
}
private Value* p_drop(Value** a, void* c) {
    if (!wantInt(a[0], "drop")) return null;
    auto xs = L(a[1]); if (!xs) return null;
    const n = a[0].i < 0 ? 0 : (a[0].i > xs.n ? xs.n : cast(size_t)a[0].i);
    return slice(a[1], xs, n, xs.n);
}
private Value* p_splitAt(Value** a, void* c) {
    auto t = mkTuple(2); t.items[0] = p_take(a, c); if (!t.items[0]) return null; t.items[1] = p_drop(a, c); return t;
}
private Value* p_takeWhile(Value** a, void* c) {
    auto xs = L(a[1]); if (!xs) return null;
    size_t k = 0;
    for (; k < xs.n; ++k) { auto t = apply1(a[0], xs.items[k]); if (!t) return null; if (!truthy(t)) break; }
    return slice(a[1], xs, 0, k);
}
private Value* p_dropWhile(Value** a, void* c) {
    auto xs = L(a[1]); if (!xs) return null;
    size_t k = 0;
    for (; k < xs.n; ++k) { auto t = apply1(a[0], xs.items[k]); if (!t) return null; if (!truthy(t)) break; }
    return slice(a[1], xs, k, xs.n);
}
private Value* p_span(Value** a, void* c) {
    auto xs = L(a[1]); if (!xs) return null;
    size_t k = 0;
    for (; k < xs.n; ++k) { auto t = apply1(a[0], xs.items[k]); if (!t) return null; if (!truthy(t)) break; }
    auto r = mkTuple(2); r.items[0] = slice(a[1], xs, 0, k); r.items[1] = slice(a[1], xs, k, xs.n); return r;
}
private Value* p_break(Value** a, void* c) {
    auto xs = L(a[1]); if (!xs) return null;
    size_t k = 0;
    for (; k < xs.n; ++k) { auto t = apply1(a[0], xs.items[k]); if (!t) return null; if (truthy(t)) break; }
    auto r = mkTuple(2); r.items[0] = slice(a[1], xs, 0, k); r.items[1] = slice(a[1], xs, k, xs.n); return r;
}
private Value* p_zip(Value** a, void* c) {
    auto x = L(a[0]); if (!x) return null; auto y = L(a[1]); if (!y) return null;
    const n = x.n < y.n ? x.n : y.n;
    auto r = mkList(n);
    foreach (k; 0 .. n) { auto t = mkTuple(2); t.items[0] = x.items[k]; t.items[1] = y.items[k]; r.items[k] = t; }
    return r;
}
private Value* p_zip3(Value** a, void* c) {
    auto x = L(a[0]); if (!x) return null; auto y = L(a[1]); if (!y) return null; auto z = L(a[2]); if (!z) return null;
    size_t n = x.n < y.n ? x.n : y.n; if (z.n < n) n = z.n;
    auto r = mkList(n);
    foreach (k; 0 .. n) { auto t = mkTuple(3); t.items[0] = x.items[k]; t.items[1] = y.items[k]; t.items[2] = z.items[k]; r.items[k] = t; }
    return r;
}
private Value* p_zipWith(Value** a, void* c) {
    auto x = L(a[1]); if (!x) return null; auto y = L(a[2]); if (!y) return null;
    const n = x.n < y.n ? x.n : y.n;
    auto r = mkList(n);
    foreach (k; 0 .. n) { r.items[k] = apply2(a[0], x.items[k], y.items[k]); if (!r.items[k]) return null; }
    return r;
}
private Value* p_unzip(Value** a, void* c) {
    auto xs = L(a[0]); if (!xs) return null;
    auto l = mkList(xs.n), r = mkList(xs.n);
    foreach (k; 0 .. xs.n) { auto t = xs.items[k]; if (t.t != VT.Tuple || t.n < 2) return err("unzip: expected pairs"); l.items[k] = t.items[0]; r.items[k] = t.items[1]; }
    auto out_ = mkTuple(2); out_.items[0] = l; out_.items[1] = r; return out_;
}
private Value* p_indexed(Value** a, void* c) {
    auto xs = L(a[0]); if (!xs) return null;
    auto r = mkList(xs.n);
    foreach (k; 0 .. xs.n) { auto t = mkTuple(2); t.items[0] = mkInt(k); t.items[1] = xs.items[k]; r.items[k] = t; }
    return r;
}
private Value* p_lookup(Value** a, void* c) {
    if (a[1].t == VT.Record || a[1].t == VT.Obj) {                     // lookup "field" record
        if (a[0].t != VT.Str) return err("lookup: a record key must be a String");
        auto v = fieldS(a[1], str(a[0])); return v ? mkJust(v) : g_nothing;
    }
    auto xs = L(a[1]); if (!xs) return null;
    foreach (k; 0 .. xs.n) { auto t = xs.items[k]; if (t.t == VT.Tuple && t.n >= 2 && valEq(t.items[0], a[0])) return mkJust(t.items[1]); }
    return g_nothing;
}
private Value* p_elem(Value** a, void* c) {
    if (a[1].t == VT.Str && a[0].t == VT.Char) { foreach (ch; str(a[1])) if (ch == a[0].i) return g_true; return g_false; }
    auto xs = L(a[1]); if (!xs) return null;
    foreach (k; 0 .. xs.n) if (valEq(xs.items[k], a[0])) return g_true;
    return g_false;
}
private Value* p_notElem(Value** a, void* c) { auto r = p_elem(a, c); if (!r) return null; return mkBool(r.i == 0); }
private Value* p_any(Value** a, void* c) { auto xs = L(a[1]); if (!xs) return null; foreach (k; 0 .. xs.n) { auto t = apply1(a[0], xs.items[k]); if (!t) return null; if (truthy(t)) return g_true; } return g_false; }
private Value* p_all(Value** a, void* c) { auto xs = L(a[1]); if (!xs) return null; foreach (k; 0 .. xs.n) { auto t = apply1(a[0], xs.items[k]); if (!t) return null; if (!truthy(t)) return g_false; } return g_true; }
private Value* p_and(Value** a, void* c) { auto xs = L(a[0]); if (!xs) return null; foreach (k; 0 .. xs.n) if (!truthy(xs.items[k])) return g_false; return g_true; }
private Value* p_or(Value** a, void* c) { auto xs = L(a[0]); if (!xs) return null; foreach (k; 0 .. xs.n) if (truthy(xs.items[k])) return g_true; return g_false; }
private Value* p_sum(Value** a, void* c) {
    auto xs = L(a[0]); if (!xs) return null;
    auto acc = mkInt(0);
    foreach (k; 0 .. xs.n) { auto b = newItems(2); b[0] = acc; b[1] = xs.items[k]; acc = arith(b, '+'); if (!acc) return null; }
    return acc;
}
private Value* p_product(Value** a, void* c) {
    auto xs = L(a[0]); if (!xs) return null;
    auto acc = mkInt(1);
    foreach (k; 0 .. xs.n) { auto b = newItems(2); b[0] = acc; b[1] = xs.items[k]; acc = arith(b, '*'); if (!acc) return null; }
    return acc;
}
private Value* p_maximum(Value** a, void* c) { auto xs = L(a[0]); if (!xs) return null; if (!xs.n) return err("maximum: empty list"); auto m = xs.items[0]; foreach (k; 1 .. xs.n) if (valCmp(xs.items[k], m) > 0) m = xs.items[k]; return m; }
private Value* p_minimum(Value** a, void* c) { auto xs = L(a[0]); if (!xs) return null; if (!xs.n) return err("minimum: empty list"); auto m = xs.items[0]; foreach (k; 1 .. xs.n) if (valCmp(xs.items[k], m) < 0) m = xs.items[k]; return m; }
private Value* p_replicate(Value** a, void* c) {
    if (!wantInt(a[0], "replicate")) return null;
    const n = a[0].i < 0 ? 0 : cast(size_t)a[0].i;
    if (a[1].t == VT.Char) { Buf b; foreach (_; 0 .. n) b.put(cast(char)a[1].i); auto s = mkStr(b.str()); b.dispose(); return s; }
    auto r = mkList(n); foreach (k; 0 .. n) r.items[k] = a[1]; return r;
}

// merge sort (stable) with a comparison: cmpFn null = valCmp, else a dash function returning Ordering or Bool
private __gshared Value* g_sortBy; private __gshared Value* g_sortKey; private __gshared bool g_sortErr;
private int sortCmp(Value* x, Value* y) {
    if (g_sortErr) return 0;
    if (g_sortKey) {
        auto kx = apply1(g_sortKey, x), ky = apply1(g_sortKey, y);
        if (!kx || !ky) { g_sortErr = true; return 0; }
        return valCmp(kx, ky);
    }
    if (g_sortBy) {
        auto r = apply2(g_sortBy, x, y);
        if (!r) { g_sortErr = true; return 0; }
        if (r.t == VT.Ctor) { const n = symName(r.name); return n == "LT" ? -1 : n == "GT" ? 1 : 0; }
        if (r.t == VT.Int) return r.i < 0 ? -1 : r.i > 0;
        return 0;
    }
    return valCmp(x, y);
}
private void msort(Value** a, Value** tmp, size_t n) {
    if (n < 2) return;
    const m = n / 2;
    msort(a, tmp, m); msort(a + m, tmp, n - m);
    size_t i = 0, j = m, k = 0;
    while (i < m && j < n) tmp[k++] = sortCmp(a[j], a[i]) < 0 ? a[j++] : a[i++];
    while (i < m) tmp[k++] = a[i++];
    while (j < n) tmp[k++] = a[j++];
    memcpy(a, tmp, n * (Value*).sizeof);
}
private Value* doSort(Value* orig, Value* by, Value* key) {
    auto xs = L(orig); if (!xs) return null;
    auto r = mkList(xs.n); if (xs.n) memcpy(r.items, xs.items, xs.n * (Value*).sizeof);
    auto tmp = newItems(xs.n);
    g_sortBy = by; g_sortKey = key; g_sortErr = false;
    msort(r.items, tmp, xs.n);
    g_sortBy = null; g_sortKey = null;
    if (g_sortErr) return null;
    return sameKind(orig, r);
}
private Value* p_sort(Value** a, void* c) { return doSort(a[0], null, null); }
private Value* p_sortBy(Value** a, void* c) { return doSort(a[1], a[0], null); }
private Value* p_sortOn(Value** a, void* c) { return doSort(a[1], null, a[0]); }
private Value* p_nub(Value** a, void* c) {
    auto xs = L(a[0]); if (!xs) return null;
    ListB lb;
    foreach (k; 0 .. xs.n) { bool seen = false; foreach (j; 0 .. lb.n) if (valEq(lb.p[j], xs.items[k])) { seen = true; break; } if (!seen) lb.push(xs.items[k]); }
    return sameKind(a[0], lb.done());
}
private Value* p_group(Value** a, void* c) {
    auto xs = L(a[0]); if (!xs) return null;
    ListB outer; size_t st = 0;
    foreach (k; 1 .. xs.n + 1) {
        if (k == xs.n || !valEq(xs.items[k], xs.items[st])) { outer.push(slice(a[0], xs, st, k)); st = k; }
    }
    return outer.done();
}
private Value* p_groupOn(Value** a, void* c) {      // groupOn key xs: [(key, [x])] in first-seen order
    auto xs = L(a[1]); if (!xs) return null;
    ListB keys; ListB groups;
    foreach (k; 0 .. xs.n) {
        auto kv = apply1(a[0], xs.items[k]); if (!kv) return null;
        size_t at = keys.n;
        foreach (j; 0 .. keys.n) if (valEq(keys.p[j], kv)) { at = j; break; }
        if (at == keys.n) { keys.push(kv); ListB g; g.push(xs.items[k]); groups.push(g.done()); }
        else { auto g = groups.p[at]; auto ng = mkList(g.n + 1); memcpy(ng.items, g.items, g.n * (Value*).sizeof); ng.items[g.n] = xs.items[k]; groups.p[at] = ng; }
    }
    auto r = mkList(keys.n);
    foreach (k; 0 .. keys.n) { auto t = mkTuple(2); t.items[0] = keys.p[k]; t.items[1] = groups.p[k]; r.items[k] = t; }
    return r;
}
private Value* p_partition(Value** a, void* c) {
    auto xs = L(a[1]); if (!xs) return null;
    ListB yes, no;
    foreach (k; 0 .. xs.n) { auto t = apply1(a[0], xs.items[k]); if (!t) return null; (truthy(t) ? yes : no).push(xs.items[k]); }
    auto r = mkTuple(2); r.items[0] = sameKind(a[1], yes.done()); r.items[1] = sameKind(a[1], no.done()); return r;
}
private Value* p_find(Value** a, void* c) {
    auto xs = L(a[1]); if (!xs) return null;
    foreach (k; 0 .. xs.n) { auto t = apply1(a[0], xs.items[k]); if (!t) return null; if (truthy(t)) return mkJust(xs.items[k]); }
    return g_nothing;
}
private Value* p_count(Value** a, void* c) {
    auto xs = L(a[1]); if (!xs) return null; long n = 0;
    foreach (k; 0 .. xs.n) { auto t = apply1(a[0], xs.items[k]); if (!t) return null; if (truthy(t)) ++n; }
    return mkInt(n);
}
private Value* p_intercalate(Value** a, void* c) {
    auto xs = L(a[1]); if (!xs) return null;
    if (a[0].t == VT.Str) {
        Buf b;
        foreach (k; 0 .. xs.n) { if (k) b.put(str(a[0])); textOf(b, xs.items[k]); }
        auto r = mkStr(b.str()); b.dispose(); return r;
    }
    auto sep = L(a[0]); if (!sep) return null;
    ListB lb;
    foreach (k; 0 .. xs.n) { if (k) foreach (j; 0 .. sep.n) lb.push(sep.items[j]); auto ys = L(xs.items[k]); if (!ys) return null; foreach (j; 0 .. ys.n) lb.push(ys.items[j]); }
    return lb.done();
}
private Value* p_intersperse(Value** a, void* c) {
    auto xs = L(a[1]); if (!xs) return null;
    ListB lb; foreach (k; 0 .. xs.n) { if (k) lb.push(a[0]); lb.push(xs.items[k]); }
    return sameKind(a[1], lb.done());
}

// ── strings ─────────────────────────────────────────────────────────────────────────────────────
private Value* p_lines(Value** a, void* c) { if (!wantStr(a[0], "lines")) return null; return linesToList(str(a[0])); }
private Value* p_unlines(Value** a, void* c) {
    auto xs = L(a[0]); if (!xs) return null;
    Buf b; foreach (k; 0 .. xs.n) { textOf(b, xs.items[k]); b.put('\n'); }
    auto r = mkStr(b.str()); b.dispose(); return r;
}
private Value* p_words(Value** a, void* c) {
    if (!wantStr(a[0], "words")) return null;
    const s = str(a[0]); ListB lb; size_t st = 0; bool in_ = false;
    foreach (k; 0 .. s.length + 1) {
        const sp = k == s.length || s[k] == ' ' || s[k] == '\t' || s[k] == '\n' || s[k] == '\r';
        if (sp && in_) { lb.push(mkStr(s[st .. k])); in_ = false; }
        else if (!sp && !in_) { st = k; in_ = true; }
    }
    return lb.done();
}
private Value* p_unwords(Value** a, void* c) {
    auto xs = L(a[0]); if (!xs) return null;
    Buf b; foreach (k; 0 .. xs.n) { if (k) b.put(' '); textOf(b, xs.items[k]); }
    auto r = mkStr(b.str()); b.dispose(); return r;
}
private Value* p_show(Value** a, void* c) { Buf b; showValue(b, a[0]); auto r = mkStr(b.str()); b.dispose(); return r; }
private Value* p_text(Value** a, void* c) { Buf b; textOf(b, a[0]); auto r = mkStr(b.str()); b.dispose(); return r; }
Value* readValue(const(char)[] s) {
    // Int, Float, True/False, else the string itself
    size_t a = 0, b = s.length;
    while (a < b && isSpace(s[a])) ++a; while (b > a && (isSpace(s[b - 1]) || s[b - 1] == '\n')) --b;
    auto t = s[a .. b];
    if (t == "True") return g_true;
    if (t == "False") return g_false;
    if (t.length) {
        auto z = cz(t); char* end;
        const long i = strtoll(z, &end, 0);
        if (*end == 0) { free(z); return mkInt(i); }
        const double d = strtod(z, &end);
        if (*end == 0) { free(z); return mkFloat(d); }
        free(z);
    }
    return null;
}
private Value* p_read(Value** a, void* c) {
    if (!wantStr(a[0], "read")) return null;
    auto v = readValue(str(a[0]));
    if (!v) return err("read: not a number or Bool: \"", str(a[0]), "\"");
    return v;
}
private Value* p_readMaybe(Value** a, void* c) { if (!wantStr(a[0], "readMaybe")) return null; auto v = readValue(str(a[0])); return v ? mkJust(v) : g_nothing; }
private char up(char c) { return (c >= 'a' && c <= 'z') ? cast(char)(c - 32) : c; }
private char lo(char c) { return (c >= 'A' && c <= 'Z') ? cast(char)(c + 32) : c; }
private Value* mapChars(Value* v, char function(char) @nogc nothrow f, const(char)[] nm) {
    if (v.t == VT.Char) return mkChar(f(cast(char)v.i));
    if (!wantStr(v, nm)) return null;
    Buf b; foreach (ch; str(v)) b.put(f(ch)); auto r = mkStr(b.str()); b.dispose(); return r;
}
private Value* p_toUpper(Value** a, void* c) { return mapChars(a[0], &up, "toUpper"); }
private Value* p_toLower(Value** a, void* c) { return mapChars(a[0], &lo, "toLower"); }
private const(char)[] asText(Value* v, ref Buf tmp) { if (v.t == VT.Str) return str(v); tmp.clear(); textOf(tmp, v); return tmp.str(); }
private Value* p_isPrefixOf(Value** a, void* c) {
    if (a[0].t == VT.Str && a[1].t == VT.Str) return mkBool(startsWith(str(a[1]), str(a[0])));
    auto p = L(a[0]); if (!p) return null; auto s = L(a[1]); if (!s) return null;
    if (p.n > s.n) return g_false; foreach (k; 0 .. p.n) if (!valEq(p.items[k], s.items[k])) return g_false; return g_true;
}
private Value* p_isSuffixOf(Value** a, void* c) {
    if (a[0].t == VT.Str && a[1].t == VT.Str) return mkBool(endsWith(str(a[1]), str(a[0])));
    auto p = L(a[0]); if (!p) return null; auto s = L(a[1]); if (!s) return null;
    if (p.n > s.n) return g_false; foreach (k; 0 .. p.n) if (!valEq(p.items[k], s.items[s.n - p.n + k])) return g_false; return g_true;
}
private bool contains(const(char)[] h, const(char)[] n) {
    if (n.length == 0) return true;
    if (n.length > h.length) return false;
    foreach (k; 0 .. h.length - n.length + 1) if (h[k .. k + n.length] == n) return true;
    return false;
}
private Value* p_isInfixOf(Value** a, void* c) {
    if (a[0].t == VT.Str && a[1].t == VT.Str) return mkBool(contains(str(a[1]), str(a[0])));
    auto p = L(a[0]); if (!p) return null; auto s = L(a[1]); if (!s) return null;
    if (p.n > s.n) return g_false;
    foreach (st; 0 .. s.n - p.n + 1) { bool ok = true; foreach (k; 0 .. p.n) if (!valEq(p.items[k], s.items[st + k])) { ok = false; break; } if (ok) return g_true; }
    return g_false;
}
private Value* p_strip(Value** a, void* c) {
    if (!wantStr(a[0], "strip")) return null;
    auto s = str(a[0]); size_t x = 0, y = s.length;
    while (x < y && (isSpace(s[x]) || s[x] == '\n')) ++x; while (y > x && (isSpace(s[y - 1]) || s[y - 1] == '\n')) --y;
    return mkStr(s[x .. y]);
}
private Value* p_splitOn(Value** a, void* c) {
    if (!wantStr(a[0], "splitOn") || !wantStr(a[1], "splitOn")) return null;
    auto sep = str(a[0]), s = str(a[1]);
    ListB lb;
    if (sep.length == 0) { foreach (ch; s) lb.push(mkStr((&ch)[0 .. 1])); return lb.done(); }
    size_t st = 0, k = 0;
    while (k + sep.length <= s.length) {
        if (s[k .. k + sep.length] == sep) { lb.push(mkStr(s[st .. k])); k += sep.length; st = k; }
        else ++k;
    }
    lb.push(mkStr(s[st .. $]));
    return lb.done();
}
private Value* p_replace(Value** a, void* c) {
    if (!wantStr(a[0], "replace") || !wantStr(a[1], "replace") || !wantStr(a[2], "replace")) return null;
    auto from = str(a[0]), to = str(a[1]), s = str(a[2]);
    if (from.length == 0) return a[2];
    Buf b; size_t k = 0;
    while (k < s.length) {
        if (k + from.length <= s.length && s[k .. k + from.length] == from) { b.put(to); k += from.length; }
        else { b.put(s[k]); ++k; }
    }
    auto r = mkStr(b.str()); b.dispose(); return r;
}
private Value* p_ord(Value** a, void* c) { if (a[0].t != VT.Char) return err("ord: expected a Char"); return mkInt(a[0].i); }
private Value* p_chr(Value** a, void* c) { if (!wantInt(a[0], "chr")) return null; return mkChar(cast(char)a[0].i); }
private Value* charTest(Value* v, bool function(char) @nogc nothrow f) {
    if (v.t == VT.Char) return mkBool(f(cast(char)v.i));
    if (v.t == VT.Str) { if (v.n == 0) return g_false; foreach (ch; str(v)) if (!f(ch)) return g_false; return g_true; }
    return err("expected a Char or String");
}
private bool fdigit(char c) { return isDigit(c); }
private bool fspace(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }
private bool falpha(char c) { return isAlpha(c) && c != '_'; }
private bool fupper(char c) { return isUpper(c); }
private bool flower(char c) { return c >= 'a' && c <= 'z'; }
private Value* p_isDigit(Value** a, void* c) { return charTest(a[0], &fdigit); }
private Value* p_isSpace(Value** a, void* c) { return charTest(a[0], &fspace); }
private Value* p_isAlpha(Value** a, void* c) { return charTest(a[0], &falpha); }
private Value* p_isUpper(Value** a, void* c) { return charTest(a[0], &fupper); }
private Value* p_isLower(Value** a, void* c) { return charTest(a[0], &flower); }
private Value* p_padLeft(Value** a, void* c) {
    if (!wantInt(a[0], "padLeft")) return null; Buf t; auto s = asText(a[1], t);
    Buf b; foreach (_; s.length .. (a[0].i > s.length ? cast(size_t)a[0].i : s.length)) b.put(' '); b.put(s);
    auto r = mkStr(b.str()); b.dispose(); t.dispose(); return r;
}
private Value* p_padRight(Value** a, void* c) {
    if (!wantInt(a[0], "padRight")) return null; Buf t; auto s = asText(a[1], t);
    Buf b; b.put(s); foreach (_; s.length .. (a[0].i > s.length ? cast(size_t)a[0].i : s.length)) b.put(' ');
    auto r = mkStr(b.str()); b.dispose(); t.dispose(); return r;
}

// ── Maybe / Either / tuples ─────────────────────────────────────────────────────────────────────
private bool isJust(Value* v) { return v.t == VT.Ctor && v.name == S_Just; }
private Value* p_maybe(Value** a, void* c) { if (isJust(a[2])) return apply1(a[1], a[2].items[0]); return a[0]; }
private Value* p_fromMaybe(Value** a, void* c) { return isJust(a[1]) ? a[1].items[0] : a[0]; }
private Value* p_isJust(Value** a, void* c) { return mkBool(isJust(a[0])); }
private Value* p_isNothing(Value** a, void* c) { return mkBool(a[0].t == VT.Ctor && a[0].name == S_Nothing); }
private Value* p_fromJust(Value** a, void* c) { if (!isJust(a[0])) return err("fromJust: Nothing"); return a[0].items[0]; }
private Value* p_catMaybes(Value** a, void* c) { auto xs = L(a[0]); if (!xs) return null; ListB lb; foreach (k; 0 .. xs.n) if (isJust(xs.items[k])) lb.push(xs.items[k].items[0]); return lb.done(); }
private Value* p_mapMaybe(Value** a, void* c) {
    auto xs = L(a[1]); if (!xs) return null; ListB lb;
    foreach (k; 0 .. xs.n) { auto r = apply1(a[0], xs.items[k]); if (!r) return null; if (isJust(r)) lb.push(r.items[0]); }
    return lb.done();
}
private Value* p_either(Value** a, void* c) {
    if (a[2].t == VT.Ctor && a[2].name == S_Left) return apply1(a[0], a[2].items[0]);
    if (a[2].t == VT.Ctor && a[2].name == S_Right) return apply1(a[1], a[2].items[0]);
    return err("either: expected Left or Right");
}
private Value* p_fst(Value** a, void* c) { if (a[0].t != VT.Tuple || a[0].n < 1) return err("fst: expected a pair"); return a[0].items[0]; }
private Value* p_snd(Value** a, void* c) { if (a[0].t != VT.Tuple || a[0].n < 2) return err("snd: expected a pair"); return a[0].items[1]; }
private Value* p_swap(Value** a, void* c) { if (a[0].t != VT.Tuple || a[0].n != 2) return err("swap: expected a pair"); auto t = mkTuple(2); t.items[0] = a[0].items[1]; t.items[1] = a[0].items[0]; return t; }
private Value* p_curry(Value** a, void* c) { auto t = mkTuple(2); t.items[0] = a[1]; t.items[1] = a[2]; return apply1(a[0], t); }
private Value* p_uncurry(Value** a, void* c) { if (a[1].t != VT.Tuple || a[1].n != 2) return err("uncurry: expected a pair"); return apply2(a[0], a[1].items[0], a[1].items[1]); }

// ── records ─────────────────────────────────────────────────────────────────────────────────────
private Value* p_keys(Value** a, void* c) {
    if (a[0].t != VT.Record && a[0].t != VT.Obj) return err("keys: expected a record or object");
    auto r = mkList(a[0].n); foreach (k; 0 .. a[0].n) r.items[k] = mkStr(symName(a[0].keys[k])); return r;
}
private Value* p_values(Value** a, void* c) {
    if (a[0].t != VT.Record && a[0].t != VT.Obj) return err("values: expected a record or object");
    auto r = mkList(a[0].n); foreach (k; 0 .. a[0].n) r.items[k] = a[0].items[k]; return r;
}
private Value* p_get(Value** a, void* c) {
    if (!wantStr(a[0], "get")) return null;
    auto v = member(a[1], intern(str(a[0])));
    return v;
}
private Value* p_set(Value** a, void* c) {
    if (!wantStr(a[0], "set")) return null;
    if (a[2].t != VT.Record && a[2].t != VT.Obj) return err("set: expected a record");
    return withField(a[2], intern(str(a[0])), a[1]);
}
private Value* p_has(Value** a, void* c) { if (!wantStr(a[0], "has")) return null; return mkBool(fieldS(a[1], str(a[0])) !is null); }
private Value* p_toPairs(Value** a, void* c) {
    if (a[0].t != VT.Record && a[0].t != VT.Obj) return err("toPairs: expected a record");
    auto r = mkList(a[0].n);
    foreach (k; 0 .. a[0].n) { auto t = mkTuple(2); t.items[0] = mkStr(symName(a[0].keys[k])); t.items[1] = a[0].items[k]; r.items[k] = t; }
    return r;
}
private Value* p_fromPairs(Value** a, void* c) {
    auto xs = L(a[0]); if (!xs) return null;
    auto r = mkRecord(0);
    foreach (k; 0 .. xs.n) {
        auto t = xs.items[k];
        if (t.t != VT.Tuple || t.n != 2 || t.items[0].t != VT.Str) return err("fromPairs: expected [(String, a)]");
        r = withField(r, intern(str(t.items[0])), t.items[1]);
    }
    return r;
}

// ── effects: output, files, processes, environment ─────────────────────────────────────────────
private Value* p_putStrLn(Value** a, void* c) { Buf b; textOf(b, a[0]); out_(b.str()); outc('\n'); b.dispose(); oflush(); return g_unit; }
private Value* p_putStr(Value** a, void* c) { Buf b; textOf(b, a[0]); out_(b.str()); b.dispose(); oflush(); return g_unit; }
private Value* p_print(Value** a, void* c) { Buf b; showValue(b, a[0]); out_(b.str()); outc('\n'); b.dispose(); oflush(); return g_unit; }
Value* readWholeFile(const(char)[] path) {
    auto z = cz(path);
    const fd = open(z, O_RDONLY); free(z);
    if (fd < 0) return err("cannot read ", path);
    Buf b; char[8192] t;
    for (;;) { const r = read(fd, t.ptr, t.length); if (r <= 0) break; b.put(t[0 .. cast(size_t)r]); }
    close(fd);
    auto v = mkStr(b.str()); b.dispose(); return v;
}
private Value* p_readFile(Value** a, void* c) { if (!wantStr(a[0], "readFile")) return null; return readWholeFile(str(a[0])); }
private Value* p_readLines(Value** a, void* c) { if (!wantStr(a[0], "readLines")) return null; auto s = readWholeFile(str(a[0])); if (!s) return null; return linesToList(str(s)); }
private Value* writeF(Value** a, bool append) {
    if (g_pure) return err("(writeFile has effects)");
    if (!wantStr(a[0], append ? "appendFile" : "writeFile")) return null;
    auto z = cz(str(a[0]));
    const fd = open(z, O_WRONLY | O_CREAT | (append ? O_APPEND : O_TRUNC), 0x1A4); free(z);
    if (fd < 0) return err("cannot write ", str(a[0]));
    Buf b; if (a[1].t == VT.List) linesOf(b, a[1]); else textOf(b, a[1]);
    size_t o = 0; while (o < b.n) { const w = write(fd, b.p + o, b.n - o); if (w <= 0) break; o += cast(size_t)w; }
    close(fd); b.dispose();
    return g_unit;
}
private Value* p_writeFile(Value** a, void* c) { return writeF(a, false); }
private Value* p_appendFile(Value** a, void* c) { return writeF(a, true); }
private Value* p_exists(Value** a, void* c) { if (!wantStr(a[0], "exists")) return null; auto z = cz(str(a[0])); const r = access(z, F_OK) == 0; free(z); return mkBool(r); }
private Value* p_isDir(Value** a, void* c) { if (!wantStr(a[0], "isDir")) return null; auto z = cz(str(a[0])); Stat st; const r = stat(z, &st) == 0 && (st.st_mode & 0xF000) == 0x4000; free(z); return mkBool(r); }
private Value* p_listDir(Value** a, void* c) {
    if (!wantStr(a[0], "listDir")) return null;
    auto z = cz(str(a[0])); auto d = opendir(z); free(z);
    if (d is null) return err("cannot list ", str(a[0]));
    ListB lb;
    for (;;) {
        auto e = cast(Dirent*)readdir(d); if (e is null) break;
        const n = e.d_name.ptr[0 .. strlen(e.d_name.ptr)];
        if (n == "." || n == "..") continue;
        lb.push(mkStr(n));
    }
    closedir(d);
    return doSort(lb.done(), null, null);
}
private Value* p_run(Value** a, void* c) {
    if (g_pure) return err("(run has effects)");
    if (!wantStr(a[0], "run")) return null;
    Buf o; runCapture(str(a[0]), null, o);
    auto l = linesToList(o.str()); o.dispose(); return l;
}
private Value* p_sh(Value** a, void* c) {
    if (g_pure) return err("(sh has effects)");
    if (!wantStr(a[0], "sh")) return null;
    return mkInt(runCommandText(str(a[0]), null));
}
private Value* p_status(Value** a, void* c) { return mkInt(g_lastStatus); }
private Value* p_env(Value** a, void* c) { if (!wantStr(a[0], "env")) return null; auto z = cz(str(a[0])); auto e = getenv(z); free(z); return e ? mkJust(mkStrZ(e)) : g_nothing; }
private Value* p_setEnv(Value** a, void* c) {
    if (g_pure) return err("(setEnv has effects)");
    if (!wantStr(a[0], "setEnv")) return null;
    Buf b; textOf(b, a[1]); auto zn = cz(str(a[0])); setenv(zn, b.cstr(), 1); free(zn); b.dispose();
    return g_unit;
}
private Value* p_cwd(Value** a, void* c) { char[1024] b; if (!getcwd(b.ptr, b.length)) return mkStr("/"); return mkStrZ(b.ptr); }
private Value* p_now(Value** a, void* c) { return mkInt(time(null)); }
private Value* p_sleep(Value** a, void* c) { if (g_pure) return g_unit; if (!wantNum(a[0], "sleep")) return null; usleep(cast(uint)(numF(a[0]) * 1_000_000)); return g_unit; }
private Value* p_exit(Value** a, void* c) {
    if (g_pure) return err("(exit has effects)");
    oflush(); g_exitRequested = true; g_exitCode = a[0].t == VT.Int ? cast(int)a[0].i : 0; return g_unit;
}
private Value* p_mapM_(Value** a, void* c) { auto xs = L(a[1]); if (!xs) return null; foreach (k; 0 .. xs.n) { if (!apply1(a[0], xs.items[k])) return null; if (g_interrupted) return err("interrupted"); } return g_unit; }
private Value* p_forM_(Value** a, void* c) { auto b = newItems(2); b[0] = a[1]; b[1] = a[0]; return p_mapM_(b, c); }
private Value* p_mapM(Value** a, void* c) { return p_map(a, c); }
private Value* p_forM(Value** a, void* c) { auto b = newItems(2); b[0] = a[1]; b[1] = a[0]; return p_map(b, c); }
private Value* p_when(Value** a, void* c) { if (truthy(a[0]) && a[1].t == VT.Func) return apply1(a[1], g_unit); return g_unit; }
private Value* p_sequence_(Value** a, void* c) { return g_unit; }
private Value* p_typeOf(Value** a, void* c) { Buf b; typeOf(b, a[0]); auto r = mkStr(b.str()); b.dispose(); return r; }
private Value* p_members(Value** a, void* c) {
    ListB lb;
    if (a[0].t == VT.Record || a[0].t == VT.Obj) foreach (k; 0 .. a[0].n) lb.push(mkStr(symName(a[0].keys[k])));
    const t = memberType(a[0]);
    foreach (ref m; g_methods[]) if (m.type == t) lb.push(mkStr(symName(m.name)));
    return lb.done();
}
private Value* p_seq(Value** a, void* c) { return a[1]; }

// Methods on base types, so `"text".<Tab>` and `xs.<Tab>` explore too.
private Value* m_upper(Value** a, void* c) { return p_toUpper(a, c); }
private Value* m_lower(Value** a, void* c) { return p_toLower(a, c); }

void libInit() {
    // operators
    defPrim("+", 2, &p_add, "Num a => a -> a -> a", "addition");
    defPrim("-", 2, &p_sub, "Num a => a -> a -> a", "subtraction");
    defPrim("*", 2, &p_mul, "Num a => a -> a -> a", "multiplication");
    defPrim("/", 2, &p_fdiv, "Num a => a -> a -> Float", "division (always a Float)");
    defPrim("^", 2, &p_pow, "Num a => a -> Int -> a", "power");
    defPrim("**", 2, &p_pow, "Float -> Float -> Float", "power");
    defPrim("==", 2, &p_eq, "a -> a -> Bool", "equal");
    defPrim("/=", 2, &p_ne, "a -> a -> Bool", "not equal");
    defPrim("<", 2, &p_lt, "a -> a -> Bool", "less than");
    defPrim("<=", 2, &p_le, "a -> a -> Bool", "less or equal");
    defPrim(">", 2, &p_gt, "a -> a -> Bool", "greater than");
    defPrim(">=", 2, &p_ge, "a -> a -> Bool", "greater or equal");
    defPrim("&&", 2, &p_and2, "Bool -> Bool -> Bool", "and");
    defPrim("||", 2, &p_or2, "Bool -> Bool -> Bool", "or");
    defPrim(".", 3, &p_compose, "(b -> c) -> (a -> b) -> a -> c", "composition: (f . g) x = f (g x)");
    defPrim("$", 2, &p_app, "(a -> b) -> a -> b", "application");
    defPrim("|>", 2, &p_app, "a -> (a -> b) -> b", "pipe: x |> f = f x");
    defPrim("++", 2, &p_append, "[a] -> [a] -> [a]", "concatenation (lists and strings)");
    defPrim("<>", 2, &p_append, "a -> a -> a", "append: lists, strings; records merge");
    defPrim(":", 2, &p_cons, "a -> [a] -> [a]", "cons");
    defPrim("!!", 2, &p_index, "[a] -> Int -> a", "index (from 0)");
    defPrim("<$>", 2, &p_map, "(a -> b) -> f a -> f b", "map over a list or a Maybe");
    defPrim("div", 2, &p_div, "Int -> Int -> Int", "integer division (rounds down)");
    defPrim("mod", 2, &p_mod, "Int -> Int -> Int", "modulus");
    defPrim("rem", 2, &p_rem, "Int -> Int -> Int", "remainder");
    defPrim("quot", 2, &p_quot, "Int -> Int -> Int", "quotient (rounds toward zero)");
    defPrim("elem", 2, &p_elem, "a -> [a] -> Bool", "is it an element of the list");
    defPrim("notElem", 2, &p_notElem, "a -> [a] -> Bool", "is it not an element");
    // numbers
    defPrim("negate", 1, &p_negate, "Num a => a -> a", "negation");
    defPrim("abs", 1, &p_abs, "Num a => a -> a", "absolute value");
    defPrim("signum", 1, &p_signum, "Num a => a -> Int", "sign: -1, 0 or 1");
    defPrim("fromIntegral", 1, &p_toFloat, "Int -> Float", "as a Float");
    defPrim("toFloat", 1, &p_toFloat, "Int -> Float", "as a Float");
    defPrim("round", 1, &p_round, "Float -> Int", "nearest Int");
    defPrim("floor", 1, &p_floor, "Float -> Int", "round down");
    defPrim("ceiling", 1, &p_ceiling, "Float -> Int", "round up");
    defPrim("truncate", 1, &p_truncate, "Float -> Int", "round toward zero");
    defPrim("sqrt", 1, &p_sqrt, "Float -> Float", "square root");
    defPrim("exp", 1, &p_exp, "Float -> Float", "e^x");
    defPrim("log", 1, &p_log, "Float -> Float", "natural logarithm");
    defPrim("sin", 1, &p_sin, "Float -> Float", "sine");
    defPrim("cos", 1, &p_cos, "Float -> Float", "cosine");
    defValue("pi", mkFloat(3.141592653589793), "Float", "pi");
    defPrim("even", 1, &p_even, "Int -> Bool", "is it even");
    defPrim("odd", 1, &p_odd, "Int -> Bool", "is it odd");
    defPrim("gcd", 2, &p_gcd, "Int -> Int -> Int", "greatest common divisor");
    defPrim("min", 2, &p_min, "a -> a -> a", "the smaller");
    defPrim("max", 2, &p_max, "a -> a -> a", "the larger");
    defPrim("subtract", 2, &p_subtract, "Num a => a -> a -> a", "subtract x y = y - x");
    defPrim("succ", 1, &p_succ, "a -> a", "the next value");
    defPrim("pred", 1, &p_pred, "a -> a", "the previous value");
    defPrim("compare", 2, &p_compare, "a -> a -> Ordering", "LT, EQ or GT");
    defPrim("not", 1, &p_not, "Bool -> Bool", "negation");
    defValue("otherwise", g_true, "Bool", "True (for guards)");
    // functions
    defPrim("id", 1, &p_id, "a -> a", "identity");
    defPrim("return", 1, &p_id, "a -> a", "the value (do blocks run as they go: return is the identity)");
    defPrim("pure", 1, &p_id, "a -> a", "the value (like return)");
    defPrim("const", 2, &p_const, "a -> b -> a", "the first argument");
    defPrim("flip", 3, &p_flip, "(a -> b -> c) -> b -> a -> c", "swap the arguments");
    defPrim("until", 3, &p_until, "(a -> Bool) -> (a -> a) -> a -> a", "apply until the test holds");
    defPrim("seq", 2, &p_seq, "a -> b -> b", "evaluate both (dash is strict), return the second");
    // lists
    defPrim("map", 2, &p_map, "(a -> b) -> [a] -> [b]", "apply to every element");
    defPrim("fmap", 2, &p_map, "(a -> b) -> f a -> f b", "map over a list or a Maybe");
    defPrim("filter", 2, &p_filter, "(a -> Bool) -> [a] -> [a]", "the elements the test keeps");
    defPrim("foldl", 3, &p_foldl, "(b -> a -> b) -> b -> [a] -> b", "fold from the left");
    defPrim("foldr", 3, &p_foldr, "(a -> b -> b) -> b -> [a] -> b", "fold from the right");
    defPrim("foldl1", 2, &p_foldl1, "(a -> a -> a) -> [a] -> a", "fold a non-empty list from the left");
    defPrim("foldr1", 2, &p_foldr1, "(a -> a -> a) -> [a] -> a", "fold a non-empty list from the right");
    defPrim("scanl", 3, &p_scanl, "(b -> a -> b) -> b -> [a] -> [b]", "running folds");
    defPrim("head", 1, &p_head, "[a] -> a", "the first element");
    defPrim("last", 1, &p_last, "[a] -> a", "the last element");
    defPrim("tail", 1, &p_tail, "[a] -> [a]", "all but the first");
    defPrim("init", 1, &p_init, "[a] -> [a]", "all but the last");
    defPrim("null", 1, &p_null, "[a] -> Bool", "is it empty");
    defPrim("length", 1, &p_length, "[a] -> Int", "number of elements (or characters, or fields)");
    defPrim("reverse", 1, &p_reverse, "[a] -> [a]", "reversed");
    defPrim("concat", 1, &p_concat, "[[a]] -> [a]", "flatten one level");
    defPrim("concatMap", 2, &p_concatMap, "(a -> [b]) -> [a] -> [b]", "map, then concat");
    defPrim("take", 2, &p_take, "Int -> [a] -> [a]", "the first n");
    defPrim("drop", 2, &p_drop, "Int -> [a] -> [a]", "all but the first n");
    defPrim("splitAt", 2, &p_splitAt, "Int -> [a] -> ([a], [a])", "(take n xs, drop n xs)");
    defPrim("takeWhile", 2, &p_takeWhile, "(a -> Bool) -> [a] -> [a]", "the prefix that passes");
    defPrim("dropWhile", 2, &p_dropWhile, "(a -> Bool) -> [a] -> [a]", "after the prefix that passes");
    defPrim("span", 2, &p_span, "(a -> Bool) -> [a] -> ([a], [a])", "(takeWhile p xs, dropWhile p xs)");
    defPrim("break", 2, &p_break, "(a -> Bool) -> [a] -> ([a], [a])", "split where the test first passes");
    defPrim("zip", 2, &p_zip, "[a] -> [b] -> [(a, b)]", "pair up");
    defPrim("zip3", 3, &p_zip3, "[a] -> [b] -> [c] -> [(a, b, c)]", "triple up");
    defPrim("zipWith", 3, &p_zipWith, "(a -> b -> c) -> [a] -> [b] -> [c]", "combine pairwise");
    defPrim("unzip", 1, &p_unzip, "[(a, b)] -> ([a], [b])", "split pairs");
    defPrim("indexed", 1, &p_indexed, "[a] -> [(Int, a)]", "pair each element with its index");
    defPrim("lookup", 2, &p_lookup, "k -> [(k, v)] -> Maybe v", "find a key (also: lookup \"field\" record)");
    defPrim("any", 2, &p_any, "(a -> Bool) -> [a] -> Bool", "does any pass");
    defPrim("all", 2, &p_all, "(a -> Bool) -> [a] -> Bool", "do all pass");
    defPrim("and", 1, &p_and, "[Bool] -> Bool", "all True");
    defPrim("or", 1, &p_or, "[Bool] -> Bool", "any True");
    defPrim("sum", 1, &p_sum, "[a] -> a", "sum");
    defPrim("product", 1, &p_product, "[a] -> a", "product");
    defPrim("maximum", 1, &p_maximum, "[a] -> a", "the largest");
    defPrim("minimum", 1, &p_minimum, "[a] -> a", "the smallest");
    defPrim("replicate", 2, &p_replicate, "Int -> a -> [a]", "n copies");
    defPrim("sort", 1, &p_sort, "[a] -> [a]", "sorted (stable)");
    defPrim("sortBy", 2, &p_sortBy, "(a -> a -> Ordering) -> [a] -> [a]", "sorted by a comparison");
    defPrim("sortOn", 2, &p_sortOn, "(a -> b) -> [a] -> [a]", "sorted by a key, e.g. sortOn (.name)");
    defPrim("nub", 1, &p_nub, "[a] -> [a]", "without duplicates");
    defPrim("group", 1, &p_group, "[a] -> [[a]]", "runs of equal elements");
    defPrim("groupOn", 2, &p_groupOn, "(a -> k) -> [a] -> [(k, [a])]", "group by a key");
    defPrim("partition", 2, &p_partition, "(a -> Bool) -> [a] -> ([a], [a])", "(passing, failing)");
    defPrim("find", 2, &p_find, "(a -> Bool) -> [a] -> Maybe a", "the first that passes");
    defPrim("count", 2, &p_count, "(a -> Bool) -> [a] -> Int", "how many pass");
    defPrim("intercalate", 2, &p_intercalate, "[a] -> [[a]] -> [a]", "join with a separator");
    defPrim("join", 2, &p_intercalate, "String -> [a] -> String", "join as text with a separator");
    defPrim("intersperse", 2, &p_intersperse, "a -> [a] -> [a]", "put a value between elements");
    // strings
    defPrim("lines", 1, &p_lines, "String -> [String]", "split into lines");
    defPrim("unlines", 1, &p_unlines, "[String] -> String", "join lines");
    defPrim("words", 1, &p_words, "String -> [String]", "split on whitespace");
    defPrim("unwords", 1, &p_unwords, "[String] -> String", "join with spaces");
    defPrim("show", 1, &p_show, "a -> String", "as dash would write it");
    defPrim("text", 1, &p_text, "a -> String", "as text (a String stays as it is)");
    defPrim("read", 1, &p_read, "String -> a", "a number or Bool from text");
    defPrim("readMaybe", 1, &p_readMaybe, "String -> Maybe a", "a number or Bool from text, if it is one");
    defPrim("toUpper", 1, &p_toUpper, "String -> String", "upper case");
    defPrim("toLower", 1, &p_toLower, "String -> String", "lower case");
    defPrim("isPrefixOf", 2, &p_isPrefixOf, "[a] -> [a] -> Bool", "does the second start with the first");
    defPrim("isSuffixOf", 2, &p_isSuffixOf, "[a] -> [a] -> Bool", "does the second end with the first");
    defPrim("isInfixOf", 2, &p_isInfixOf, "[a] -> [a] -> Bool", "does the second contain the first");
    defPrim("strip", 1, &p_strip, "String -> String", "without leading/trailing whitespace");
    defPrim("trim", 1, &p_strip, "String -> String", "without leading/trailing whitespace");
    defPrim("splitOn", 2, &p_splitOn, "String -> String -> [String]", "split on a separator");
    defPrim("replace", 3, &p_replace, "String -> String -> String -> String", "replace old new text");
    defPrim("ord", 1, &p_ord, "Char -> Int", "character code");
    defPrim("chr", 1, &p_chr, "Int -> Char", "character from code");
    defPrim("isDigit", 1, &p_isDigit, "Char -> Bool", "0-9");
    defPrim("isSpace", 1, &p_isSpace, "Char -> Bool", "whitespace");
    defPrim("isAlpha", 1, &p_isAlpha, "Char -> Bool", "a letter");
    defPrim("isUpper", 1, &p_isUpper, "Char -> Bool", "upper case");
    defPrim("isLower", 1, &p_isLower, "Char -> Bool", "lower case");
    defPrim("padLeft", 2, &p_padLeft, "Int -> a -> String", "right-align in n columns");
    defPrim("padRight", 2, &p_padRight, "Int -> a -> String", "left-align in n columns");
    // Maybe / Either / tuples
    defPrim("maybe", 3, &p_maybe, "b -> (a -> b) -> Maybe a -> b", "default or apply");
    defPrim("fromMaybe", 2, &p_fromMaybe, "a -> Maybe a -> a", "the value, or a default");
    defPrim("isJust", 1, &p_isJust, "Maybe a -> Bool", "is it Just");
    defPrim("isNothing", 1, &p_isNothing, "Maybe a -> Bool", "is it Nothing");
    defPrim("fromJust", 1, &p_fromJust, "Maybe a -> a", "the value of a Just");
    defPrim("catMaybes", 1, &p_catMaybes, "[Maybe a] -> [a]", "the Just values");
    defPrim("mapMaybe", 2, &p_mapMaybe, "(a -> Maybe b) -> [a] -> [b]", "map, keeping the Just results");
    defPrim("either", 3, &p_either, "(a -> c) -> (b -> c) -> Either a b -> c", "apply to Left or Right");
    defPrim("fst", 1, &p_fst, "(a, b) -> a", "first of a pair");
    defPrim("snd", 1, &p_snd, "(a, b) -> b", "second of a pair");
    defPrim("swap", 1, &p_swap, "(a, b) -> (b, a)", "swap a pair");
    defPrim("curry", 3, &p_curry, "((a, b) -> c) -> a -> b -> c", "curry");
    defPrim("uncurry", 2, &p_uncurry, "(a -> b -> c) -> (a, b) -> c", "uncurry");
    // records
    defPrim("keys", 1, &p_keys, "Record -> [String]", "field names");
    defPrim("values", 1, &p_values, "Record -> [a]", "field values");
    defPrim("get", 2, &p_get, "String -> Record -> a", "a field (or member) by name");
    defPrim("set", 3, &p_set, "String -> a -> Record -> Record", "a record with a field set");
    defPrim("has", 2, &p_has, "String -> Record -> Bool", "does it have the field");
    defPrim("toPairs", 1, &p_toPairs, "Record -> [(String, a)]", "fields as pairs");
    defPrim("fromPairs", 1, &p_fromPairs, "[(String, a)] -> Record", "a record from pairs");
    // effects
    defPrim("putStrLn", 1, &p_putStrLn, "a -> ()", "print as text, with a newline");
    defPrim("putStr", 1, &p_putStr, "a -> ()", "print as text");
    defPrim("print", 1, &p_print, "a -> ()", "print as dash writes it");
    defPrim("readFile", 1, &p_readFile, "String -> String", "a file's contents");
    defPrim("readLines", 1, &p_readLines, "String -> [String]", "a file's lines");
    defPrim("writeFile", 2, &p_writeFile, "String -> a -> ()", "write text (a list: one element per line)");
    defPrim("appendFile", 2, &p_appendFile, "String -> a -> ()", "append text");
    defPrim("exists", 1, &p_exists, "String -> Bool", "does the path exist");
    defPrim("isDir", 1, &p_isDir, "String -> Bool", "is it a directory");
    defPrim("listDir", 1, &p_listDir, "String -> [String]", "a directory's entries, sorted");
    defPrim("run", 1, &p_run, "String -> [String]", "run a command line, its output lines");
    defPrim("sh", 1, &p_sh, "String -> Int", "run a command line on the terminal, its exit status");
    defPrim("lastStatus", 0, &p_status, "Int", "the exit status of the last command");
    defPrim("env", 1, &p_env, "String -> Maybe String", "an environment variable");
    defPrim("setEnv", 2, &p_setEnv, "String -> a -> ()", "set an environment variable");
    defPrim("cwd", 0, &p_cwd, "String", "the current directory");
    defPrim("now", 0, &p_now, "Int", "seconds since 1970");
    defPrim("sleep", 1, &p_sleep, "Float -> ()", "pause (seconds)");
    defPrim("exit", 1, &p_exit, "Int -> ()", "leave dash with a status");
    defPrim("mapM_", 2, &p_mapM_, "(a -> b) -> [a] -> ()", "run for each element");
    defPrim("forM_", 2, &p_forM_, "[a] -> (a -> b) -> ()", "run for each element");
    defPrim("mapM", 2, &p_mapM, "(a -> b) -> [a] -> [b]", "run for each element, collect the results");
    defPrim("forM", 2, &p_forM, "[a] -> (a -> b) -> [b]", "run for each element, collect the results");
    defPrim("when", 2, &p_when, "Bool -> (() -> a) -> ()", "run a function of () when True");
    defPrim("typeOf", 1, &p_typeOf, "a -> String", "the type of a value");
    defPrim("members", 1, &p_members, "a -> [String]", "the fields and methods of a value");

    // base-type methods (x.name): the explorable surface of ordinary values
    defMethod("String", "length", 0, &p_length, "Int", "number of characters");
    defMethod("String", "upper", 0, &m_upper, "String", "upper case");
    defMethod("String", "lower", 0, &m_lower, "String", "lower case");
    defMethod("String", "trim", 0, &p_strip, "String", "without surrounding whitespace");
    defMethod("String", "lines", 0, &p_lines, "[String]", "split into lines");
    defMethod("String", "words", 0, &p_words, "[String]", "split on whitespace");
    defMethod("String", "reverse", 0, &p_reverse, "String", "reversed");
    defMethod("String", "toInt", 0, &p_read, "Int", "the number it spells");
    defMethod("String", "split", 1, &m_split, "String -> [String]", "split on a separator");
    defMethod("String", "startsWith", 1, &m_startsWith, "String -> Bool", "does it start with");
    defMethod("String", "endsWith", 1, &m_endsWith, "String -> Bool", "does it end with");
    defMethod("String", "contains", 1, &m_contains, "String -> Bool", "does it contain");
    defMethod("String", "replace", 2, &m_replace, "String -> String -> String", "replace old new");
    defMethod("List", "length", 0, &p_length, "Int", "number of elements");
    defMethod("List", "head", 0, &p_head, "a", "the first element");
    defMethod("List", "last", 0, &p_last, "a", "the last element");
    defMethod("List", "tail", 0, &p_tail, "[a]", "all but the first");
    defMethod("List", "reverse", 0, &p_reverse, "[a]", "reversed");
    defMethod("List", "sort", 0, &p_sort, "[a]", "sorted");
    defMethod("List", "sum", 0, &p_sum, "a", "sum");
    defMethod("List", "unique", 0, &p_nub, "[a]", "without duplicates");
    defMethod("List", "null", 0, &p_null, "Bool", "is it empty");
    defMethod("List", "map", 1, &m_map, "(a -> b) -> [b]", "apply to every element");
    defMethod("List", "filter", 1, &m_filter, "(a -> Bool) -> [a]", "keep what passes");
    defMethod("List", "take", 1, &m_take, "Int -> [a]", "the first n");
    defMethod("List", "drop", 1, &m_drop, "Int -> [a]", "all but the first n");
    defMethod("List", "sortOn", 1, &m_sortOn, "(a -> b) -> [a]", "sorted by a key");
    defMethod("List", "join", 1, &m_join, "String -> String", "joined as text with a separator");
    defMethod("List", "count", 1, &m_count, "(a -> Bool) -> Int", "how many pass");
    defMethod("Record", "keys", 0, &p_keys, "[String]", "field names");
    defMethod("Record", "values", 0, &p_values, "[a]", "field values");
    defMethod("Int", "toFloat", 0, &p_toFloat, "Float", "as a Float");
    defMethod("Int", "even", 0, &p_even, "Bool", "is it even");
    defMethod("Int", "odd", 0, &p_odd, "Bool", "is it odd");
    defMethod("Float", "round", 0, &p_round, "Int", "nearest Int");
    defMethod("Float", "floor", 0, &p_floor, "Int", "round down");
    defMethod("Float", "ceiling", 0, &p_ceiling, "Int", "round up");
}
// methods take (self, args...): adapt to the prims' (args..., self) order
private Value* swapCall(Value** a, PrimFn f, size_t nargs) {
    auto b = newItems(nargs + 1);
    foreach (k; 0 .. nargs) b[k] = a[k + 1];
    b[nargs] = a[0];
    return f(b, null);
}
private Value* m_split(Value** a, void* c) { return swapCall(a, &p_splitOn, 1); }
private Value* m_startsWith(Value** a, void* c) { return swapCall(a, &p_isPrefixOf, 1); }
private Value* m_endsWith(Value** a, void* c) { return swapCall(a, &p_isSuffixOf, 1); }
private Value* m_contains(Value** a, void* c) { return swapCall(a, &p_isInfixOf, 1); }
private Value* m_replace(Value** a, void* c) { return swapCall(a, &p_replace, 2); }
private Value* m_map(Value** a, void* c) { return swapCall(a, &p_map, 1); }
private Value* m_filter(Value** a, void* c) { return swapCall(a, &p_filter, 1); }
private Value* m_take(Value** a, void* c) { return swapCall(a, &p_take, 1); }
private Value* m_drop(Value** a, void* c) { return swapCall(a, &p_drop, 1); }
private Value* m_sortOn(Value** a, void* c) { return swapCall(a, &p_sortOn, 1); }
private Value* m_join(Value** a, void* c) { return swapCall(a, &p_intercalate, 1); }
private Value* m_count(Value** a, void* c) { return swapCall(a, &p_count, 1); }
