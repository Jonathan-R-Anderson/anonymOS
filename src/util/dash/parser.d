// dash parser: the Haskell half (expressions, patterns, definitions) with the layout rule, plus the
// do-block items that are commands.
module dash.parser;

import dash.rt;
import dash.ast;
import dash.lexer;

// Asked while parsing a do block: is this first word a dash name (then the line is an expression)
// or a command?  Supplied by the evaluator, which knows the environment and $PATH.
alias NameClassFn = int function(const(char)[] name) @nogc nothrow;   // 0 unknown, 1 dash, 2 command, 3 user dash
__gshared NameClassFn g_nameClass;

enum : ubyte { VSEMI = 200, VCLOSE = 201 }

struct Parser {
    const(char)[] src;
    Vec!Tok toks;
    size_t pos;
    Vec!int layout;          // block columns (-1: an explicit { } block)
    size_t vsemiDone = size_t.max;   // the token whose virtual ';' was already consumed
    Vec!Sym scope_;          // locally bound names (for the command/expression decision)
    bool failed;

    @nogc nothrow:

    bool init(const(char)[] s) { src = s; pos = 0; return lex(s, toks); }
    void dispose() { toks.dispose(); layout.dispose(); scope_.dispose(); }

    ref Tok tok() { return toks[pos]; }
    ubyte kind() {
        auto t = &toks[pos];
        if (layout.n && t.lineStart && t.t != T.EOF && pos != vsemiDone) {
            const bc = layout.back();
            if (bc >= 0) {
                if (cast(int)t.col == bc) return VSEMI;
                if (cast(int)t.col < bc) return VCLOSE;
            }
        }
        return t.t;
    }
    void next() { if (toks[pos].t != T.EOF) ++pos; }
    bool at(T t) { return kind() == t; }
    bool accept(T t) { if (kind() == t) { next(); return true; } return false; }
    bool expect(T t, const(char)[] what) {
        if (kind() == t) { next(); return true; }
        return fail("expected ", what);
    }
    bool fail(const(char)[] a, const(char)[] b = null) {
        if (!failed) {
            failed = true;
            Buf m; m.put(a); m.put(b);
            const t = &toks[pos];
            char[64] where;
            const k = snprintf(where.ptr, where.length, " (line %u, col %u", t.line, t.col + 1);
            m.put(where[0 .. k]);
            if (t.t == T.EOF) m.put(", at end of input)");
            else { m.put(", near '"); m.put(t.s.length > 20 ? t.s[0 .. 20] : t.s); m.put("')"); }
            setErr("parse error: ", m.str());
            m.dispose();
        }
        return false;
    }
    bool atBoundary() {
        const k = kind();
        return k == VSEMI || k == VCLOSE || k == T.EOF || k == T.Semi || k == T.RParen || k == T.RBracket ||
               k == T.RBrace || k == T.Comma || k == T.KwIn || k == T.KwThen || k == T.KwElse || k == T.KwOf ||
               k == T.KwWhere || k == T.Equals || k == T.Pipe || k == T.Arrow || k == T.DotDot || k == T.LArrow ||
               k == T.DColon;
    }

    // ── blocks (layout) ──────────────────────────────────────────────────────────────────────
    // Parse the items of a block opened by where/let/of/do.  `item` parses one item; returns false.
    bool block(scope bool delegate() @nogc nothrow item) {
        if (kind() == T.LBrace) {
            next();
            layout.push(-1);
            while (!at(T.RBrace) && !at(T.EOF)) {
                if (accept(T.Semi)) continue;
                if (!item()) { layout.pop(); return false; }
                if (!at(T.RBrace) && !accept(T.Semi)) { layout.pop(); return fail("expected ';' or '}'"); }
            }
            layout.pop();
            return expect(T.RBrace, "'}'");
        }
        if (at(T.EOF)) return true;                          // an empty block
        const col = cast(int)toks[pos].col;
        const outer = layout.n ? layout.back() : -2;
        if (col <= outer && toks[pos].lineStart) return true; // nothing indented: empty block
        layout.push(col);
        vsemiDone = pos;                                     // the first item needs no separator
        for (;;) {
            if (!item()) { layout.pop(); return false; }
            const k = kind();
            if (k == VSEMI) { vsemiDone = pos; continue; }
            if (k == T.Semi) { next(); if (kind() == VSEMI) vsemiDone = pos; continue; }
            break;                                           // VCLOSE / EOF / a closing token
        }
        layout.pop();
        return true;
    }

    // ── expressions ──────────────────────────────────────────────────────────────────────────
    Node* expr() {
        auto e = opExpr(-2);
        if (e && accept(T.DColon)) skipType();              // (e :: T): annotations are ignored
        return e;
    }
    void skipType() { while (!atBoundary()) { if (at(T.LParen) || at(T.LBracket)) skipGroup(); else next(); } }
    void skipGroup() {
        int d = 0;
        do {
            if (at(T.LParen) || at(T.LBracket) || at(T.LBrace)) ++d;
            else if (at(T.RParen) || at(T.RBracket) || at(T.RBrace)) --d;
            next();
        } while (d > 0 && !at(T.EOF));
    }

    // operator name + precedence + associativity (0 left, 1 right, 2 none)
    bool opAt(out const(char)[] name, out int prec, out int assoc) {
        const k = kind();
        if (k == T.Op) name = tok().s;
        else if (k == T.BackOp) name = tok().s;
        else return false;
        fixity(name, k == T.BackOp, prec, assoc);
        return true;
    }
    static void fixity(const(char)[] n, bool back, out int prec, out int assoc) {
        assoc = 0; prec = 9;
        switch (n) {
            case "|>": prec = -1; assoc = 0; break;
            case "$": prec = 0; assoc = 1; break;
            case ">>=": case ">>": prec = 1; assoc = 0; break;
            case "||": prec = 2; assoc = 1; break;
            case "&&": prec = 3; assoc = 1; break;
            case "==": case "/=": case "<": case "<=": case ">": case ">=": prec = 4; assoc = 2; break;
            case "elem": case "notElem": prec = 4; assoc = 2; break;
            case "<$>": case "<&>": prec = 4; assoc = 0; break;
            case ":": case "++": case "<>": prec = 5; assoc = 1; break;
            case "+": case "-": prec = 6; assoc = 0; break;
            case "*": case "/": case "div": case "mod": case "rem": case "quot": prec = 7; assoc = 0; break;
            case "^": case "**": case "^^": prec = 8; assoc = 1; break;
            case ".": prec = 9; assoc = 1; break;
            case "!!": prec = 9; assoc = 0; break;
            default: prec = back ? 9 : 9; assoc = 0; break;
        }
    }

    Node* opExpr(int minPrec) {
        auto lhs = unary();
        if (!lhs) return null;
        for (;;) {
            const(char)[] name; int prec, assoc;
            if (!opAt(name, prec, assoc) || prec < minPrec) break;
            const line = tok().line, col = tok().col;
            next();
            auto rhs = opExpr(assoc == 1 ? prec : prec + 1);
            if (!rhs) return null;
            lhs = binop(name, lhs, rhs, line, col);
        }
        return lhs;
    }
    Node* binop(const(char)[] name, Node* l, Node* r, uint line, uint col) {
        if (name == "$") { auto n = mkNode(NK.App, line, col); n.a = l; n.kids = one(r); return n; }
        if (name == "|>") { auto n = mkNode(NK.App, line, col); n.a = r; n.kids = one(l); return n; }
        auto f = mkNode(NK.Var, line, col); f.sym = intern(name);
        auto n = mkNode(NK.App, line, col); n.a = f;
        auto ks = cast(Node**)malloc(2 * (Node*).sizeof); ks[0] = l; ks[1] = r;
        n.kids = ks[0 .. 2];
        return n;
    }
    static Node*[] one(Node* x) { auto ks = cast(Node**)malloc((Node*).sizeof); ks[0] = x; return ks[0 .. 1]; }

    Node* unary() {
        if (kind() == T.Op && tok().s == "-") {
            const line = tok().line, col = tok().col;
            next();
            auto e = app();
            if (!e) return null;
            if (e.k == NK.Int) { e.i = -e.i; return e; }
            if (e.k == NK.Float) { e.f = -e.f; return e; }
            auto n = mkNode(NK.Neg, line, col); n.a = e; return n;
        }
        return app();
    }

    bool startsAexp() {
        switch (kind()) {
            case T.Int, T.Float, T.Str, T.Char, T.VarId, T.ConId, T.LParen, T.LBracket, T.LBrace,
                 T.CmdSub, T.Lambda, T.KwIf, T.KwCase, T.KwLet, T.KwDo:
                return true;
            default: return false;
        }
    }
    Node* app() {
        auto f = aexp();
        if (!f) return null;
        Vec!(Node*) args;
        while (startsAexp()) {
            // record update binds to the preceding atom, handled in aexp; a block argument
            // (lambda/if/case/let/do) extends to the end and ends the application
            const blockArg = kind() == T.Lambda || kind() == T.KwIf || kind() == T.KwCase ||
                             kind() == T.KwLet || kind() == T.KwDo;
            auto a = aexp();
            if (!a) { args.dispose(); return null; }
            args.push(a);
            if (blockArg) break;
        }
        if (args.n == 0) return f;
        auto n = mkNode(NK.App, f.line, f.col); n.a = f; n.kids = permSlice(args);
        return n;
    }

    Node* aexp() {
        auto e = atom();
        if (!e) return null;
        for (;;) {
            if (kind() == T.DotField && !tok().spaceBefore) {
                if (e.k == NK.Con && e.kids.length == 0) {       // Domain.start: a type member
                    auto n = mkNode(NK.TypeMember, e.line, e.col); n.sym = e.sym; n.keys = oneSym(intern(tok().s));
                    next(); e = n; continue;
                }
                auto n = mkNode(NK.Field, e.line, e.col); n.a = e; n.sym = intern(tok().s);
                next(); e = n; continue;
            }
            if (kind() == T.LBrace && e.k != NK.Con && isRecordBraces()) {  // r { f = e }
                auto n = mkNode(NK.RecUpd, e.line, e.col); n.a = e;
                if (!recordFields(n)) return null;
                e = n; continue;
            }
            break;
        }
        return e;
    }
    static Sym[] oneSym(Sym s) { auto p = cast(Sym*)malloc(Sym.sizeof); p[0] = s; return p[0 .. 1]; }

    // { name = ... } (a record) rather than a block
    bool isRecordBraces() {
        if (pos + 2 >= toks.n) return false;
        if (toks[pos + 1].t == T.RBrace) return true;
        return toks[pos + 1].t == T.VarId && toks[pos + 2].t == T.Equals;
    }
    bool recordFields(Node* n) {
        next();   // {
        Vec!Sym ks; Vec!(Node*) vs;
        while (!at(T.RBrace)) {
            if (!at(T.VarId)) { ks.dispose(); vs.dispose(); return fail("expected a field name"); }
            const k = intern(tok().s); next();
            Node* v;
            if (accept(T.Equals)) { v = expr(); if (!v) { ks.dispose(); vs.dispose(); return false; } }
            else { v = mkNode(NK.Var); v.sym = k; }           // { name } punning
            ks.push(k); vs.push(v);
            if (!accept(T.Comma)) break;
        }
        n.keys = permSlice(ks); n.kids = permSlice(vs);
        return expect(T.RBrace, "'}'");
    }

    Node* atom() {
        const t = &toks[pos];
        const line = t.line, col = t.col;
        switch (kind()) {
            case T.Int: { auto n = mkNode(NK.Int, line, col); n.i = t.i; next(); return n; }
            case T.Float: { auto n = mkNode(NK.Float, line, col); n.f = t.f; next(); return n; }
            case T.Str: { auto n = mkNode(NK.Str, line, col); n.s = t.s; next(); return n; }
            case T.Char: { auto n = mkNode(NK.Char, line, col); n.i = t.i; next(); return n; }
            case T.VarId: { auto n = mkNode(NK.Var, line, col); n.sym = intern(t.s); next(); return n; }
            case T.ConId: { auto n = mkNode(NK.Con, line, col); n.sym = intern(t.s); next(); return n; }
            case T.CmdSub: { auto n = mkNode(NK.CmdSub, line, col); n.s = permDup(t.s); next(); return n; }
            case T.LParen: return paren();
            case T.LBracket: return bracket();
            case T.LBrace: {
                auto n = mkNode(NK.Rec, line, col);
                if (!recordFields(n)) return null;
                return n;
            }
            case T.Lambda: return lambda();
            case T.KwIf: {
                next();
                auto c = expr(); if (!c) return null;
                accept(T.Semi); if (kind() == VSEMI) vsemiDone = pos;
                if (!expect(T.KwThen, "'then'")) return null;
                auto a = expr(); if (!a) return null;
                accept(T.Semi); if (kind() == VSEMI) vsemiDone = pos;
                if (!expect(T.KwElse, "'else'")) return null;
                auto b = expr(); if (!b) return null;
                auto n = mkNode(NK.If, line, col); n.a = c; n.b = a; n.c = b; return n;
            }
            case T.KwCase: {
                next();
                auto scr = expr(); if (!scr) return null;
                if (!expect(T.KwOf, "'of'")) return null;
                Vec!(Alt*) alts;
                bool okb = block(delegate bool() @nogc nothrow {
                    auto al = pnew!Alt();
                    al.pat = pattern(); if (!al.pat) return false;
                    if (at(T.Pipe)) {
                        Vec!(Guard*) gs;
                        while (accept(T.Pipe)) {
                            auto g = pnew!Guard(); g.cond = expr(); if (!g.cond) return false;
                            if (!expect(T.Arrow, "'->'")) return false;
                            g.body = expr(); if (!g.body) return false;
                            gs.push(g);
                        }
                        al.guards = permSlice(gs);
                    } else {
                        if (!expect(T.Arrow, "'->'")) return false;
                        al.body = expr(); if (!al.body) return false;
                    }
                    if (accept(T.KwWhere)) { if (!decls(al.wheres)) return false; }
                    alts.push(al);
                    return true;
                });
                if (!okb) { alts.dispose(); return null; }
                auto n = mkNode(NK.Case, line, col); n.a = scr; n.alts = permSlice(alts); return n;
            }
            case T.KwLet: {
                next();
                auto n = mkNode(NK.Let, line, col);
                if (!decls(n.decls)) return null;
                accept(T.Semi); if (kind() == VSEMI) vsemiDone = pos;
                if (!expect(T.KwIn, "'in'")) return null;
                n.a = expr(); if (!n.a) return null;
                return n;
            }
            case T.KwDo: return doBlock();
            case VSEMI: case VCLOSE: return fail("unexpected end of expression") ? null : null;
            default: {
                if (t.t == T.Op) return fail("unexpected operator '", t.s) ? null : null;
                return fail("unexpected token") ? null : null;
            }
        }
    }

    Node* paren() {
        const line = tok().line, col = tok().col;
        next();
        if (accept(T.RParen)) return mkNode(NK.Unit, line, col);
        // (.name)
        if (kind() == T.DotField) {
            auto n = mkNode(NK.FieldSel, line, col); n.sym = intern(tok().s); next();
            if (!expect(T.RParen, "')'")) return null;
            return n;
        }
        // (op) and (op e): a right section.  "(- e)" is negation, as in Haskell.
        if ((kind() == T.Op && tok().s != "-") || kind() == T.BackOp) {
            const name = tok().s; next();
            if (accept(T.RParen)) { auto n = mkNode(NK.OpFn, line, col); n.sym = intern(name); return n; }
            auto e = opExpr(-2); if (!e) return null;
            if (!expect(T.RParen, "')'")) return null;
            auto n = mkNode(NK.SectionR, line, col); n.sym = intern(name); n.a = e; return n;
        }
        if (kind() == T.Op && tok().s == "-" && pos + 1 < toks.n && toks[pos + 1].t == T.RParen) {
            next(); next(); auto n = mkNode(NK.OpFn, line, col); n.sym = intern("-"); return n;
        }
        // (e op): a left section -- parse an expression, then see if an operator is left dangling
        auto first = sectionOrExpr();
        if (!first) return null;
        if (first.k == NK.SectionL) { if (!expect(T.RParen, "')'")) return null; return first; }
        if (accept(T.RParen)) return first;
        if (at(T.Comma)) {
            Vec!(Node*) items; items.push(first);
            while (accept(T.Comma)) { auto e = expr(); if (!e) { items.dispose(); return null; } items.push(e); }
            if (!expect(T.RParen, "')'")) { items.dispose(); return null; }
            auto n = mkNode(NK.Tuple, line, col); n.kids = permSlice(items); return n;
        }
        return fail("expected ')'") ? null : null;
    }
    // An expression, or "e op" followed by ')' (a left section).
    Node* sectionOrExpr() {
        auto lhs = unary();
        if (!lhs) return null;
        for (;;) {
            const(char)[] name; int prec, assoc;
            if (!opAt(name, prec, assoc)) break;
            const line = tok().line, col = tok().col;
            next();
            if (at(T.RParen)) { auto n = mkNode(NK.SectionL, line, col); n.sym = intern(name); n.a = lhs; return n; }
            auto rhs = opExpr(assoc == 1 ? prec : prec + 1);
            if (!rhs) return null;
            lhs = binop(name, lhs, rhs, line, col);
            // keep climbing at any precedence: the parentheses delimit it
            lhs = climbRest(lhs);
            if (!lhs) return null;
            if (at(T.RParen) || at(T.Comma)) break;
        }
        if (lhs && accept(T.DColon)) skipType();
        return lhs;
    }
    Node* climbRest(Node* lhs) {
        for (;;) {
            const(char)[] name; int prec, assoc;
            if (!opAt(name, prec, assoc)) return lhs;
            if (pos + 1 < toks.n && toks[pos + 1].t == T.RParen) return lhs;   // dangling: a section
            const line = tok().line, col = tok().col;
            next();
            auto rhs = opExpr(assoc == 1 ? prec : prec + 1);
            if (!rhs) return null;
            lhs = binop(name, lhs, rhs, line, col);
        }
    }

    Node* bracket() {
        const line = tok().line, col = tok().col;
        next();
        if (accept(T.RBracket)) { auto n = mkNode(NK.List, line, col); return n; }
        auto first = expr(); if (!first) return null;
        if (accept(T.DotDot)) {                                  // [a..b]
            auto n = mkNode(NK.Range, line, col); n.a = first;
            if (at(T.RBracket)) return fail("infinite ranges are not supported (dash is strict); give an end") ? null : null;
            n.c = expr(); if (!n.c) return null;
            if (!expect(T.RBracket, "']'")) return null;
            return n;
        }
        if (at(T.Pipe)) {                                        // [e | quals]
            next();
            auto n = mkNode(NK.Comp, line, col); n.a = first;
            Vec!(Qual*) qs;
            for (;;) {
                auto q = pnew!Qual();
                if (at(T.KwLet)) { next(); q.k = QK.Let; if (!decls(q.decls)) { qs.dispose(); return null; } }
                else if (genAhead()) {
                    q.k = QK.Gen; q.pat = pattern(); if (!q.pat) { qs.dispose(); return null; }
                    if (!expect(T.LArrow, "'<-'")) { qs.dispose(); return null; }
                    q.e = expr(); if (!q.e) { qs.dispose(); return null; }
                } else { q.k = QK.Guard; q.e = expr(); if (!q.e) { qs.dispose(); return null; } }
                qs.push(q);
                if (!accept(T.Comma)) break;
            }
            n.quals = permSlice(qs);
            if (!expect(T.RBracket, "']'")) return null;
            return n;
        }
        Vec!(Node*) items; items.push(first);
        if (accept(T.Comma)) {
            auto second = expr(); if (!second) { items.dispose(); return null; }
            if (accept(T.DotDot)) {                              // [a,b..c]
                items.dispose();
                auto n = mkNode(NK.Range, line, col); n.a = first; n.b = second;
                n.c = expr(); if (!n.c) return null;
                if (!expect(T.RBracket, "']'")) return null;
                return n;
            }
            items.push(second);
            while (accept(T.Comma)) { auto e = expr(); if (!e) { items.dispose(); return null; } items.push(e); }
        }
        if (!expect(T.RBracket, "']'")) { items.dispose(); return null; }
        auto n = mkNode(NK.List, line, col); n.kids = permSlice(items); return n;
    }
    // Is there a '<-' before the next ',' / ']' at this depth?
    bool genAhead() {
        int d = 0;
        foreach (j; pos .. toks.n) {
            const t = toks[j].t;
            if (t == T.LParen || t == T.LBracket || t == T.LBrace) ++d;
            else if (t == T.RParen || t == T.RBracket || t == T.RBrace) { if (d == 0) return false; --d; }
            else if (d == 0 && t == T.Comma) return false;
            else if (d == 0 && t == T.LArrow) return true;
            else if (t == T.EOF) return false;
        }
        return false;
    }

    Node* lambda() {
        const line = tok().line, col = tok().col;
        next();
        Vec!(Pat*) ps;
        const mark = scope_.n;
        while (!at(T.Arrow)) {
            auto p = apat(); if (!p) { ps.dispose(); return null; }
            bindPat(p);
            ps.push(p);
        }
        next();
        auto body = expr();
        scope_.n = mark;
        if (!body) { ps.dispose(); return null; }
        auto n = mkNode(NK.Lam, line, col); n.pats = permSlice(ps); n.a = body; return n;
    }
    void bindPat(Pat* p) {
        if (p is null) return;
        if (p.k == PK.Var || p.k == PK.As) scope_.push(p.sym);
        foreach (k; p.kids) bindPat(k);
    }

    // ── do blocks: a statement per item; commands keep their source text ─────────────────────
    Node* doBlock() {
        const line = tok().line, col = tok().col;
        next();
        auto n = mkNode(NK.Do, line, col);
        Vec!(Stmt*) ss;
        const mark = scope_.n;
        bool ok = block(delegate bool() @nogc nothrow {
            auto st = pnew!Stmt();
            if (at(T.KwLet)) {
                next(); st.k = SK.Let;
                if (!decls(st.decls)) return false;
                foreach (d; st.decls) if (d.k == DK.Fun || d.k == DK.PatBind) { if (d.k == DK.Fun) scope_.push(d.name); else bindPat(d.pat); }
                ss.push(st); return true;
            }
            const end = itemEnd();
            // "pat <- rhs"
            size_t arrow = size_t.max;
            { int d = 0; foreach (j; pos .. end) { const t = toks[j].t;
                if (t == T.LParen || t == T.LBracket || t == T.LBrace) ++d;
                else if (t == T.RParen || t == T.RBracket || t == T.RBrace) --d;
                else if (d == 0 && t == T.LArrow) { arrow = j; break; } } }
            if (arrow != size_t.max) {
                st.k = SK.Bind;
                st.pat = pattern(); if (!st.pat) return false;
                if (!expect(T.LArrow, "'<-'")) return false;
                st.e = itemBody(end); if (!st.e) return false;
                bindPat(st.pat);
                ss.push(st); return true;
            }
            st.e = itemBody(end); if (!st.e) return false;
            st.k = st.e.k == NK.Cmd ? SK.Cmd : SK.Expr;
            ss.push(st); return true;
        });
        scope_.n = mark;
        if (!ok) { ss.dispose(); return null; }
        n.stmts = permSlice(ss);
        return n;
    }
    // The token index where the current block item ends.
    size_t itemEnd() {
        const bc = layout.n ? layout.back() : -1;
        int d = 0;
        foreach (j; pos .. toks.n) {
            const t = &toks[j];
            if (t.t == T.EOF) return j;
            if (j > pos && d == 0 && t.lineStart && bc >= 0 && cast(int)t.col <= bc) return j;
            if (t.t == T.LParen || t.t == T.LBracket || t.t == T.LBrace) ++d;
            else if (t.t == T.RParen || t.t == T.RBracket || t.t == T.RBrace) { if (d == 0) return j; --d; }
            else if (d == 0 && t.t == T.Semi) return j;
        }
        return toks.n - 1;
    }
    // A do item from here to `end`: a command (raw text) or an expression.
    Node* itemBody(size_t end) {
        if (end > pos && isCommandStart(pos, end)) {
            auto n = mkNode(NK.Cmd, tok().line, tok().col);
            n.s = permDup(src[toks[pos].off .. toks[end - 1].end]);
            pos = end;
            return n;
        }
        return expr();
    }
    bool isCommandStart(size_t st, size_t end) {
        const t = &toks[st];
        switch (t.t) {
            case T.Int, T.Float, T.Str, T.Char, T.ConId, T.LParen, T.LBracket, T.LBrace, T.Lambda,
                 T.KwIf, T.KwCase, T.KwLet, T.KwDo, T.CmdSub:
                return false;
            case T.VarId: {
                const s = intern(t.s);
                foreach (b; scope_[]) if (b == s) return false;   // a local binding
                // "x.field" / "f x" with dash names: expression; otherwise ask
                const c = g_nameClass ? g_nameClass(t.s) : 0;
                if (c == 3) return false;                          // user-defined dash name
                if (c == 2) return true;                           // a command / shell builtin
                if (c == 1) return false;                          // a library name
                return false;                                      // unknown: a dash name defined later
            }
            default: return true;                                  // ./x, /bin/y, ~, $VAR, 'quoted' ...
        }
    }

    // ── patterns ─────────────────────────────────────────────────────────────────────────────
    Pat* pattern() {
        auto p = pat10();
        if (!p) return null;
        if (kind() == T.Op && tok().s == ":") {               // x : xs (right associative)
            next();
            auto rest = pattern(); if (!rest) return null;
            auto c = mkPat(PK.Cons);
            auto ks = cast(Pat**)malloc(2 * (Pat*).sizeof); ks[0] = p; ks[1] = rest; c.kids = ks[0 .. 2];
            return c;
        }
        return p;
    }
    Pat* pat10() {
        if (kind() == T.ConId) {
            const name = intern(tok().s); next();
            Vec!(Pat*) args;
            while (startsApat()) { auto a = apat(); if (!a) { args.dispose(); return null; } args.push(a); }
            auto p = mkPat(PK.Con); p.sym = name; p.kids = permSlice(args); return p;
        }
        if (kind() == T.Op && tok().s == "-" && pos + 1 < toks.n && (toks[pos + 1].t == T.Int || toks[pos + 1].t == T.Float)) {
            next(); auto p = apat(); if (p.k == PK.Int) p.i = -p.i; else p.f = -p.f; return p;
        }
        return apat();
    }
    bool startsApat() {
        switch (kind()) {
            case T.VarId, T.ConId, T.Int, T.Float, T.Str, T.Char, T.LParen, T.LBracket, T.LBrace: return true;
            default: return false;
        }
    }
    Pat* apat() {
        const t = &toks[pos];
        switch (kind()) {
            case T.VarId: {
                if (t.s == "_") { next(); return mkPat(PK.Wild); }
                const name = intern(t.s); next();
                if (accept(T.At)) {
                    auto inner = apat(); if (!inner) return null;
                    auto p = mkPat(PK.As); p.sym = name;
                    auto ks = cast(Pat**)malloc((Pat*).sizeof); ks[0] = inner; p.kids = ks[0 .. 1];
                    return p;
                }
                auto p = mkPat(PK.Var); p.sym = name; return p;
            }
            case T.ConId: { auto p = mkPat(PK.Con); p.sym = intern(t.s); next(); return p; }
            case T.Int: { auto p = mkPat(PK.Int); p.i = t.i; next(); return p; }
            case T.Float: { auto p = mkPat(PK.Float); p.f = t.f; next(); return p; }
            case T.Str: { auto p = mkPat(PK.Str); p.s = t.s; next(); return p; }
            case T.Char: { auto p = mkPat(PK.Char); p.i = t.i; next(); return p; }
            case T.LParen: {
                next();
                if (accept(T.RParen)) return mkPat(PK.Unit);
                auto first = pattern(); if (!first) return null;
                if (accept(T.RParen)) return first;
                Vec!(Pat*) items; items.push(first);
                while (accept(T.Comma)) { auto p = pattern(); if (!p) { items.dispose(); return null; } items.push(p); }
                if (!expect(T.RParen, "')'")) { items.dispose(); return null; }
                auto p = mkPat(PK.Tuple); p.kids = permSlice(items); return p;
            }
            case T.LBracket: {
                next();
                Vec!(Pat*) items;
                while (!at(T.RBracket)) {
                    auto p = pattern(); if (!p) { items.dispose(); return null; }
                    items.push(p);
                    if (!accept(T.Comma)) break;
                }
                if (!expect(T.RBracket, "']'")) { items.dispose(); return null; }
                auto p = mkPat(PK.List); p.kids = permSlice(items); return p;
            }
            case T.LBrace: {                                    // { name = p, size }
                next();
                Vec!Sym ks; Vec!(Pat*) ps;
                while (at(T.VarId)) {
                    const k = intern(tok().s); next();
                    Pat* p;
                    if (accept(T.Equals)) { p = pattern(); if (!p) { ks.dispose(); ps.dispose(); return null; } }
                    else { p = mkPat(PK.Var); p.sym = k; }
                    ks.push(k); ps.push(p);
                    if (!accept(T.Comma)) break;
                }
                if (!expect(T.RBrace, "'}'")) { ks.dispose(); ps.dispose(); return null; }
                auto p = mkPat(PK.Rec); p.keys = permSlice(ks); p.kids = permSlice(ps); return p;
            }
            default: return fail("expected a pattern") ? null : null;
        }
    }

    // ── declarations ─────────────────────────────────────────────────────────────────────────
    bool decls(ref Decl*[] outd) {
        Vec!(Decl*) ds;
        bool ok = block(delegate bool() @nogc nothrow {
            auto d = decl(); if (!d) return false;
            ds.push(d); return true;
        });
        if (!ok) { ds.dispose(); return false; }
        outd = permSlice(ds);
        return true;
    }

    Decl* decl() {
        auto d = pnew!Decl();
        d.line = tok().line;
        // data T a = C1 .. | C2 ..
        if (at(T.KwData)) return dataDecl(d);
        // f, g :: Type
        if (at(T.VarId) || (at(T.LParen) && pos + 2 < toks.n && toks[pos + 1].t == T.Op && toks[pos + 2].t == T.RParen)) {
            size_t j = pos; Vec!Sym names;
            for (;;) {
                if (toks[j].t == T.VarId) { names.push(intern(toks[j].s)); ++j; }
                else if (toks[j].t == T.LParen && j + 2 < toks.n && toks[j + 1].t == T.Op && toks[j + 2].t == T.RParen) { names.push(intern(toks[j + 1].s)); j += 3; }
                else break;
                if (toks[j].t == T.Comma) { ++j; continue; }
                break;
            }
            if (toks[j].t == T.DColon && names.n) {
                pos = j + 1;
                const st = pos;
                skipType();
                d.k = DK.Sig; d.names = permSlice(names); d.name = d.names[0];
                d.text = permDup(pos > st ? src[toks[st].off .. toks[pos - 1].end] : "");
                return d;
            }
            names.dispose();
        }
        // Type.member self args = ...   (an extension of an object type)
        if (at(T.ConId) && pos + 1 < toks.n && toks[pos + 1].t == T.DotField && !toks[pos + 1].spaceBefore) {
            d.k = DK.Ext; d.type = intern(tok().s); next();
            d.name = intern(tok().s); next();
            Vec!(Pat*) ps;
            const mark = scope_.n;
            while (!at(T.Equals) && !at(T.Pipe)) { auto p = apat(); if (!p) { ps.dispose(); return null; } bindPat(p); ps.push(p); }
            d.params = permSlice(ps);
            const ok = rhs(d.rhs, T.Equals);
            scope_.n = mark;
            return ok ? d : null;
        }
        // f p1 p2 = ... | p1 `op` p2 = ... | p1 <op> p2 = ... | pat = ...
        const save = pos;
        if (at(T.VarId) && !(pos + 1 < toks.n && (toks[pos + 1].t == T.Op || toks[pos + 1].t == T.BackOp) && toks[pos + 1].s != "@")) {
            d.k = DK.Fun; d.name = intern(tok().s); next();
            Vec!(Pat*) ps;
            const mark = scope_.n;
            scope_.push(d.name);
            while (!at(T.Equals) && !at(T.Pipe)) {
                if (!startsApat()) { ps.dispose(); scope_.n = mark; return fail("expected '=' in a definition") ? null : null; }
                auto p = apat(); if (!p) { ps.dispose(); scope_.n = mark; return null; }
                bindPat(p); ps.push(p);
            }
            d.params = permSlice(ps);
            const ok = rhs(d.rhs, T.Equals);
            scope_.n = mark;
            if (d.params.length == 0) { /* a value binding: f = e */ }
            return ok ? d : null;
        }
        pos = save;
        auto lp = pattern(); if (!lp) return null;
        if (kind() == T.Op || kind() == T.BackOp) {             // infix definition
            d.k = DK.Fun; d.name = intern(tok().s); next();
            auto rp = pattern(); if (!rp) return null;
            auto ks = cast(Pat**)malloc(2 * (Pat*).sizeof); ks[0] = lp; ks[1] = rp;
            d.params = ks[0 .. 2];
            const mark = scope_.n; bindPat(lp); bindPat(rp);
            const ok = rhs(d.rhs, T.Equals);
            scope_.n = mark;
            return ok ? d : null;
        }
        d.k = DK.PatBind; d.pat = lp;
        return rhs(d.rhs, T.Equals) ? d : null;
    }

    // "= e [where ..]" or "| g = e | g = e [where ..]"  (sep is '=' for definitions)
    bool rhs(ref Rhs r, T sep) {
        if (at(T.Pipe)) {
            Vec!(Guard*) gs;
            while (accept(T.Pipe)) {
                auto g = pnew!Guard(); g.cond = expr(); if (!g.cond) { gs.dispose(); return false; }
                if (!expect(sep, "'='")) { gs.dispose(); return false; }
                g.body = expr(); if (!g.body) { gs.dispose(); return false; }
                gs.push(g);
                if (kind() == VSEMI && pos + 0 < toks.n && toks[pos].t == T.Pipe) vsemiDone = pos;
            }
            r.guards = permSlice(gs);
        } else {
            if (!expect(sep, "'='")) return false;
            r.body = expr(); if (!r.body) return false;
        }
        if (kind() == VSEMI && toks[pos].t == T.KwWhere) vsemiDone = pos;
        if (accept(T.KwWhere)) { if (!decls(r.wheres)) return false; }
        return true;
    }

    Decl* dataDecl(Decl* d) {
        const st = pos;
        next();
        if (!at(T.ConId)) return fail("expected a type name after 'data'") ? null : null;
        d.k = DK.Data; d.name = intern(tok().s); next();
        while (at(T.VarId)) next();                           // type variables
        if (!expect(T.Equals, "'='")) return null;
        Vec!(Ctor*) cs;
        for (;;) {
            if (!at(T.ConId)) { cs.dispose(); return fail("expected a constructor") ? null : null; }
            auto c = pnew!Ctor(); c.name = intern(tok().s); next();
            if (at(T.LBrace)) {                                // record syntax
                next();
                Vec!Sym fs;
                while (at(T.VarId)) {
                    fs.push(intern(tok().s)); next();
                    while (accept(T.Comma)) { if (at(T.VarId)) { fs.push(intern(tok().s)); next(); } }
                    if (accept(T.DColon)) {
                        int dd = 0;
                        while (!at(T.EOF)) {
                            if (at(T.LParen) || at(T.LBracket)) ++dd;
                            else if (at(T.RParen) || at(T.RBracket)) --dd;
                            else if (dd == 0 && (at(T.Comma) || at(T.RBrace))) break;
                            next();
                        }
                    }
                    accept(T.Comma);
                }
                if (!expect(T.RBrace, "'}'")) { fs.dispose(); cs.dispose(); return null; }
                c.fields = permSlice(fs); c.arity = cast(uint)c.fields.length;
            } else {
                while (at(T.ConId) || at(T.VarId) || at(T.LParen) || at(T.LBracket)) {
                    if (at(T.LParen) || at(T.LBracket)) skipGroup(); else next();
                    ++c.arity;
                }
            }
            cs.push(c);
            if (!accept(T.Pipe)) break;
        }
        if (accept(T.VarId)) { /* "deriving (..)" -- accepted and ignored */ if (at(T.LParen)) skipGroup(); else if (at(T.ConId)) next(); }
        d.ctors = permSlice(cs);
        d.text = permDup(src[toks[st].off .. toks[pos > 0 ? pos - 1 : 0].end]);
        return d;
    }
}
