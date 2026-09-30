// dash tokens.  The lexer is deliberately lenient: a do block may contain command lines (bash
// syntax), and those must tokenize well enough for the parser to find where each one starts and
// ends -- their text is then handed to the command parser as-is.
module dash.lexer;

import dash.rt;

enum T : ubyte {
    EOF, Int, Float, Str, Char, VarId, ConId, Op, BackOp, DotField,
    LParen, RParen, LBracket, RBracket, LBrace, RBrace, Comma, Semi,
    Lambda, Arrow, LArrow, Equals, Pipe, DColon, At, DotDot, CmdSub, Raw,
    KwLet, KwIn, KwWhere, KwIf, KwThen, KwElse, KwCase, KwOf, KwDo, KwData,
}

struct Tok {
    T t;
    const(char)[] s;     // the token text (Str/Char: the decoded contents; CmdSub: the inner command)
    long i; double f;
    uint line, col;      // col is 0-based
    uint off, end;       // byte span in the source
    bool spaceBefore;    // whitespace (or line start) immediately before
    bool lineStart;      // first token on its line
}

@nogc nothrow:

private bool isSym(char c) {
    switch (c) {
        case '!', '#', '$', '%', '&', '*', '+', '.', '/', '<', '=', '>', '?', '@', '\\', '^', '|', '-', '~', ':': return true;
        default: return false;
    }
}

// Tokenize `src`.  Returns false (with g_err) only for things that cannot be recovered from.
bool lex(const(char)[] src, ref Vec!Tok toks) {
    size_t i = 0; uint line = 1, col = 0;
    bool space = true, lineStart = true;
    void adv(size_t n) { foreach (_; 0 .. n) { if (i < src.length && src[i] == '\n') { ++line; col = 0; } else ++col; ++i; } }
    Tok mk(T t, size_t st, uint l, uint c) {
        Tok k; k.t = t; k.line = l; k.col = c; k.off = cast(uint)st; k.end = cast(uint)i;
        k.s = src[st .. i]; k.spaceBefore = space; k.lineStart = lineStart;
        return k;
    }
    while (i < src.length) {
        const c = src[i];
        if (c == '\n') { adv(1); space = true; lineStart = true; continue; }
        if (isSpace(c)) { adv(1); space = true; continue; }
        // comments: "-- ..." (not "-->" and not a flag like --verbose after a space... -- followed by
        // a space or end is always a comment), and {- ... -}
        if (c == '-' && i + 1 < src.length && src[i + 1] == '-' &&
            (i + 2 >= src.length || src[i + 2] == ' ' || src[i + 2] == '-' || src[i + 2] == '\n')) {
            while (i < src.length && src[i] != '\n') adv(1);
            continue;
        }
        if (c == '{' && i + 1 < src.length && src[i + 1] == '-') {
            int depth = 0;
            while (i < src.length) {
                if (src[i] == '{' && i + 1 < src.length && src[i + 1] == '-') { ++depth; adv(2); continue; }
                if (src[i] == '-' && i + 1 < src.length && src[i + 1] == '}') { --depth; adv(2); if (depth == 0) break; continue; }
                adv(1);
            }
            space = true;
            continue;
        }
        const st = i; const l = line, co = col;
        Tok k;
        if (isDigit(c)) {
            bool isF = false;
            if (c == '0' && i + 1 < src.length && (src[i + 1] == 'x' || src[i + 1] == 'X')) {
                adv(2); while (i < src.length && (isDigit(src[i]) || (src[i] | 0x20) >= 'a' && (src[i] | 0x20) <= 'f')) adv(1);
            } else {
                while (i < src.length && isDigit(src[i])) adv(1);
                if (i + 1 < src.length && src[i] == '.' && isDigit(src[i + 1])) { isF = true; adv(1); while (i < src.length && isDigit(src[i])) adv(1); }
                if (i < src.length && (src[i] == 'e' || src[i] == 'E') && i + 1 < src.length &&
                    (isDigit(src[i + 1]) || ((src[i + 1] == '-' || src[i + 1] == '+') && i + 2 < src.length && isDigit(src[i + 2])))) {
                    isF = true; adv(2); while (i < src.length && isDigit(src[i])) adv(1);
                }
            }
            // a number glued to letters is a word (e.g. "2>&1" or "7z"): leave it as Raw
            if (i < src.length && (isAlpha(src[i]))) {
                while (i < src.length && !isSpace(src[i]) && src[i] != '\n' && src[i] != ')' && src[i] != ']') adv(1);
                k = mk(T.Raw, st, l, co);
            } else {
                k = mk(isF ? T.Float : T.Int, st, l, co);
                auto z = cz(k.s);
                if (isF) k.f = strtod(z, null); else k.i = strtoll(z, null, 0);
                free(z);
            }
        } else if (isAlpha(c)) {
            while (i < src.length && isIdentChar(src[i])) adv(1);
            k = mk(isUpper(c) ? T.ConId : T.VarId, st, l, co);
            if (k.t == T.VarId) {
                switch (k.s) {
                    case "let": k.t = T.KwLet; break;
                    case "in": k.t = T.KwIn; break;
                    case "where": k.t = T.KwWhere; break;
                    case "if": k.t = T.KwIf; break;
                    case "then": k.t = T.KwThen; break;
                    case "else": k.t = T.KwElse; break;
                    case "case": k.t = T.KwCase; break;
                    case "of": k.t = T.KwOf; break;
                    case "do": k.t = T.KwDo; break;
                    case "data": k.t = T.KwData; break;
                    default: break;
                }
            }
        } else if (c == '"') {
            adv(1);
            Buf b;
            while (i < src.length && src[i] != '"') {
                if (src[i] == '\\' && i + 1 < src.length) {
                    const e = src[i + 1];
                    switch (e) {
                        case 'n': b.put('\n'); break;
                        case 't': b.put('\t'); break;
                        case 'r': b.put('\r'); break;
                        case '0': b.put('\0'); break;
                        case 'e': b.put('\x1b'); break;
                        default: b.put(e); break;
                    }
                    adv(2);
                } else { b.put(src[i]); adv(1); }
            }
            if (i < src.length) adv(1);
            k = mk(T.Str, st, l, co);
            k.s = permDup(b.str()); b.dispose();
        } else if (c == '\'') {
            // a Char literal 'x' / '\n'; anything else is a shell single-quoted word
            if (i + 2 < src.length && src[i + 1] != '\\' && src[i + 2] == '\'') {
                adv(3); k = mk(T.Char, st, l, co); k.i = cast(ubyte)src[st + 1];
            } else if (i + 3 < src.length && src[i + 1] == '\\' && src[i + 3] == '\'') {
                const e = src[i + 2];
                adv(4); k = mk(T.Char, st, l, co);
                k.i = e == 'n' ? '\n' : e == 't' ? '\t' : e == '0' ? 0 : e;
            } else {
                adv(1); while (i < src.length && src[i] != '\'') adv(1);
                if (i < src.length) adv(1);
                k = mk(T.Raw, st, l, co);
            }
        } else if (c == '$' && i + 1 < src.length && src[i + 1] == '(') {
            // $(command) -- or $((expr)) which a command stage evaluates; keep the raw text
            const dbl = i + 2 < src.length && src[i + 2] == '(';
            adv(2);
            int depth = 1;
            const inner = i;
            while (i < src.length && depth > 0) {
                const d = src[i];
                if (d == '(') ++depth; else if (d == ')') { --depth; if (depth == 0) break; }
                else if (d == '\'' || d == '"') { const q = d; adv(1); while (i < src.length && src[i] != q) { if (src[i] == '\\') adv(1); adv(1); } }
                adv(1);
            }
            const innerEnd = i;
            if (i < src.length) adv(1);
            k = mk(dbl ? T.Raw : T.CmdSub, st, l, co);
            if (!dbl) k.s = src[inner .. innerEnd];
        } else {
            switch (c) {
                case '(': adv(1); k = mk(T.LParen, st, l, co); break;
                case ')': adv(1); k = mk(T.RParen, st, l, co); break;
                case '[': adv(1); k = mk(T.LBracket, st, l, co); break;
                case ']': adv(1); k = mk(T.RBracket, st, l, co); break;
                case '{': adv(1); k = mk(T.LBrace, st, l, co); break;
                case '}': adv(1); k = mk(T.RBrace, st, l, co); break;
                case ',': adv(1); k = mk(T.Comma, st, l, co); break;
                case ';': adv(1); k = mk(T.Semi, st, l, co); break;
                case '`': {
                    adv(1); const ns = i;
                    while (i < src.length && isIdentChar(src[i])) adv(1);
                    const ne = i;
                    if (i < src.length && src[i] == '`') adv(1);
                    k = mk(T.BackOp, st, l, co); k.s = src[ns .. ne];
                    break;
                }
                default:
                    if (c == '.' && !space && i + 1 < src.length && isLower(src[i + 1]) && toks.n > 0 &&
                        toks.back().end == i) {
                        // a.name / (e).name / Domain.name: field access, glued on both sides
                        adv(1); const ns = i;
                        while (i < src.length && isIdentChar(src[i])) adv(1);
                        k = mk(T.DotField, st, l, co); k.s = src[ns .. i];
                    } else if (c == '.' && i + 1 < src.length && isLower(src[i + 1]) && toks.n > 0 &&
                               toks.back().t == T.LParen) {
                        adv(1); const ns = i;                     // (.name): a field selector
                        while (i < src.length && isIdentChar(src[i])) adv(1);
                        k = mk(T.DotField, st, l, co); k.s = src[ns .. i];
                    } else if (isSym(c)) {
                        while (i < src.length && isSym(src[i])) adv(1);
                        k = mk(T.Op, st, l, co);
                        switch (k.s) {
                            case "\\": k.t = T.Lambda; break;
                            case "->": k.t = T.Arrow; break;
                            case "<-": k.t = T.LArrow; break;
                            case "=": k.t = T.Equals; break;
                            case "|": k.t = T.Pipe; break;
                            case "::": k.t = T.DColon; break;
                            case "@": k.t = T.At; break;
                            case "..": k.t = T.DotDot; break;
                            default: break;
                        }
                        // "\x" lambda glued to its parameter: split the backslash off
                        if (k.t == T.Op && k.s.length > 1 && k.s[0] == '\\') {
                            i = st; line = l; col = co; adv(1);
                            k = mk(T.Lambda, st, l, co);
                        }
                    } else {
                        // anything else (unicode, stray chars in command text): a raw word
                        while (i < src.length && !isSpace(src[i]) && src[i] != '\n') adv(1);
                        k = mk(T.Raw, st, l, co);
                    }
            }
        }
        toks.push(k);
        space = false; lineStart = false;
    }
    Tok e; e.t = T.EOF; e.line = line + 1; e.col = 0; e.off = e.end = cast(uint)src.length; e.spaceBefore = true; e.lineStart = true;
    toks.push(e);
    return true;
}
