// JSON <-> dash values: objects become records, arrays lists, null Nothing.
module dash.json;

import dash.rt;
import dash.value;

@nogc nothrow:

struct JP {
    const(char)[] s; size_t i; bool bad;
    @nogc nothrow:
    void ws() { while (i < s.length && (s[i] == ' ' || s[i] == '\n' || s[i] == '\t' || s[i] == '\r')) ++i; }
    Value* value() {
        ws();
        if (i >= s.length) { bad = true; return null; }
        const c = s[i];
        if (c == '{') {
            ++i; auto r = mkRecord(0);
            ws();
            if (i < s.length && s[i] == '}') { ++i; return r; }
            for (;;) {
                ws();
                auto k = str_(); if (!k) return null;
                ws(); if (i >= s.length || s[i] != ':') { bad = true; return null; } ++i;
                auto v = value(); if (!v) return null;
                r = withField(r, intern(dash.value.str(k)), v);
                ws();
                if (i < s.length && s[i] == ',') { ++i; continue; }
                if (i < s.length && s[i] == '}') { ++i; return r; }
                bad = true; return null;
            }
        }
        if (c == '[') {
            ++i; ListB lb;
            ws();
            if (i < s.length && s[i] == ']') { ++i; return lb.done(); }
            for (;;) {
                auto v = value(); if (!v) return null;
                lb.push(v);
                ws();
                if (i < s.length && s[i] == ',') { ++i; continue; }
                if (i < s.length && s[i] == ']') { ++i; return lb.done(); }
                bad = true; return null;
            }
        }
        if (c == '"') return str_();
        if (s[i .. $].startsWith("true")) { i += 4; return g_true; }
        if (s[i .. $].startsWith("false")) { i += 5; return g_false; }
        if (s[i .. $].startsWith("null")) { i += 4; return g_nothing; }
        // number
        const st = i; bool isF = false;
        if (i < s.length && (s[i] == '-' || s[i] == '+')) ++i;
        while (i < s.length && (isDigit(s[i]) || s[i] == '.' || s[i] == 'e' || s[i] == 'E' || ((s[i] == '-' || s[i] == '+') && (s[i - 1] == 'e' || s[i - 1] == 'E')))) {
            if (s[i] == '.' || s[i] == 'e' || s[i] == 'E') isF = true;
            ++i;
        }
        if (i == st) { bad = true; return null; }
        auto z = cz(s[st .. i]);
        auto v = isF ? mkFloat(strtod(z, null)) : mkInt(strtoll(z, null, 10));
        free(z);
        return v;
    }
    Value* str_() {
        if (i >= s.length || s[i] != '"') { bad = true; return null; }
        ++i;
        Buf b;
        while (i < s.length && s[i] != '"') {
            if (s[i] == '\\' && i + 1 < s.length) {
                const e = s[i + 1]; i += 2;
                switch (e) {
                    case 'n': b.put('\n'); break;
                    case 't': b.put('\t'); break;
                    case 'r': b.put('\r'); break;
                    case 'b': b.put('\b'); break;
                    case 'f': b.put('\f'); break;
                    case 'u': {
                        uint cp = 0;
                        foreach (k; 0 .. 4) { if (i >= s.length) break; const h = s[i++]; cp = cp * 16 + (isDigit(h) ? h - '0' : ((h | 0x20) - 'a' + 10)); }
                        if (cp < 0x80) b.put(cast(char)cp);
                        else if (cp < 0x800) { b.put(cast(char)(0xC0 | (cp >> 6))); b.put(cast(char)(0x80 | (cp & 0x3F))); }
                        else { b.put(cast(char)(0xE0 | (cp >> 12))); b.put(cast(char)(0x80 | ((cp >> 6) & 0x3F))); b.put(cast(char)(0x80 | (cp & 0x3F))); }
                        break;
                    }
                    default: b.put(e); break;
                }
            } else { b.put(s[i]); ++i; }
        }
        if (i < s.length) ++i;
        auto v = mkStr(b.str()); b.dispose();
        return v;
    }
}

Value* parseJson(const(char)[] text) {
    JP p; p.s = text; p.i = 0;
    auto v = p.value();
    if (!v || p.bad) { setErr("not valid JSON"); return null; }
    return v;
}

void toJson(ref Buf b, Value* v) {
    switch (v.t) {
        case VT.Unit: b.put("null"); break;
        case VT.Bool: b.put(v.i ? "true" : "false"); break;
        case VT.Int: b.puti(v.i); break;
        case VT.Float: showFloat(b, v.f); break;
        case VT.Char: case VT.Str: {
            b.put('"');
            const(char)[] s = v.t == VT.Str ? v.s[0 .. v.n] : (cast(char*)&v.i)[0 .. 1];
            foreach (c; s) {
                if (c == '"' || c == '\\') { b.put('\\'); b.put(c); }
                else if (c == '\n') b.put("\\n");
                else if (c == '\t') b.put("\\t");
                else if (cast(ubyte)c < 32) { char[8] t; const n = snprintf(t.ptr, t.length, "\\u%04x", cast(int)c); b.put(t[0 .. n]); }
                else b.put(c);
            }
            b.put('"'); break;
        }
        case VT.List: case VT.Tuple:
            b.put('[');
            foreach (k; 0 .. v.n) { if (k) b.put(','); toJson(b, v.items[k]); }
            b.put(']'); break;
        case VT.Record: case VT.Obj:
            b.put('{');
            foreach (k; 0 .. v.n) { if (k) b.put(','); b.put('"'); b.put(symName(v.keys[k])); b.put("\":"); toJson(b, v.items[k]); }
            b.put('}'); break;
        case VT.Ctor:
            if (v.name == S_Nothing) { b.put("null"); break; }
            if (v.name == S_Just && v.n == 1) { toJson(b, v.items[0]); break; }
            b.put("{\"tag\":\""); b.put(symName(v.name)); b.put("\",\"fields\":[");
            foreach (k; 0 .. v.n) { if (k) b.put(','); toJson(b, v.items[k]); }
            b.put("]}"); break;
        default: b.put("null"); break;
    }
}
