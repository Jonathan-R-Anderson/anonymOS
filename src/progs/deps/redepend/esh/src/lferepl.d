module lferepl;

import dlexer;
import dparser;
import std.regex : regex;
import std.stdio;
import std.string;
import std.ascii : isDigit;
import std.algorithm : canFind, filter, sort, countUntil, joiner;
import std.array;
import std.conv : to;
import std.utf : encode;
import std.file : readText, copy;
import core.thread : Thread;
import cpio : createArchive, extractArchive;
import core.sync.mutex : Mutex;
import core.sync.condition : Condition;
import syswrap : system;
version(Posix) import core.sys.posix.unistd : execvp;
version(Posix) extern(C) int sethostname(const char* name, size_t len);
import std.process;
import objectsystem;
import local;
import locate;
import login;
import logname;
import logout;

struct Expr {
    bool isList;
    string atom;
    Expr[] list;
    bool isAtom;
    bool isTuple;
    bool isMap;
}

enum ValueKind { Number, Atom, Tuple, List, Map }

struct Value {
    ValueKind kind;
    double number;
    string atom;
    Value[] tuple;
    Value[] list;
    Value[string] map;
}

Value num(double n) { return Value(ValueKind.Number, n, "", null, null, null); }
Value atomVal(string a) { return Value(ValueKind.Atom, 0, a, null, null, null); }
Value tupleVal(Value[] t) { return Value(ValueKind.Tuple, 0, "", t, null, null); }
Value listVal(Value[] l) { return Value(ValueKind.List, 0, "", null, l, null); }
Value mapVal(Value[string] m) { return Value(ValueKind.Map, 0, "", null, null, m); }

class ExitException : Exception {
    Value reason;
    this(Value r) {
        super("exit");
        this.reason = r;
    }
}

string valueToString(Value v) {
    final switch(v.kind) {
        case ValueKind.Number:
            return to!string(v.number);
        case ValueKind.Atom:
            return "'" ~ v.atom;
        case ValueKind.Tuple:
            string s;
            foreach(elem; v.tuple) {
                s ~= valueToString(elem) ~ " ";
            }
            if(s.length > 0) s = s[0 .. $-1];
            return "#(" ~ s ~ ")";
        case ValueKind.List:
            string ls;
            foreach(elem; v.list) {
                ls ~= valueToString(elem) ~ " ";
            }
            if(ls.length > 0) ls = ls[0 .. $-1];
            return "(" ~ ls ~ ")";
        case ValueKind.Map:
            string ms;
            foreach(k, val; v.map) {
                ms ~= k ~ " " ~ valueToString(val) ~ " ";
            }
            if(ms.length > 0) ms = ms[0 .. $-1];
            return "#M(" ~ ms ~ ")";
    }
    return "";
}

string formatValue(Value v) {
    final switch(v.kind) {
        case ValueKind.Number:
            return to!string(v.number);
        case ValueKind.Atom:
            return v.atom;
        case ValueKind.Tuple:
            string s;
            foreach(elem; v.tuple) {
                s ~= formatValue(elem) ~ " ";
            }
            if(s.length > 0) s = s[0 .. $-1];
            return "#(" ~ s ~ ")";
        case ValueKind.List:
            string ls;
            foreach(elem; v.list) {
                ls ~= formatValue(elem) ~ " ";
            }
            if(ls.length > 0) ls = ls[0 .. $-1];
            return "(" ~ ls ~ ")";
        case ValueKind.Map:
            string ms;
            foreach(k, val; v.map) {
                ms ~= k ~ " " ~ formatValue(val) ~ " ";
            }
            if(ms.length > 0) ms = ms[0 .. $-1];
            return "#M(" ~ ms ~ ")";
    }
    return "";
}

string unescape(string s) {
    string result;
    for(size_t i = 0; i < s.length; i++) {
        auto c = s[i];
        if(c == '\\' && i + 1 < s.length) {
            auto n = s[i+1];
            switch(n) {
                case 'a': result ~= "\a"; break;
                case 'b': result ~= "\b"; break;
                case 'c': return result; // suppress trailing newline
                case 'e': case 'E': result ~= "\x1b"; break;
                case 'f': result ~= "\f"; break;
                case 'n': result ~= "\n"; break;
                case 'r': result ~= "\r"; break;
                case 't': result ~= "\t"; break;
                case 'v': result ~= "\v"; break;
                case '\\': result ~= "\\"; break;
                case 'x': {
                    string hx; size_t j = i + 2;
                    while(j < s.length && hx.length < 2 &&
                          ((s[j] >= '0' && s[j] <= '9') ||
                           (s[j] >= 'a' && s[j] <= 'f') ||
                           (s[j] >= 'A' && s[j] <= 'F'))) {
                        hx ~= s[j]; j++; }
                    if(hx.length) {
                        result ~= cast(char)to!int("0x" ~ hx);
                        i = j - 1;
                    } else result ~= 'x';
                    break; }
                case '0': case '1': case '2': case '3': case '4':
                case '5': case '6': case '7': {
                    string oc; size_t j = i + 1;
                    while(j < s.length && j < i + 4 &&
                          s[j] >= '0' && s[j] <= '7') {
                        oc ~= s[j]; j++; }
                    result ~= cast(char)to!int(oc, 8);
                    i = j - 1; break; }
                case 'u': case 'U': {
                    size_t maxLen = n == 'u' ? 4 : 8;
                    string hx; size_t j = i + 2;
                    while(j < s.length && hx.length < maxLen &&
                          ((s[j] >= '0' && s[j] <= '9') ||
                           (s[j] >= 'a' && s[j] <= 'f') ||
                           (s[j] >= 'A' && s[j] <= 'F'))) {
                        hx ~= s[j]; j++; }
                    if(hx.length) {
                        dchar val = cast(dchar)to!int("0x" ~ hx);
                        char[4] tmp;
                        auto len = encode(tmp, val);
                        result ~= tmp[0 .. len];
                        i = j - 1;
                    } else result ~= n;
                    break; }
                default:
            result ~= n; break;
            }
            i++; // skip the escape code
        } else {
            result ~= c;
        }
    }
    return result;
}

class LfeParser : Parser {
    this(Token[] toks) {
        super(toks);
    }

    Expr parseExpr() {
        if (peek("QUOTE")) {
            consume("QUOTE");
            auto q = parseExpr();
            Expr[] elems = [Expr(false, "quote", null, false, false, false), q];
            return Expr(true, "", elems, false, false, false);
        } else if (peek("BQUOTE")) {
            consume("BQUOTE");
            auto q = parseExpr();
            Expr[] elems = [Expr(false, "backquote", null, false, false, false), q];
            return Expr(true, "", elems, false, false, false);
        } else if (peek("COMMA_AT")) {
            consume("COMMA_AT");
            auto q = parseExpr();
            Expr[] elems = [Expr(false, "comma-at", null, false, false, false), q];
            return Expr(true, "", elems, false, false, false);
        } else if (peek("COMMA")) {
            consume("COMMA");
            auto q = parseExpr();
            Expr[] elems = [Expr(false, "comma", null, false, false, false), q];
            return Expr(true, "", elems, false, false, false);
        } else if (peek("HASHMAP")) {
            consume("HASHMAP");
            Expr[] elems;
            while (!peek("RPAREN")) {
                elems ~= parseExpr();
                if (pos >= tokens.length) break;
            }
            consume("RPAREN");
            return Expr(true, "", elems, false, false, true);
        } else if (peek("HASHLPAREN")) {
            consume("HASHLPAREN");
            Expr[] elems;
            while (!peek("RPAREN")) {
                elems ~= parseExpr();
                if (pos >= tokens.length) break;
            }
            consume("RPAREN");
            return Expr(true, "", elems, false, true, false);
        } else if (peek("LPAREN") || peek("LBRACK")) {
            bool br = peek("LBRACK");
            if(br) consume("LBRACK"); else consume("LPAREN");
            Expr[] elems;
            while (!(br ? peek("RBRACK") : peek("RPAREN"))) {
                elems ~= parseExpr();
                if (pos >= tokens.length) break;
            }
            if(br) consume("RBRACK"); else consume("RPAREN");
            return Expr(true, "", elems, false, false, false);
        } else if (peek("NUMBER")) {
            auto t = consume("NUMBER");
            return Expr(false, t.value, null, false, false, false);
        } else if (peek("STRING")) {
            auto t = consume("STRING");
            // Strip the surrounding quotes from the string literal
            auto value = t.value.length > 1 ? t.value[1 .. $-1] : "";
            return Expr(false, value, null, false, false, false);
        } else if (peek("ATOM")) {
            auto t = consume("ATOM");
            return Expr(false, t.value[1 .. $], null, true, false, false);
        } else if (peek("SYMBOL")) {
            auto t = consume("SYMBOL");
            return Expr(false, t.value, null, false, false, false);
        }
        throw new Exception("Unexpected token");
    }
}

struct FunctionClause {
    Expr[] params;
    Expr body;
    Expr guard;
    bool hasGuard;
}

struct MacroDef {
    string[] params;
    Expr body;
}

Value[string] variables;
FunctionClause[][string] functions;
MacroDef[string] macros;
string[][string] moduleFunctions;
string[][string] recordDefs;
size_t pidCounter;
string[] historyLines;
string currentModule;

class Process {
    Mutex m;
    Condition c;
    Value[] inbox;
    string[] links;
    bool trapExit = false;
    bool alive = true;
    this() {
        m = new Mutex();
        c = new Condition(m);
    }
}

Process[string] processes;
Mutex procMutex;
string currentPid;

void sendExitSignal(string fromPid, string toPid, Value reason) {
    Process proc;
    synchronized(procMutex) {
        if(!(toPid in processes)) return;
        proc = processes[toPid];
    }
    synchronized(proc.m) {
        proc.inbox ~= tupleVal([atomVal("EXIT"), atomVal(fromPid), reason]);
        proc.c.notify();
    }
    if(!proc.trapExit) proc.alive = false;
}

void propagateExit(string pid, Value reason) {
    Process proc;
    synchronized(procMutex) {
        if(!(pid in processes)) return;
        proc = processes[pid];
    }
    foreach(linkPid; proc.links) {
        sendExitSignal(pid, linkPid, reason);
    }
    synchronized(procMutex) processes.remove(pid);
}

immutable string[] builtinModules = [
    "application", "application_controller", "application_master",
    "beam_lib", "binary", "c", "code", "code_server",
    "edlin", "edlin_expand", "epp", "erl_distribution", "erl_eval",
    "erl_parse", "erl_prim_loader", "erl_scan", "erlang", "error_handler",
    "error_logger", "error_logger_tty_h", "erts_internal", "ets",
    "file", "file_io_server", "file_server", "filename", "gb_sets",
    "gb_trees", "gen", "gen_event", "gen_server", "global",
    "global_group", "group", "heart", "hipe_unified_loader", "inet",
    "inet_config", "inet_db", "inet_parse", "inet_udp", "init", "io",
    "io_lib", "io_lib_format", "kernel", "kernel_config", "lfe_env",
    "lfe_eval", "lfe_init", "lfe_io", "lfe_shell", "lists",
    "net_kernel", "orddict", "os", "otp_ring0", "prim_eval",
    "prim_file", "prim_inet", "prim_zip", "proc_lib", "proplists",
    "ram_file", "rpc", "standard_error", "supervisor",
    "supervisor_bridge", "sys", "unicode", "user_drv", "user_sup",
    "zlib"
];

immutable string[][string] builtinModuleFunctions = [
    "gb_trees" : [
        "add/2", "add_element/2", "balance/1", "del_element/2",
        "delete/2", "delete_any/2", "difference/2", "empty/0",
        "filter/2", "fold/3", "from_list/1", "from_ordset/1",
        "insert/2", "intersection/1", "intersection/2",
        "is_disjoint/2", "is_element/2", "is_empty/1",
        "is_member/2", "is_set/1", "is_subset/2", "iterator/1",
        "largest/1", "module_info/0", "module_info/1", "new/0",
        "next/1", "singleton/1", "size/1", "smallest/1",
        "subtract/2", "take_largest/1", "take_smallest/1",
        "to_list/1", "union/1", "union/2"
    ]
];

bool isNumber(string s) {
    bool seenDot = false;
    if(s.length == 0) return false;
    foreach(ch; s) {
        if(ch == '.') {
            if(seenDot) return false;
            seenDot = true;
        } else if(!ch.isDigit) {
            return false;
        }
    }
    return true;
}

Value evalExpr(Expr e);
Value quoteValue(Expr e);
Expr valueToExpr(Value v);
Expr macroExpand(Expr e);

Rule[] rules = [
    Rule("HASHMAP", regex("#M\\(")),
    Rule("HASHLPAREN", regex("#\\(")),
    Rule("LPAREN", regex("\\(")),
    Rule("LBRACK", regex("\\[")),
    Rule("RBRACK", regex("\\]")),
    Rule("RPAREN", regex("\\)")),
    Rule("STRING", regex("\"[^\"]*\"")),
    Rule("NUMBER", regex("[0-9]+(\\.[0-9]+)?")),
    Rule("ATOM", regex("'[a-zA-Z_+*/:<>=!?-][a-zA-Z0-9_+*/:<>=!?-]*")),
    Rule("BQUOTE", regex("`")),
    Rule("COMMA_AT", regex(",@")),
    Rule("COMMA", regex(",")),
    Rule("QUOTE", regex("'")),
    Rule("SYMBOL", regex("[a-zA-Z_+*/:<>=!?-][a-zA-Z0-9_+*/:<>=!?-]*")),
    Rule("WS", regex("\\s+"))
];

Token[] lexInput(string input) {
    auto lex = new Lexer(rules);
    auto toks = lex.tokenize(input);
    return toks.filter!(t => t.type != "WS").array;
}

Expr parseString(string code) {
    auto toks = lexInput(code);
    auto parser = new LfeParser(toks);
    return parser.parseExpr();
}

Expr[] parseAll(string code) {
    auto toks = lexInput(code);
    auto parser = new LfeParser(toks);
    Expr[] exprs;
    while (parser.pos < parser.tokens.length) {
        exprs ~= parser.parseExpr();
    }
    return exprs;
}

Value evalString(string code) {
    auto ast = parseString(code);
    return evalExpr(ast);
}

void loadFile(string path) {
    auto text = readText(path);
    auto exprs = parseAll(text);
    auto prev = currentModule;
    string modName;
    foreach(ast; exprs) {
        evalExpr(ast);
        if(ast.isList && ast.list.length > 0 && ast.list[0].atom == "defmodule")
            modName = ast.list[1].atom;
    }
    currentModule = prev;
    if(modName.length)
        writeln("#(module ", modName, ")");
    else
        writeln("ok");
}

void showCompletions(string prefix) {
    if(prefix.indexOf(":") == -1) {
        string[] mods;
        foreach(m; builtinModules) if(m.startsWith(prefix)) mods ~= m;
        foreach(m; moduleFunctions.keys) if(m.startsWith(prefix)) mods ~= m;
        sort(mods);
        foreach(m; mods) write(m ~ "    ");
        writeln();
    } else {
        auto parts = prefix.split(":");
        auto mod = parts[0];
        auto funPref = parts.length > 1 ? parts[1] : "";
        string[] funcs;
        if(auto arr = mod in builtinModuleFunctions)
            foreach(f; *arr) if(f.startsWith(funPref)) funcs ~= f;
        if(auto arr2 = mod in moduleFunctions)
            foreach(f; *arr2) if(f.startsWith(funPref)) funcs ~= f;
        sort(funcs);
        foreach(f; funcs) write(f ~ "    ");
        writeln();
    }
}

bool matchPattern(Value val, Expr pat, ref string[] varNames, ref Value[string] saved) {
    if(pat.isAtom) {
        return val.kind == ValueKind.Atom && val.atom == pat.atom;
    }
    if(pat.isList && pat.list.length > 0 && !pat.list[0].isList && pat.list[0].atom.startsWith("match-")) {
        auto recName = pat.list[0].atom[6 .. $];
        if(auto fieldsPtr = recName in recordDefs) {
            auto fields = *fieldsPtr;
            if(val.kind != ValueKind.Tuple || val.tuple.length < fields.length + 1) return false;
            if(val.tuple[0].kind != ValueKind.Atom || val.tuple[0].atom != recName) return false;
            for(size_t i = 1; i + 1 < pat.list.length; i += 2) {
                auto fname = pat.list[i].atom;
                size_t idx = fields.countUntil(fname);
                if(idx >= fields.length) return false;
                if(!matchPattern(val.tuple[idx+1], pat.list[i+1], varNames, saved)) return false;
            }
            return true;
        }
    }
    if(pat.isTuple || (pat.isList && pat.list.length > 0 && !pat.list[0].isList && pat.list[0].atom == "tuple")) {
        auto elems = pat.isTuple ? pat.list : pat.list[1 .. $];
        if(val.kind != ValueKind.Tuple || val.tuple.length != elems.length) return false;
        foreach(i, pe; elems) {
            if(!matchPattern(val.tuple[i], pe, varNames, saved)) return false;
        }
        return true;
    }
    if(pat.isMap || (pat.isList && pat.list.length > 0 && !pat.list[0].isList && pat.list[0].atom == "map")) {
        auto elems = pat.isMap ? pat.list : pat.list[1 .. $];
        if(val.kind != ValueKind.Map) return false;
        for(size_t i = 0; i + 1 < elems.length; i += 2) {
            auto keyStr = valueToString(evalExpr(elems[i]));
            if(!(keyStr in val.map)) return false;
            if(!matchPattern(val.map[keyStr], elems[i+1], varNames, saved)) return false;
        }
        return true;
    }
    if(pat.isList) {
        if(pat.list.length == 0) {
            return val.kind == ValueKind.List && val.list.length == 0;
        }
        if(pat.list.length == 2 && !pat.list[0].isList && pat.list[0].atom == "quote") {
            auto qval = quoteValue(pat.list[1]);
            return valuesEqual(val, qval);
        }
        if(pat.list.length == 3 && !pat.list[0].isList && pat.list[0].atom == "cons") {
            if(val.kind != ValueKind.List || val.list.length == 0) return false;
            auto headVal = val.list[0];
            auto tailVal = listVal(val.list[1 .. $]);
            if(!matchPattern(headVal, pat.list[1], varNames, saved)) return false;
            if(!matchPattern(tailVal, pat.list[2], varNames, saved)) return false;
            return true;
        }
    }
    if(!pat.isList) {
        auto name = pat.atom;
        if(name in variables) saved[name] = variables[name];
        variables[name] = val;
        varNames ~= name;
        return true;
    }
    return false;
}

Value quoteValue(Expr e) {
    if(!e.isList) {
        if(e.isAtom) return atomVal(e.atom);
        if(isNumber(e.atom)) return num(to!double(e.atom));
        return atomVal(e.atom);
    }
    if(e.isTuple) {
        Value[] elems; foreach(sub; e.list) elems ~= quoteValue(sub);
        return tupleVal(elems);
    }
    if(e.isMap) {
        Value[string] m;
        for(size_t i = 0; i + 1 < e.list.length; i += 2) {
            auto k = quoteValue(e.list[i]);
            auto v = quoteValue(e.list[i+1]);
            m[valueToString(k)] = v;
        }
        return mapVal(m);
    }
    Value[] els; foreach(sub; e.list) els ~= quoteValue(sub);
    return listVal(els);
}

Value backquoteValue(Expr e) {
    if(e.isList) {
        if(e.list.length > 0 && !e.list[0].isList) {
            auto h = e.list[0].atom;
            if(h == "comma") {
                return evalExpr(e.list[1]);
            } else if(h == "comma-at") {
                auto v = evalExpr(e.list[1]);
                return v;
            }
        }
        if(e.isTuple) {
            Value[] elems; foreach(sub; e.list) elems ~= backquoteValue(sub);
            return tupleVal(elems);
        }
        if(e.isMap) {
            Value[string] m;
            for(size_t i = 0; i + 1 < e.list.length; i += 2) {
                auto k = backquoteValue(e.list[i]);
                auto v = backquoteValue(e.list[i+1]);
                m[valueToString(k)] = v;
            }
            return mapVal(m);
        }
        Value[] els;
        foreach(sub; e.list) {
            if(sub.isList && sub.list.length > 0 && !sub.list[0].isList &&
               sub.list[0].atom == "comma-at") {
                auto v = evalExpr(sub.list[1]);
                if(v.kind == ValueKind.List)
                    els ~= v.list;
                else
                    els ~= [v];
            } else {
                els ~= backquoteValue(sub);
            }
        }
        return listVal(els);
    }
    return quoteValue(e);
}

Expr valueToExpr(Value v) {
    final switch(v.kind) {
        case ValueKind.Number:
            return Expr(false, to!string(v.number), null, false, false, false);
        case ValueKind.Atom:
            return Expr(false, v.atom, null, true, false, false);
        case ValueKind.Tuple:
            Expr[] tElems;
            foreach(elem; v.tuple) tElems ~= valueToExpr(elem);
            return Expr(true, "", tElems, false, true, false);
        case ValueKind.List:
            Expr[] lElems;
            foreach(elem; v.list) lElems ~= valueToExpr(elem);
            return Expr(true, "", lElems, false, false, false);
        case ValueKind.Map:
            Expr[] mElems;
            foreach(k, val; v.map) {
                auto keyExpr = parseString(k);
                mElems ~= keyExpr;
                mElems ~= valueToExpr(val);
            }
            return Expr(true, "", mElems, false, false, true);
    }
    return Expr(false, "", null, false, false, false);
}

bool isTruthy(Value v) {
    if(v.kind == ValueKind.Number) return v.number != 0;
    if(v.kind == ValueKind.Atom) return v.atom != "false";
    return true;
}

bool valuesEqual(Value a, Value b) {
    if(a.kind != b.kind) return false;
    final switch(a.kind) {
        case ValueKind.Number:
            return a.number == b.number;
        case ValueKind.Atom:
            return a.atom == b.atom;
        case ValueKind.Tuple:
            if(a.tuple.length != b.tuple.length) return false;
            foreach(i, av; a.tuple)
                if(!valuesEqual(av, b.tuple[i])) return false;
            return true;
        case ValueKind.List:
            if(a.list.length != b.list.length) return false;
            foreach(i, av; a.list)
                if(!valuesEqual(av, b.list[i])) return false;
            return true;
        case ValueKind.Map:
            if(a.map.length != b.map.length) return false;
            foreach(k, v; a.map) {
                if(!(k in b.map)) return false;
                if(!valuesEqual(v, b.map[k])) return false;
            }
            return true;
    }
    return false;
}

Value handleRecordCall(string head, Expr e, ref bool handled) {
    foreach(recordName, fields; recordDefs) {
        auto makeName = "make-" ~ recordName;
        if(head == makeName) {
            Value[string] vals;
            for(size_t i = 1; i + 1 < e.list.length; i += 2) {
                auto fname = e.list[i].atom;
                vals[fname] = evalExpr(e.list[i+1]);
            }
            Value[] tup = [ atomVal(recordName) ];
            foreach(f; fields) {
                if(auto v = f in vals) tup ~= *v; else tup ~= atomVal("undefined");
            }
            handled = true;
            return tupleVal(tup);
        }
        auto setPrefix = "set-" ~ recordName ~ "-";
        if(head.startsWith(setPrefix)) {
            auto field = head[setPrefix.length .. $];
            size_t idx = fields.countUntil(field);
            if(idx < fields.length) {
                auto rec = evalExpr(e.list[1]);
                auto val = evalExpr(e.list[2]);
                Value[] tup;
                if(rec.kind == ValueKind.Tuple) tup = rec.tuple.dup; else {
                    tup = [atomVal(recordName)];
                    foreach(i; 0 .. fields.length) tup ~= atomVal("undefined");
                }
                if(tup.length != fields.length + 1) {
                    tup.length = fields.length + 1;
                    foreach(i; 0 .. fields.length) if(i+1 >= tup.length) tup ~= atomVal("undefined");
                }
                tup[0] = atomVal(recordName);
                tup[idx+1] = val;
                handled = true;
                return tupleVal(tup);
            }
        }
        auto getPrefix = recordName ~ "-";
        if(head.startsWith(getPrefix)) {
            auto field = head[getPrefix.length .. $];
            size_t idx = fields.countUntil(field);
            if(idx < fields.length) {
                auto rec = evalExpr(e.list[1]);
                if(rec.kind != ValueKind.Tuple || rec.tuple.length <= idx+1)
                    return atomVal("undefined");
                handled = true;
                return rec.tuple[idx+1];
            }
        }
    }
    handled = false;
    return num(0);
}

Value callFunctionDirect(string name, Value[] argVals) {
    auto key = name ~ "/" ~ to!string(argVals.length);
    if(auto fn = key in functions) {
        auto clauses = *fn;
        foreach(clause; clauses) {
            if(clause.params.length != argVals.length) continue;
            bool match = true;
            string[] varNames;
            Value[string] saved;
            foreach(i, pexp; clause.params) {
                auto val = argVals[i];
                if(!matchPattern(val, pexp, varNames, saved)) { match = false; break; }
            }
            if(match) {
                if(clause.hasGuard) {
                    auto gval = evalExpr(clause.guard);
                    bool pass = false;
                    if(gval.kind == ValueKind.Number) pass = gval.number != 0;
                    else if(gval.kind == ValueKind.Atom) pass = gval.atom != "false";
                    else pass = true;
                    if(!pass) {
                        foreach(k,v; saved) variables[k] = v;
                        foreach(n; varNames) if(!(n in saved)) variables.remove(n);
                        continue;
                    }
                }
                auto result = evalExpr(clause.body);
                foreach(k,v; saved) variables[k] = v;
                foreach(n; varNames) if(!(n in saved)) variables.remove(n);
                return result;
            } else {
                foreach(k,v; saved) variables[k] = v;
                foreach(n; varNames) if(!(n in saved)) variables.remove(n);
            }
        }
    }
    return num(0);
}

Expr callMacro(string name, Expr[] args) {
    auto m = macros[name];
    Value[string] saved;
    string[] varNames;
    foreach(i, pname; m.params) {
        if(i >= args.length) break;
        auto val = quoteValue(args[i]);
        if(pname in variables) saved[pname] = variables[pname];
        variables[pname] = val;
        varNames ~= pname;
    }
    auto result = evalExpr(m.body);
    foreach(k,v; saved) variables[k] = v;
    foreach(n; varNames) if(!(n in saved)) variables.remove(n);
    return valueToExpr(result);
}

Expr macroExpand(Expr e) {
    if(!e.isList) return e;
    if(e.list.length > 0 && !e.list[0].isList && e.list[0].atom == "quote")
        return e;
    auto cur = e;
    while(cur.isList && cur.list.length > 0 && !cur.list[0].isList && (cur.list[0].atom in macros)) {
        auto name = cur.list[0].atom;
        auto args = cur.list[1 .. $];
        cur = callMacro(name, args);
        if(!cur.isList) return cur;
    }
    if(!cur.isList) return cur;
    Expr[] newList;
    foreach(elem; cur.list) newList ~= macroExpand(elem);
    return Expr(true, cur.atom, newList, cur.isAtom, cur.isTuple, cur.isMap);
}

Value evalList(Expr e) {
    if(e.list.length == 0) return listVal([]);
    auto head = e.list[0].atom;
    if(head == "+") {
        double result = 0;
        foreach(arg; e.list[1 .. $]) result += evalExpr(arg).number;
        return num(result);
    } else if(head == "-") {
        double result = evalExpr(e.list[1]).number;
        foreach(arg; e.list[2 .. $]) result -= evalExpr(arg).number;
        return num(result);
    } else if(head == "*") {
        double result = 1;
        foreach(arg; e.list[1 .. $]) result *= evalExpr(arg).number;
        return num(result);
    } else if(head == "/") {
        double result = evalExpr(e.list[1]).number;
        foreach(arg; e.list[2 .. $]) result /= evalExpr(arg).number;
        return num(result);
    } else if(head == ">") {
        auto a = evalExpr(e.list[1]).number;
        auto b = evalExpr(e.list[2]).number;
        return atomVal(a > b ? "true" : "false");
    } else if(head == "<") {
        auto a = evalExpr(e.list[1]).number;
        auto b = evalExpr(e.list[2]).number;
        return atomVal(a < b ? "true" : "false");
    } else if(head == "=:=") {
        auto a = evalExpr(e.list[1]);
        auto b = evalExpr(e.list[2]);
        return atomVal(valuesEqual(a, b) ? "true" : "false");
    } else if(head == "is_atom") {
        auto v = evalExpr(e.list[1]);
        return atomVal(v.kind == ValueKind.Atom ? "true" : "false");
    } else if(head == "is_tuple") {
        auto v = evalExpr(e.list[1]);
        return atomVal(v.kind == ValueKind.Tuple ? "true" : "false");
    } else if(head == "is_list") {
        auto v = evalExpr(e.list[1]);
        return atomVal(v.kind == ValueKind.List ? "true" : "false");
    } else if(head == "is_number") {
        auto v = evalExpr(e.list[1]);
        return atomVal(v.kind == ValueKind.Number ? "true" : "false");
    } else if(head == "tuple") {
        Value[] els;
        foreach(arg; e.list[1 .. $]) els ~= evalExpr(arg);
        return tupleVal(els);
    } else if(head == "list") {
        Value[] els;
        foreach(arg; e.list[1 .. $]) els ~= evalExpr(arg);
        return listVal(els);
    } else if(head == "cons") {
        auto first = evalExpr(e.list[1]);
        auto rest = evalExpr(e.list[2]);
        Value[] combined = [first];
        if(rest.kind == ValueKind.List)
            combined ~= rest.list;
        return listVal(combined);
    } else if(head == "quote") {
        auto q = e.list[1];
        return quoteValue(q);
    } else if(head == "backquote") {
        auto q = e.list[1];
        return backquoteValue(q);
    } else if(head == "eval") {
        auto val = evalExpr(e.list[1]);
        auto expr = valueToExpr(val);
        return evalExpr(expr);
    } else if(head == "if") {
        auto condVal = evalExpr(e.list[1]);
        if(isTruthy(condVal))
            return evalExpr(e.list[2]);
        else
            return evalExpr(e.list[3]);
    } else if(head == "cond") {
        for(size_t i = 1; i < e.list.length; i++) {
            auto clause = e.list[i];
            if(clause.list.length < 2) continue;
            auto test = clause.list[0];
            auto body = clause.list[1];
            if(test.isList && test.list.length > 0 && !test.list[0].isList && test.list[0].atom == "?=") {
                auto pat = test.list[1];
                Expr guard; bool hasGuard = false; Expr valExpr;
                if(test.list.length == 4 && test.list[2].isList && test.list[2].list.length > 0 && !test.list[2].list[0].isList && test.list[2].list[0].atom == "when") {
                    guard = test.list[2].list[1];
                    hasGuard = true;
                    valExpr = test.list[3];
                } else if(test.list.length >= 3) {
                    valExpr = test.list[2];
                } else continue;
                auto val = evalExpr(valExpr);
                string[] varNames; Value[string] saved;
                if(matchPattern(val, pat, varNames, saved)) {
                    if(hasGuard && !isTruthy(evalExpr(guard))) {
                        foreach(k,v; saved) variables[k] = v;
                        foreach(n; varNames) if(!(n in saved)) variables.remove(n);
                        continue;
                    }
                    auto res = evalExpr(body);
                    foreach(k,v; saved) variables[k] = v;
                    foreach(n; varNames) if(!(n in saved)) variables.remove(n);
                    return res;
                } else {
                    foreach(k,v; saved) variables[k] = v;
                    foreach(n; varNames) if(!(n in saved)) variables.remove(n);
                }
            } else {
                auto val = evalExpr(test);
                if(isTruthy(val)) return evalExpr(body);
            }
        }
        return num(0);
    } else if(head == "case") {
        auto val = evalExpr(e.list[1]);
        for(size_t i = 2; i < e.list.length; i++) {
            auto clause = e.list[i];
            if(clause.list.length < 2) continue;
            auto pat = clause.list[0];
            Expr guard; bool hasGuard = false; Expr body;
            if(clause.list.length == 3 && clause.list[1].isList && clause.list[1].list.length > 0 && !clause.list[1].list[0].isList && clause.list[1].list[0].atom == "when") {
                guard = clause.list[1].list[1];
                hasGuard = true;
                body = clause.list[2];
            } else {
                body = clause.list[1];
            }
            string[] varNames; Value[string] saved;
            if(matchPattern(val, pat, varNames, saved)) {
                if(hasGuard && !isTruthy(evalExpr(guard))) {
                    foreach(k,v; saved) variables[k] = v;
                    foreach(n; varNames) if(!(n in saved)) variables.remove(n);
                    continue;
                }
                auto res = evalExpr(body);
                foreach(k,v; saved) variables[k] = v;
                foreach(n; varNames) if(!(n in saved)) variables.remove(n);
                return res;
            } else {
                foreach(k,v; saved) variables[k] = v;
                foreach(n; varNames) if(!(n in saved)) variables.remove(n);
            }
        }
        return num(0);
    } else if(head == "set") {
        auto name = e.list[1].atom;
        auto val = evalExpr(e.list[2]);
        variables[name] = val;
        return val;
    } else if(head == "let") {
        auto bindings = e.list[1];
        string[] names;
        Value[string] saved;
        foreach(b; bindings.list) {
            auto var = b.list[0].atom;
            auto val = evalExpr(b.list[1]);
            if(var in variables) saved[var] = variables[var];
            names ~= var;
            variables[var] = val;
        }
        Value result = num(0);
        for(size_t i = 2; i < e.list.length; i++) {
            result = evalExpr(e.list[i]);
        }
        foreach(n; names) {
            if(n in saved) variables[n] = saved[n];
            else variables.remove(n);
        }
        return result;
    } else if(head == "map") {
        Value[string] m;
        for(size_t i = 1; i + 1 < e.list.length; i += 2) {
            auto k = evalExpr(e.list[i]);
            auto v = evalExpr(e.list[i+1]);
            m[valueToString(k)] = v;
        }
        return mapVal(m);
    } else if(head == "map-update") {
        auto base = evalExpr(e.list[1]);
        Value[string] m;
        if(base.kind == ValueKind.Map)
            foreach(k, v; base.map) m[k] = v;
        for(size_t i = 2; i + 1 < e.list.length; i += 2) {
            auto k = evalExpr(e.list[i]);
            auto v = evalExpr(e.list[i+1]);
            m[valueToString(k)] = v;
        }
        return mapVal(m);
    } else if(head == "!") {
        auto pidVal = evalExpr(e.list[1]);
        auto msgVal = evalExpr(e.list[2]);
        string pid = pidVal.kind == ValueKind.Atom ? pidVal.atom : valueToString(pidVal);
        Process proc;
        synchronized(procMutex) {
            if(pid in processes) proc = processes[pid];
            else return atomVal("undefined");
        }
        synchronized(proc.m) {
            proc.inbox ~= msgVal;
            proc.c.notify();
        }
        return msgVal;
    } else if(head == "receive") {
        Process proc;
        synchronized(procMutex) {
            if(currentPid in processes) proc = processes[currentPid];
            else proc = new Process();
        }
        for(;;) {
            if(!proc.alive) throw new ExitException(atomVal("killed"));
            Value msg;
            synchronized(proc.m) {
                while(proc.inbox.length == 0) proc.c.wait();
                msg = proc.inbox[0];
                proc.inbox = proc.inbox[1 .. $];
            }
            foreach(clause; e.list[1 .. $]) {
                if(clause.list.length < 2) continue;
                auto pat = clause.list[0];
                string[] varNames; Value[string] saved;
                if(matchPattern(msg, pat, varNames, saved)) {
                    Value result = num(0);
                    for(size_t i = 1; i < clause.list.length; i++)
                        result = evalExpr(clause.list[i]);
                    foreach(k,v; saved) variables[k] = v;
                    foreach(n; varNames) if(!(n in saved)) variables.remove(n);
                    return result;
                } else {
                    foreach(k,v; saved) variables[k] = v;
                    foreach(n; varNames) if(!(n in saved)) variables.remove(n);
                }
            }
            synchronized(proc.m) {
                proc.inbox ~= msg;
            }
        }
    } else if(head == "self") {
        return atomVal(currentPid);
    } else if(head == "link") {
        auto pidVal = evalExpr(e.list[1]);
        string pid = pidVal.kind == ValueKind.Atom ? pidVal.atom : valueToString(pidVal);
        Process target; Process cur;
        synchronized(procMutex) {
            if(!(pid in processes)) return atomVal("undefined");
            target = processes[pid];
            if(currentPid in processes) cur = processes[currentPid];
        }
        synchronized(procMutex) {
            cur.links ~= pid;
            target.links ~= currentPid;
        }
        return atomVal("true");
    } else if(head == "spawn" || head == "spawn_link") {
        auto modVal = evalExpr(e.list[1]);
        auto funVal = evalExpr(e.list[2]);
        auto argsVal = evalExpr(e.list[3]);
        if(modVal.kind != ValueKind.Atom || funVal.kind != ValueKind.Atom || argsVal.kind != ValueKind.List)
            throw new Exception("badarg");
        string mod = modVal.atom;
        string fun = funVal.atom;
        auto argVals = argsVal.list.dup;
        auto pidNum = pidCounter++;
        string pid = "<" ~ to!string(pidNum) ~ ">";
        auto proc = new Process();
        synchronized(procMutex) processes[pid] = proc;
        if(head == "spawn_link") {
            Process cur;
            synchronized(procMutex) if(currentPid in processes) cur = processes[currentPid];
            cur.links ~= pid;
            proc.links ~= currentPid;
        }
        auto thr = new Thread({
            currentPid = pid;
            Value reason = atomVal("normal");
            try {
                callFunctionDirect(mod ~ ":" ~ fun, argVals);
            } catch(ExitException ex) {
                reason = ex.reason;
            } catch(Exception ex) {
                reason = atomVal("error");
            }
            propagateExit(pid, reason);
        });
        thr.start();
        return atomVal(pid);
    } else if(head == "process_flag") {
        auto flagVal = evalExpr(e.list[1]);
        auto valueVal = evalExpr(e.list[2]);
        if(flagVal.kind != ValueKind.Atom) throw new Exception("badarg");
        Process proc;
        synchronized(procMutex) {
            if(currentPid in processes) proc = processes[currentPid];
            else proc = new Process();
        }
        if(flagVal.atom == "trap_exit") {
            bool old = proc.trapExit;
            proc.trapExit = (valueVal.kind == ValueKind.Atom && valueVal.atom == "true");
            return atomVal(old ? "true" : "false");
        }
        return atomVal("false");
    } else if(head == "lfe_io:format") {
        auto fmtExpr = e.list[1];
        string fmt = fmtExpr.atom;
        if(fmt.length >= 2 && fmt[0] == '"' && fmt[$-1] == '"')
            fmt = fmt[1 .. $-1];
        auto argsVal = evalExpr(e.list[2]);
        if(argsVal.kind != ValueKind.List)
            throw new Exception("badarg");
        string result;
        size_t ai = 0;
        for(size_t i = 0; i < fmt.length; i++) {
            if(fmt[i] == '~' && i + 1 < fmt.length) {
                auto n = fmt[i+1];
                if(n == 'w') {
                    if(ai >= argsVal.list.length) throw new Exception("badarg");
                    result ~= formatValue(argsVal.list[ai++]);
                    i++;
                    continue;
                } else if(n == 'n') {
                    result ~= "\n";
                    i++;
                    continue;
                }
            }
            result ~= fmt[i];
        }
        write(result);
        return atomVal("ok");
    } else if(head == "echo") {
        bool newline = true;
        bool interpret = false;
        size_t idx = 1;
        while(idx < e.list.length) {
            auto optExpr = e.list[idx];
            if(!optExpr.isList && !optExpr.isAtom && optExpr.atom.startsWith("-")) {
                auto opt = optExpr.atom;
                if(opt == "-n") newline = false;
                else if(opt == "-e") interpret = true;
                else if(opt == "-E") interpret = false;
                else break;
                idx++;
            } else break;
        }
        string output;
        for(size_t i = idx; i < e.list.length; i++) {
            auto val = evalExpr(e.list[i]);
            output ~= formatValue(val);
            if(i + 1 < e.list.length) output ~= " ";
        }
        if(interpret) output = unescape(output);
        if(newline) output ~= "\n";
        write(output);
        return atomVal("ok");
    } else if(head == "cp") {
        auto srcVal = evalExpr(e.list[1]);
        auto dstVal = evalExpr(e.list[2]);
        string src = valueToString(srcVal);
        string dst = valueToString(dstVal);
        if(src.length >= 2 && src[0] == '"' && src[$-1] == '"')
            src = src[1 .. $-1];
        if(dst.length >= 2 && dst[0] == '"' && dst[$-1] == '"')
            dst = dst[1 .. $-1];
        try {
            copy(src, dst);
            return atomVal("ok");
        } catch(Exception e) {
            writeln("cp: failed to copy ", src, " to ", dst);
            return atomVal("error");
        }
    } else if(head == "local") {
        string[] toks = ["local"];
        foreach(expr; e.list[1 .. $])
            toks ~= valueToString(evalExpr(expr));
        local.localCommand(toks);
        return atomVal("ok");
    } else if(head == "locate") {
        string[] toks = ["locate"];
        foreach(expr; e.list[1 .. $])
            toks ~= valueToString(evalExpr(expr));
        locate.locateCommand(toks);
        return atomVal("ok");
    } else if(head == "login") {
        string[] toks = ["login"];
        foreach(expr; e.list[1 .. $])
            toks ~= valueToString(evalExpr(expr));
        login.loginCommand(toks);
        return atomVal("ok");
    } else if(head == "logname") {
        logname.lognameCommand(["logname"]);
        return atomVal("ok");
    } else if(head == "logout") {
        logout.logoutCommand(["logout"]);
        return num(0); /* unreachable */
    } else if(head == "cpio-create") {
        if(e.list.length < 3) return atomVal("error");
        auto archVal = evalExpr(e.list[1]);
        string arch = valueToString(archVal);
        if(arch.length >= 2 && arch[0] == '"' && arch[$-1] == '"')
            arch = arch[1 .. $-1];
        string[] files;
        foreach(expr; e.list[2 .. $]) {
            string p = valueToString(evalExpr(expr));
            if(p.length >= 2 && p[0] == '"' && p[$-1] == '"')
                p = p[1 .. $-1];
            files ~= p;
        }
        createArchive(arch, files);
        return atomVal("ok");
    } else if(head == "cpio-extract") {
        auto archVal = evalExpr(e.list[1]);
        string arch = valueToString(archVal);
        if(arch.length >= 2 && arch[0] == '"' && arch[$-1] == '"')
            arch = arch[1 .. $-1];
        extractArchive(toStringz(arch));
        return atomVal("ok");
    } else if(head == "head") {
        if(e.list.length < 2) return atomVal("error");
        auto fileVal = evalExpr(e.list[1]);
        string file = valueToString(fileVal);
        if(file.length >= 2 && file[0] == '"' && file[$-1] == '"')
            file = file[1 .. $-1];
        size_t lines = 10;
        if(e.list.length > 2)
            lines = cast(size_t)evalExpr(e.list[2]).number;
        try {
            auto text = readText(file).splitLines;
            size_t count = 0;
            foreach(l; text) {
                writeln(l);
                count++;
                if(count >= lines) break;
            }
            return atomVal("ok");
        } catch(Exception) {
            writeln("head: cannot read ", file);
            return atomVal("error");
        }
    } else if(head == "history") {
        foreach(i, cmd; historyLines)
            writeln(i + 1, " ", cmd);
        return atomVal("ok");
    } else if(head == "hostname") {
        version(Posix) {
            import core.sys.posix.unistd : gethostname;
            char[256] buf;
            if(e.list.length == 1) {
                auto len = gethostname(buf.ptr, buf.length);
                auto name = buf[0 .. (len < 0 ? 0 : len)];
                writeln(name);
            } else {
                auto val = evalExpr(e.list[1]);
                string name = valueToString(val);
                if(name.length >= 2 && name[0] == '"' && name[$-1] == '"')
                    name = name[1 .. $-1];
                sethostname(name.ptr, cast(size_t)name.length);
            }
            return atomVal("ok");
        } else {
            writeln("hostname not supported");
            return atomVal("error");
        }
    } else if(head == "htop") {
        string[] args;
        foreach(expr; e.list[1 .. $])
            args ~= valueToString(evalExpr(expr));
        string cmd = "htop" ~ (args.length ? " " ~ args.join(" ") : "");
        auto rc = system(cmd);
        if(rc != 0)
            writeln("htop failed with code ", rc);
        return num(rc);
    } else if(head == "proplists:get_value") {
        auto key = evalExpr(e.list[1]);
        auto plist = evalExpr(e.list[2]);
        Value defval = e.list.length > 3 ? evalExpr(e.list[3]) : atomVal("undefined");
        if(plist.kind != ValueKind.List) return defval;
        auto kstr = valueToString(key);
        foreach(item; plist.list) {
            if(item.kind == ValueKind.Tuple && item.tuple.length >= 2) {
                if(valueToString(item.tuple[0]) == kstr) return item.tuple[1];
            }
        }
        return defval;
    } else if(head == "defrecord") {
        auto rname = e.list[1].atom;
        string[] fields;
        foreach(f; e.list[2 .. $]) fields ~= f.atom;
        recordDefs[rname] = fields;
        return num(0);
    } else if(head == "defmacro") {
        auto name = e.list[1].atom;
        string[] params;
        foreach(p; e.list[2].list) params ~= p.atom;
        auto body = e.list[3];
        macros[name] = MacroDef(params, body);
        return num(0);
    } else if(head == "macroexpand") {
        auto val = evalExpr(e.list[1]);
        auto expr = valueToExpr(val);
        auto expanded = macroExpand(expr);
        return quoteValue(expanded);
    } else if(head == "defun") {
        auto name = e.list[1].atom;
        FunctionClause[] clauses;
        if(e.list.length > 4 || (e.list[2].isList && e.list[2].list.length == 2 && e.list[2].list[0].isList)) {
            foreach(cl; e.list[2 .. $]) {
                auto params = cl.list[0].list;
                Expr guard;
                bool hasGuard = false;
                Expr body;
                if(cl.list.length == 3 && cl.list[1].isList && cl.list[1].list.length > 0 && !cl.list[1].list[0].isList && cl.list[1].list[0].atom == "when") {
                    guard = cl.list[1].list[1];
                    hasGuard = true;
                    body = cl.list[2];
                } else {
                    body = cl.list[1];
                }
                clauses ~= FunctionClause(params, body, guard, hasGuard);
            }
        } else {
            auto params = e.list[2].list;
            Expr guard;
            bool hasGuard = false;
            auto body = e.list[3];
            clauses ~= FunctionClause(params, body, guard, hasGuard);
        }
        auto arity = clauses[0].params.length;
        string entry = name ~ "/" ~ to!string(arity);
        string mod = currentModule.length ? currentModule : "global";
        string key = mod == "global" ? entry : mod ~ ":" ~ entry;
        functions[key] = clauses;
        if(!(mod in moduleFunctions)) moduleFunctions[mod] = [];
        if(!moduleFunctions[mod].canFind(entry)) moduleFunctions[mod] ~= entry;
        return num(0);
    } else if(head == "defmodule") {
        auto modName = e.list[1].atom;
        currentModule = modName;
        foreach(expr; e.list[2 .. $]) {
            if(expr.isList && expr.list.length > 0 && expr.list[0].atom == "defun") {
                auto fname = expr.list[1].atom;
                FunctionClause[] clauses;
                if(expr.list.length > 4 || (expr.list[2].isList && expr.list[2].list.length == 2 && expr.list[2].list[0].isList)) {
                    foreach(cl; expr.list[2 .. $]) {
                        auto params = cl.list[0].list;
                        Expr guard;
                        bool hasGuard = false;
                        Expr body;
                        if(cl.list.length == 3 && cl.list[1].isList && cl.list[1].list.length > 0 && !cl.list[1].list[0].isList && cl.list[1].list[0].atom == "when") {
                            guard = cl.list[1].list[1];
                            hasGuard = true;
                            body = cl.list[2];
                        } else {
                            body = cl.list[1];
                        }
                        clauses ~= FunctionClause(params, body, guard, hasGuard);
                    }
                } else {
                    auto params = expr.list[2].list;
                    Expr guard;
                    bool hasGuard = false;
                    auto body = expr.list[3];
                    clauses ~= FunctionClause(params, body, guard, hasGuard);
                }
                auto arity = clauses[0].params.length;
                functions[modName ~ ":" ~ fname ~ "/" ~ to!string(arity)] = clauses;
                string entry = fname ~ "/" ~ to!string(arity);
                if(!(modName in moduleFunctions)) moduleFunctions[modName] = [];
                if(!moduleFunctions[modName].canFind(entry)) moduleFunctions[modName] ~= entry;
            } else if(expr.isList && expr.list.length > 0 && expr.list[0].atom == "defmacro") {
                auto mname = expr.list[1].atom;
                string[] params;
                foreach(p; expr.list[2].list) params ~= p.atom;
                auto body = expr.list[3];
                macros[mname] = MacroDef(params, body);
            }
        }
        return num(0);
    } else if(head == "c") {
        auto fexpr = e.list[1];
        auto path = fexpr.atom;
        if(path.length >= 2 && path[0] == '"' && path[$-1] == '"')
            path = path[1 .. $-1];
        loadFile(path);
        return num(0);
    } else if(head == "exec") {
        if(e.list.length < 2) return atomVal("error");
        string cmd = valueToString(evalExpr(e.list[1]));
        string[] args;
        foreach(expr; e.list[2 .. $]) {
            auto v = evalExpr(expr);
            string s = valueToString(v);
            if(s.length >= 2 && s[0] == '"' && s[$-1] == '"')
                s = s[1 .. $-1];
            args ~= s;
        }
        if(cmd.length >= 2 && cmd[0] == '"' && cmd[$-1] == '"')
            cmd = cmd[1 .. $-1];
        version(Posix) {
            import std.string : toStringz;
            import core.stdc.stdlib : exit;
            const(char)*[] argv;
            argv ~= cmd.toStringz;
            foreach(a; args) argv ~= a.toStringz;
            argv ~= null;
            execvp(cmd.toStringz, argv.ptr);
            writeln("exec failed: " ~ cmd);
            exit(127);
        } else {
            auto line = cmd ~ (args.length ? " " ~ args.join(" ") : "");
            auto rc = system(line);
            import core.stdc.stdlib : exit;
            exit(rc);
        }
    } else if(head == "resolve") {
        auto pathVal = evalExpr(e.list[1]);
        string p = valueToString(pathVal);
        auto h = objectsystem.resolve(p);
        return atomVal(h.length ? h : "undefined");
    } else if(head == "bind") {
        auto srcVal = evalExpr(e.list[1]);
        auto dstVal = evalExpr(e.list[2]);
        bool ok = objectsystem.bind(valueToString(srcVal), valueToString(dstVal));
        return atomVal(ok ? "true" : "false");
    } else if(head == "clone") {
        auto objVal = evalExpr(e.list[1]);
        auto id = objectsystem.cloneObj(valueToString(objVal));
        return atomVal(id.length ? id : "undefined");
    } else if(head == "delete") {
        auto objVal = evalExpr(e.list[1]);
        bool ok = objectsystem.deleteObj(valueToString(objVal));
        return atomVal(ok ? "true" : "false");
    } else if(head == "list") {
        auto objVal = evalExpr(e.list[1]);
        auto items = objectsystem.list(valueToString(objVal));
        Value[] vals;
        foreach(i; items) vals ~= atomVal(i);
        return listVal(vals);
    } else if(head == "introspect") {
        auto objVal = evalExpr(e.list[1]);
        auto info = objectsystem.introspect(valueToString(objVal));
        return atomVal(info);
    } else if(head == "rename") {
        auto objVal = evalExpr(e.list[1]);
        auto newVal = evalExpr(e.list[2]);
        bool ok = objectsystem.rename(valueToString(objVal), valueToString(newVal));
        return atomVal(ok ? "true" : "false");
    } else if(head == "getType") {
        auto objVal = evalExpr(e.list[1]);
        auto t = objectsystem.getType(valueToString(objVal));
        return atomVal(t);
    } else if(head == "getProp") {
        auto objVal = evalExpr(e.list[1]);
        auto keyVal = evalExpr(e.list[2]);
        auto val = objectsystem.getProp(valueToString(objVal), valueToString(keyVal));
        return atomVal(val);
    } else if(head == "setProp") {
        auto objVal = evalExpr(e.list[1]);
        auto keyVal = evalExpr(e.list[2]);
        auto valVal = evalExpr(e.list[3]);
        bool ok = objectsystem.setProp(valueToString(objVal), valueToString(keyVal), valueToString(valVal));
        return atomVal(ok ? "true" : "false");
    } else if(head == "listProps") {
        auto objVal = evalExpr(e.list[1]);
        auto props = objectsystem.listProps(valueToString(objVal));
        Value[] vals; foreach(p; props) vals ~= atomVal(p);
        return listVal(vals);
    } else if(head == "delProp") {
        auto objVal = evalExpr(e.list[1]);
        auto keyVal = evalExpr(e.list[2]);
        bool ok = objectsystem.delProp(valueToString(objVal), valueToString(keyVal));
        return atomVal(ok ? "true" : "false");
    } else if(head == "listMethods") {
        auto objVal = evalExpr(e.list[1]);
        auto meths = objectsystem.listMethods(valueToString(objVal));
        Value[] vals; foreach(m; meths) vals ~= atomVal(m);
        return listVal(vals);
    } else if(head == "call") {
        auto objVal = evalExpr(e.list[1]);
        auto mVal = evalExpr(e.list[2]);
        string[] args; foreach(a; e.list[3 .. $]) args ~= valueToString(evalExpr(a));
        auto res = objectsystem.callMethod(valueToString(objVal), valueToString(mVal), args);
        return atomVal(res);
    } else if(head == "describeMethod") {
        auto objVal = evalExpr(e.list[1]);
        auto mVal = evalExpr(e.list[2]);
        auto d = objectsystem.describeMethod(valueToString(objVal), valueToString(mVal));
        return atomVal(d);
    } else if(head == "createObject") {
        auto tVal = evalExpr(e.list[1]);
        auto id = objectsystem.createObject(valueToString(tVal));
        return atomVal(id);
    } else if(head == "instantiate") {
        auto cVal = evalExpr(e.list[1]);
        auto id = objectsystem.instantiate(valueToString(cVal));
        return atomVal(id);
    } else if(head == "defineClass") {
        auto pVal = evalExpr(e.list[1]);
        auto dVal = evalExpr(e.list[2]);
        bool ok = objectsystem.defineClass(valueToString(pVal), valueToString(dVal));
        return atomVal(ok ? "true" : "false");
    } else if(head == "attach") {
        auto parent = valueToString(evalExpr(e.list[1]));
        auto child = valueToString(evalExpr(e.list[2]));
        auto aliasName = valueToString(evalExpr(e.list[3]));
        bool ok = objectsystem.attach(parent, child, aliasName);
        return atomVal(ok ? "true" : "false");
    } else if(head == "detach") {
        auto parent = valueToString(evalExpr(e.list[1]));
        auto name = valueToString(evalExpr(e.list[2]));
        bool ok = objectsystem.detach(parent, name);
        return atomVal(ok ? "true" : "false");
    } else if(head == "getParent") {
        auto objVal = evalExpr(e.list[1]);
        auto p = objectsystem.getParent(valueToString(objVal));
        return atomVal(p);
    } else if(head == "getChildren") {
        auto objVal = evalExpr(e.list[1]);
        auto ch = objectsystem.getChildren(valueToString(objVal));
        Value[] vals; foreach(c; ch) vals ~= atomVal(c);
        return listVal(vals);
    } else if(head == "sandbox") {
        auto objVal = evalExpr(e.list[1]);
        auto id = objectsystem.sandbox(valueToString(objVal));
        return atomVal(id);
    } else if(head == "isIsolated") {
        auto objVal = evalExpr(e.list[1]);
        bool iso = objectsystem.isIsolated(valueToString(objVal));
        return atomVal(iso ? "true" : "false");
    } else if(head == "seal") {
        auto objVal = evalExpr(e.list[1]);
        bool ok = objectsystem.seal(valueToString(objVal));
        return atomVal(ok ? "true" : "false");
    } else if(head == "verify") {
        auto objVal = evalExpr(e.list[1]);
        auto h = objectsystem.verify(valueToString(objVal));
        return atomVal(h);
    } else if(head == "sh") {
        if (e.list.length < 2) {
            throw new Exception("sh: missing command");
        }
        string[] cmdArgs;
        foreach(arg; e.list[1 .. $]) {
            auto val = evalExpr(arg);
            cmdArgs ~= formatValue(val);
        }
        auto pipes = pipeProcess(cmdArgs);
        auto output = cast(string) pipes.stdout.byChunk(4096).joiner.array;
        auto error = cast(string) pipes.stderr.byChunk(4096).joiner.array;
        auto status = wait(pipes.pid);

        Value[] resultTuple = [
            num(status),
            atomVal(output.strip),
            atomVal(error.strip)
        ];
        return tupleVal(resultTuple);
    } else if(head == "exit") {
        Value reason = atomVal("normal");
        if(e.list.length > 1) reason = evalExpr(e.list[1]);
        throw new ExitException(reason);
    } else {
        bool recHandled = false;
        auto res = handleRecordCall(head, e, recHandled);
        if(recHandled) return res;
        auto key = head ~ "/" ~ to!string(e.list.length - 1);
        FunctionClause[]* fn;
        string fnModule;
        if(auto fptr = key in functions) {
            fn = fptr;
            auto colon = head.indexOf(":");
            if(colon != -1) fnModule = head[0 .. colon];
        } else if(currentModule.length) {
            auto modKey = currentModule ~ ":" ~ key;
            if(auto fptr2 = modKey in functions) {
                fn = fptr2;
                fnModule = currentModule;
            }
        }
        if(fn !is null) {
            auto clauses = *fn;
            auto args = e.list[1 .. $];
            auto prevMod = currentModule;
            if(fnModule.length) currentModule = fnModule;
            foreach(clause; clauses) {
                if(clause.params.length != args.length) continue;
                bool match = true;
                string[] varNames;
                Value[string] saved;
                Value[] argVals;
                foreach(a; args) argVals ~= evalExpr(a);
                foreach(i, pexp; clause.params) {
                    auto val = argVals[i];
                    if(!matchPattern(val, pexp, varNames, saved)) { match = false; break; }
                }
                if(match) {
                    if(clause.hasGuard) {
                        auto gval = evalExpr(clause.guard);
                        bool pass = false;
                        if(gval.kind == ValueKind.Number) pass = gval.number != 0;
                        else if(gval.kind == ValueKind.Atom) pass = gval.atom != "false";
                        else pass = true;
                        if(!pass) {
                            foreach(k,v; saved) variables[k] = v;
                            foreach(n; varNames) if(!(n in saved)) variables.remove(n);
                            continue;
                        }
                    }
                    auto result = evalExpr(clause.body);
                    foreach(k,v; saved) variables[k] = v;
                    foreach(n; varNames) if(!(n in saved)) variables.remove(n);
                    currentModule = prevMod;
                    return result;
                } else {
                    foreach(k,v; saved) variables[k] = v;
                    foreach(n; varNames) if(!(n in saved)) variables.remove(n);
                }
            }
            currentModule = prevMod;
            return num(0);
        }
        return num(0);
    }
    return num(0);
}

Value evalExpr(Expr e) {
    if(e.isList) {
        e = macroExpand(e);
    } else {
        if(e.isAtom) return atomVal(e.atom);
        if(isNumber(e.atom)) return num(to!double(e.atom));
        if(auto v = e.atom in variables) return *v;
        // If a symbol is not a number and not a variable, treat it as a string atom.
        return atomVal(e.atom);
    }
    if(e.isTuple) {
        Value[] elems;
        foreach(sub; e.list) elems ~= evalExpr(sub);
        return tupleVal(elems);
    }
    if(e.isMap) {
        Value[string] m;
        for(size_t i = 0; i + 1 < e.list.length; i += 2) {
            auto k = evalExpr(e.list[i]);
            auto v = evalExpr(e.list[i+1]);
            m[valueToString(k)] = v;
        }
        return mapVal(m);
    }
    return evalList(e);
}

void repl() {
    currentPid = "<0>";
    writeln("LFE REPL -- type (exit) to quit");
    auto lex = new Lexer(rules);
    for(;;) {
        write("lfe> ");
        auto line = readln();
        if(line is null) break;
        line = line.strip;
        if(line.length == 0) continue;
        historyLines ~= line;
        auto tabPos = line.indexOf('\t');
        if(tabPos >= 0) {
            auto prefix = line[0 .. tabPos];
            showCompletions(prefix);
            continue;
        }
        auto toks = lex.tokenize(line);
        toks = toks.filter!(t => t.type != "WS").array;
        auto parser = new LfeParser(toks);
        Expr ast;
        try {
            ast = parser.parseExpr();
            auto result = evalExpr(ast);
            writeln(valueToString(result));
        } catch(ExitException ex) {
            break;
        } catch(Exception e) {
            writeln("Error: ", e.msg);
        }
    }
}

/// Start the minimal LFE REPL.
void lfereplMain() {
    repl();
}

