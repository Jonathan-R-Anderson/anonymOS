// dash syntax trees.  Everything here is permanent (malloc, never collected): closures point into
// it, and it is small -- it only grows with what the user types.
module dash.ast;

import dash.rt;

enum NK : ubyte {
    Int, Float, Str, Char, Unit,
    Var, Con, App, Lam, Let, If, Case, List, Range, Comp, Tuple, Rec, RecUpd,
    Field,        // a.name
    FieldSel,     // (.name)
    TypeMember,   // Domain.start  (a member of a type, as a function of the object)
    SectionL,     // (x +)
    SectionR,     // (+ x)
    OpFn,         // (+)
    Neg, Do, Cmd, CmdSub, Seq,
}

struct Node {
    NK k;
    long i; double f; const(char)[] s;   // literal payloads; Cmd/CmdSub source text
    Sym sym;                              // Var/Con/Field/op name
    Node* a, b, c;                        // generic children
    Node*[] kids;                         // List/Tuple/Rec/App args
    Pat*[] pats;                          // Lam
    Decl*[] decls;                        // Let
    Alt*[] alts;                          // Case
    Qual*[] quals;                        // Comp
    Stmt*[] stmts;                        // Do
    Sym[] keys;                           // Rec/RecUpd
    void* cache;                          // Cmd: the parsed command (lazily)
    uint line, col;
}

enum PK : ubyte { Var, Wild, Int, Float, Str, Char, Unit, Con, Cons, List, Tuple, As, Rec }
struct Pat {
    PK k;
    Sym sym;            // Var / Con / As name
    long i; double f; const(char)[] s;
    Pat*[] kids;        // Con args / List / Tuple / Cons (head, tail) / As (inner) / Rec field pats
    Sym[] keys;         // Rec
}

struct Guard { Node* cond; Node* body; }
struct Rhs { Node* body; Guard*[] guards; Decl*[] wheres; }

enum DK : ubyte { Fun, PatBind, Sig, Data, Ext }
struct Decl {
    DK k;
    Sym name;           // Fun/Sig: the function; Ext: the member; Data: the type
    Sym type;           // Ext: the object type it extends
    Pat*[] params;      // Fun/Ext
    Pat* pat;           // PatBind
    Rhs rhs;
    const(char)[] text; // Sig: the type text; Data: the declaration text
    Ctor*[] ctors;      // Data
    Sym[] names;        // Sig: every name the signature covers
    uint line;
}
struct Ctor { Sym name; uint arity; Sym[] fields; }

struct Alt { Pat* pat; Node* body; Guard*[] guards; Decl*[] wheres; }
enum QK : ubyte { Gen, Guard, Let }
struct Qual { QK k; Pat* pat; Node* e; Decl*[] decls; }
enum SK : ubyte { Expr, Bind, Let, Cmd }
struct Stmt { SK k; Pat* pat; Node* e; Decl*[] decls; }

@nogc nothrow:

T* pnew(T)() { auto p = cast(T*)calloc(1, T.sizeof); return p; }
Node* mkNode(NK k, uint line = 0, uint col = 0) { auto n = pnew!Node(); n.k = k; n.line = line; n.col = col; return n; }
Pat* mkPat(PK k) { auto p = pnew!Pat(); p.k = k; return p; }

// A permanent slice built from a Vec.
T[] permSlice(T)(ref Vec!T v) {
    if (v.n == 0) return null;
    auto p = cast(T*)malloc(v.n * T.sizeof);
    memcpy(p, v.p, v.n * T.sizeof);
    auto r = p[0 .. v.n];
    v.dispose();
    return r;
}
