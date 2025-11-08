// tools/posixutils/expr/expr.d
module expr_lex;

extern (C) {
    // From the Bison-generated parser (expr_parse.c / .o)
    int  yyparse();
    __gshared long yylval;          // must match YYSTYPE long long
}

import core.stdc.stdio  : fprintf, stderr;
import core.stdc.stdlib : strtoll;
import core.stdc.string : strcmp;

// ----------------------
// Token codes (match parser!)
// ----------------------
enum TOK_LPAREN = cast(int) '(';
enum TOK_RPAREN = cast(int) ')';
enum TOK_OR     = cast(int) '|';
enum TOK_AND    = cast(int) '&';
enum TOK_EQ     = cast(int) '=';
enum TOK_GT     = cast(int) '>';
enum TOK_LT     = cast(int) '<';
enum TOK_ADD    = cast(int) '+';
enum TOK_SUB    = cast(int) '-';
enum TOK_MUL    = cast(int) '*';
enum TOK_DIV    = cast(int) '/';
enum TOK_MOD    = cast(int) '%';
enum TOK_COLON  = cast(int) ':';

// Keep these numbers in sync with your Bison header
enum TOK_GE   = 258; // >=
enum TOK_LE   = 259; // <=
enum TOK_NE   = 260; // !=
enum TOK_STR  = 261; // symbol/string
enum TOK_NUM  = 262; // integer
enum TOK_EOF  = 0;

// ----------------------
// argv-backed lexer state
// ----------------------
__gshared int    gArgc;
__gshared char** gArgv;
__gshared int    gIdx = 1; // start at argv[1]

// ----------------------
// tiny helpers (no Phobos)
// ----------------------

@nogc nothrow
static bool isDigit(const char c) { return c >= '0' && c <= '9'; }

@nogc nothrow
static bool isIntStr(const char* s)
{
    if (s is null || *s == 0) return false;
    int i = 0;
    if (s[i] == '-') { ++i; if (s[i] == 0) return false; }
    for (; s[i] != 0; ++i) if (!isDigit(s[i])) return false;
    return true;
}

@nogc nothrow
static int parseToken(const char* s)
{
    // single-char tokens
    if      (strcmp(s, "(") == 0) return TOK_LPAREN;
    else if (strcmp(s, ")") == 0) return TOK_RPAREN;
    else if (strcmp(s, "|") == 0) return TOK_OR;
    else if (strcmp(s, "&") == 0) return TOK_AND;
    else if (strcmp(s, "=") == 0) return TOK_EQ;
    else if (strcmp(s, ">") == 0) return TOK_GT;
    else if (strcmp(s, "<") == 0) return TOK_LT;
    else if (strcmp(s, "+") == 0) return TOK_ADD;
    else if (strcmp(s, "-") == 0) return TOK_SUB;
    else if (strcmp(s, "*") == 0) return TOK_MUL;
    else if (strcmp(s, "/") == 0) return TOK_DIV;
    else if (strcmp(s, "%") == 0) return TOK_MOD;
    else if (strcmp(s, ":") == 0) return TOK_COLON;

    // multi-char
    else if (strcmp(s, ">=") == 0) return TOK_GE;
    else if (strcmp(s, "<=") == 0) return TOK_LE;
    else if (strcmp(s, "!=") == 0) return TOK_NE;

    // classify
    else if (isIntStr(s)) return TOK_NUM;
    else return TOK_STR;
}

// ----------------------
// C-callable hooks
// ----------------------
extern (C) @nogc nothrow void yyerror(const char* s)
{
    fprintf(stderr, "%s\n", s ? s : "parse error");
}

extern (C) @nogc nothrow int yylex()
{
    if (gIdx >= gArgc)
        return TOK_EOF;

    const char* s = gArgv[gIdx++];
    const int   tt = parseToken(s);

    if (tt == TOK_NUM)
        yylval = cast(long) strtoll(s, null, 10);

    // If your grammar needs the actual string for TOK_STR, you’ll need
    // YYSTYPE to carry a pointer and lifetime management. With pure
    // long long yylval, the parser must treat TOK_STR by token only.

    return tt;
}

// ----------------------
// main (do NOT mark @nogc/nothrow)
// ----------------------
extern (C) int main(int argc, char** argv)
{
    gArgc = argc;
    gArgv = argv;
    gIdx  = 1;
    return yyparse();
}

// ---------------------------------------------
// Optional: stub yyparse() to satisfy linking
// Use: add -version=NoBison when building D file
// ---------------------------------------------
version (NoBison)
extern (C) int yyparse()
{
    yyerror("yyparse() not linked (build your Bison parser and link it).");
    return 2;
}
