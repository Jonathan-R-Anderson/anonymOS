// expr_lex.d — D port of your C lexer/driver
module expr_lex;

import std.stdio  : stderr, writeln, writefln;
import std.string : toStringz;
import std.conv   : to;
import std.ascii  : isDigit;

// ================================
// Bison/Yacc interop
// ================================
extern (C):
    // Bison parser entry
    int yyparse();

    // Value type expected by the parser (mirrors `#define YYSTYPE long long`)
    __gshared long yylval;

    // Error callback used by the parser
    void yyerror(const char* s);

// ================================
// Token codes
// IMPORTANT: Ensure these values match your generated expr-parse.h
// ================================

// Single-char tokens use their ASCII codes (same as in your C enum)
enum TOK_LPAREN = cast(int) '('; // (
enum TOK_RPAREN = cast(int) ')'; // )
enum TOK_OR     = cast(int) '|'; // |
enum TOK_AND    = cast(int) '&'; // &
enum TOK_EQ     = cast(int) '='; // =
enum TOK_GT     = cast(int) '>'; // >
enum TOK_LT     = cast(int) '<'; // <
enum TOK_ADD    = cast(int) '+'; // +
enum TOK_SUB    = cast(int) '-'; // -
enum TOK_MUL    = cast(int) '*'; // *
enum TOK_DIV    = cast(int) '/'; // /
enum TOK_MOD    = cast(int) '%'; // %
enum TOK_COLON  = cast(int) ':'; // :

// Multi-char/operator and lexical tokens.
// If your bison header defines different numbers, copy them here.
enum TOK_GE   = 258; // >=
enum TOK_LE   = 259; // <=
enum TOK_NE   = 260; // !=
enum TOK_STR  = 261; // bare string/symbol
enum TOK_NUM  = 262; // integer literal

// End-of-input
enum TOK_EOF  = 0;

// ================================
// Lexer state
// ================================
__gshared string[] gTokens;

// ================================
// Helpers
// ================================
@safe nothrow:
bool isIntStr(const string s)
{
    if (s.length == 0) return false;
    foreach (i, c; s)
    {
        if (c.isDigit) continue;
        if (i == 0 && c == '-') continue;
        return false;
    }
    return true;
}

int parseToken(const string s) @safe
{
    // single-char / simple tokens
    if      (s == "(")  return TOK_LPAREN;
    else if (s == ")")  return TOK_RPAREN;
    else if (s == "|")  return TOK_OR;
    else if (s == "&")  return TOK_AND;
    else if (s == "=")  return TOK_EQ;
    else if (s == ">")  return TOK_GT;
    else if (s == "<")  return TOK_LT;
    else if (s == "+")  return TOK_ADD;
    else if (s == "-")  return TOK_SUB;
    else if (s == "*")  return TOK_MUL;
    else if (s == "/")  return TOK_DIV;
    else if (s == "%")  return TOK_MOD;
    else if (s == ":")  return TOK_COLON;

    // multi-char comparison ops
    else if (s == ">=") return TOK_GE;
    else if (s == "<=") return TOK_LE;
    else if (s == "!=") return TOK_NE;

    // numbers and strings
    else if (isIntStr(s)) return TOK_NUM;
    else return TOK_STR;
}

// ================================
// C-callable error & lexer
// ================================
extern (C) void yyerror(const char* s)
{
    // Mirror your C version: just print the error text
    stderr.writeln(s);
}

extern (C) int yylex()
{
    if (gTokens.length == 0)
        return TOK_EOF;

    auto s = gTokens[0];
    gTokens = gTokens[1 .. $];

    const tt = parseToken(s);

    // Set yylval for numeric tokens
    if (tt == TOK_NUM)
    {
        // strtoll base-10 behavior; throws on invalid (but parseToken protected us)
        // D's `long` is 64-bit on 64-bit platforms, matching `long long`.
        yylval = s.to!long;
    }

    return tt;
}

// ================================
// main: push argv tokens then call yyparse
// ================================
int main(string[] args)
{
    // argv[1:] are directly treated as lexical tokens (like your C)
    if (args.length > 1)
        gTokens = args[1 .. $].dup;

    // Hand off to the parser
    return yyparse();
}
