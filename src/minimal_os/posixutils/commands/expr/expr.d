// tools/posixutils/expr/expr.d
module expr_lex;

extern (C) {
    // From the Bison-generated parser (expr_parse.c / .o)
    int  yyparse();
    __gshared long yylval;          // must match YYSTYPE long long
}

import core.stdc.stdio  : fprintf, printf, stderr;
import core.stdc.stdlib : strtoll;
import core.stdc.string : strcmp;
import std.conv         : ConvException, to;
import std.regex        : matchFirst, regex;
import std.string       : fromStringz, toStringz;

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
__gshared const(char)* gTokenText;

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
    else if (strcmp(s, "==") == 0) return TOK_EQ;
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
// Parser implementation
// ----------------------

private class ExprException : Exception
{
    this(string message)
    {
        super(message);
    }
}

private struct Value
{
    bool isNumber;
    long number;
    string text;
}

private Value makeNumber(long value)
{
    return Value(true, value, null);
}

private Value makeString(string text)
{
    return Value(false, 0, text);
}

private string valueToString(Value value)
{
    if (value.isNumber)
        return to!string(value.number);
    return value.text is null ? "" : value.text;
}

private bool truthy(Value value)
{
    if (value.isNumber)
        return value.number != 0;
    auto text = value.text;
    return text !is null && text.length != 0;
}

private void reportError(string message)
{
    yyerror(toStringz(message));
    throw new ExprException(message);
}

private void nonIntegerArgument()
{
    reportError("expr: non-integer argument");
}

private void divisionByZero()
{
    reportError("expr: division by zero");
}

private void unexpectedToken(string token)
{
    reportError("expr: syntax error: unexpected '" ~ token ~ "'");
}

private void unexpectedArgument(string token)
{
    reportError("expr: syntax error: unexpected argument '" ~ token ~ "'");
}

private void unexpectedEndOfExpression()
{
    reportError("expr: syntax error: unexpected end of expression");
}

private void missingArgument(string keyword)
{
    reportError("expr: syntax error: missing argument after '" ~ keyword ~ "'");
}

private bool tryToLong(Value value, ref long result)
{
    if (value.isNumber)
    {
        result = value.number;
        return true;
    }

    auto text = valueToString(value);
    if (!text.length)
        return false;

    try
    {
        result = to!long(text);
        return true;
    }
    catch (ConvException)
    {
        return false;
    }
}

private long requireInteger(Value value)
{
    long result;
    if (tryToLong(value, result))
        return result;
    nonIntegerArgument();
    return 0;
}

private Value applyRegex(Value baseValue, Value regexValue)
{
    auto text = valueToString(baseValue);
    auto pattern = valueToString(regexValue);
    try
    {
        auto rx = regex("^" ~ pattern);
        auto match = matchFirst(text, rx);
        if (match.empty)
            return makeNumber(0);
        if (match.captures.length > 1)
            return makeString(match.captures[1]);
        return makeNumber(cast(long) match.hit.length);
    }
    catch (Exception)
    {
        return makeNumber(0);
    }
}

private string tokenFallback(int token)
{
    switch (token)
    {
        case TOK_LPAREN: return "(";
        case TOK_RPAREN: return ")";
        case TOK_OR: return "|";
        case TOK_AND: return "&";
        case TOK_EQ: return "=";
        case TOK_GT: return ">";
        case TOK_LT: return "<";
        case TOK_ADD: return "+";
        case TOK_SUB: return "-";
        case TOK_MUL: return "*";
        case TOK_DIV: return "/";
        case TOK_MOD: return "%";
        case TOK_COLON: return ":";
        case TOK_GE: return ">=";
        case TOK_LE: return "<=";
        case TOK_NE: return "!=";
        case TOK_EOF: return "end of expression";
        default: return "token";
    }
}

private struct Parser
{
    int    current;
    string lexeme;
    long   numberValue;

    void nextToken()
    {
        current = yylex();
        if (current == TOK_EOF)
        {
            lexeme = "";
            return;
        }
        lexeme = gTokenText is null ? "" : fromStringz(gTokenText);
        if (current == TOK_NUM)
            numberValue = yylval;
    }

    string currentTokenText() const
    {
        if (lexeme.length)
            return lexeme;
        return tokenFallback(current);
    }

    Value parseExpr()
    {
        return parseOr();
    }

    Value parseOr()
    {
        auto value = parseAnd();
        while (current == TOK_OR)
        {
            nextToken();
            auto rhs = parseAnd();
            if (!truthy(value))
                value = rhs;
        }
        return value;
    }

    Value parseAnd()
    {
        auto value = parseCompare();
        while (current == TOK_AND)
        {
            nextToken();
            auto rhs = parseCompare();
            if (truthy(value) && truthy(rhs))
            {
                // keep the left-hand value
            }
            else
            {
                value = makeNumber(0);
            }
        }
        return value;
    }

    Value parseCompare()
    {
        auto value = parseAdd();
        while (current == TOK_EQ || current == TOK_GT || current == TOK_LT ||
               current == TOK_GE || current == TOK_LE || current == TOK_NE)
        {
            auto op = current;
            nextToken();
            auto rhs = parseAdd();
            const bool result = performComparison(value, rhs, op);
            value = makeNumber(result ? 1 : 0);
        }
        return value;
    }

    Value parseAdd()
    {
        auto value = parseMul();
        while (current == TOK_ADD || current == TOK_SUB)
        {
            auto op = current;
            nextToken();
            auto rhs = parseMul();
            const long lhsNum = requireInteger(value);
            const long rhsNum = requireInteger(rhs);
            if (op == TOK_ADD)
                value = makeNumber(lhsNum + rhsNum);
            else
                value = makeNumber(lhsNum - rhsNum);
        }
        return value;
    }

    Value parseMul()
    {
        auto value = parseMatchSequence();
        while (current == TOK_MUL || current == TOK_DIV || current == TOK_MOD)
        {
            auto op = current;
            nextToken();
            auto rhs = parseMatchSequence();
            const long lhsNum = requireInteger(value);
            const long rhsNum = requireInteger(rhs);
            switch (op)
            {
                case TOK_MUL:
                    value = makeNumber(lhsNum * rhsNum);
                    break;
                case TOK_DIV:
                    if (rhsNum == 0)
                        divisionByZero();
                    value = makeNumber(lhsNum / rhsNum);
                    break;
                case TOK_MOD:
                    if (rhsNum == 0)
                        divisionByZero();
                    value = makeNumber(lhsNum % rhsNum);
                    break;
                default:
                    break;
            }
        }
        return value;
    }

    Value parseMatchSequence()
    {
        auto value = parsePrimary();
        while (current == TOK_COLON)
        {
            nextToken();
            auto rhs = parsePrimary();
            value = applyRegex(value, rhs);
        }
        return value;
    }

    Value parsePrimary()
    {
        switch (current)
        {
            case TOK_LPAREN:
            {
                nextToken();
                auto inner = parseExpr();
                if (current != TOK_RPAREN)
                {
                    if (current == TOK_EOF)
                        unexpectedEndOfExpression();
                    else
                        unexpectedToken(currentTokenText());
                }
                nextToken();
                return inner;
            }
            case TOK_NUM:
            {
                auto number = numberValue;
                nextToken();
                return makeNumber(number);
            }
            case TOK_STR:
            {
                auto word = lexeme;
                if (word == "length") return parseLength();
                if (word == "match") return parseMatchFunction();
                if (word == "substr") return parseSubstr();
                if (word == "index") return parseIndex();
                nextToken();
                return makeString(word);
            }
            case TOK_RPAREN:
                unexpectedToken(currentTokenText());
            case TOK_EOF:
                unexpectedEndOfExpression();
            default:
                unexpectedToken(currentTokenText());
        }
    }

    Value parseLength()
    {
        nextToken();
        auto arg = requirePrimary("length");
        auto text = valueToString(arg);
        return makeNumber(cast(long) text.length);
    }

    Value parseIndex()
    {
        nextToken();
        auto haystack = requirePrimary("index");
        auto needles = requirePrimary("index");
        auto text = valueToString(haystack);
        auto chars = valueToString(needles);
        foreach (size_t i; 0 .. text.length)
        {
            immutable(char) ch = text[i];
            foreach (immutable(char) needle; chars)
            {
                if (needle == ch)
                    return makeNumber(cast(long) (i + 1));
            }
        }
        return makeNumber(0);
    }

    Value parseSubstr()
    {
        nextToken();
        auto textValue = requirePrimary("substr");
        auto posValue = requirePrimary("substr");
        auto lenValue = requirePrimary("substr");
        auto text = valueToString(textValue);
        const long pos = requireInteger(posValue);
        const long len = requireInteger(lenValue);
        if (pos <= 0 || len <= 0)
            return makeString("");
        size_t start = cast(size_t) (pos - 1);
        if (start >= text.length)
            return makeString("");
        size_t end = start + cast(size_t) len;
        if (end > text.length)
            end = text.length;
        return makeString(text[start .. end]);
    }

    Value parseMatchFunction()
    {
        nextToken();
        auto base = requirePrimary("match");
        auto pattern = requirePrimary("match");
        return applyRegex(base, pattern);
    }

    Value requirePrimary(string keyword)
    {
        if (current == TOK_EOF)
            missingArgument(keyword);
        return parsePrimary();
    }

    bool performComparison(Value lhs, Value rhs, int op)
    {
        long lhsNum;
        long rhsNum;
        if (tryToLong(lhs, lhsNum) && tryToLong(rhs, rhsNum))
        {
            switch (op)
            {
                case TOK_LT: return lhsNum < rhsNum;
                case TOK_LE: return lhsNum <= rhsNum;
                case TOK_GT: return lhsNum > rhsNum;
                case TOK_GE: return lhsNum >= rhsNum;
                case TOK_EQ: return lhsNum == rhsNum;
                case TOK_NE: return lhsNum != rhsNum;
                default: return false;
            }
        }

        auto left = valueToString(lhs);
        auto right = valueToString(rhs);
        switch (op)
        {
            case TOK_LT: return left < right;
            case TOK_LE: return left <= right;
            case TOK_GT: return left > right;
            case TOK_GE: return left >= right;
            case TOK_EQ: return left == right;
            case TOK_NE: return left != right;
            default: return false;
        }
    }
}

extern (C) int yyparse()
{
    Parser parser;
    parser.nextToken();
    if (parser.current == TOK_EOF)
    {
        yyerror("expr: missing operand");
        return 2;
    }

    try
    {
        auto value = parser.parseExpr();
        if (parser.current != TOK_EOF)
            unexpectedArgument(parser.currentTokenText());

        auto output = valueToString(value);
        const(char)* data = output.length ? output.ptr : "".ptr;
        printf("%.*s\n", cast(int) output.length, data);
        return truthy(value) ? 0 : 1;
    }
    catch (ExprException)
    {
        return 2;
    }
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
    {
        gTokenText = null;
        return TOK_EOF;
    }

    const char* s = gArgv[gIdx++];
    gTokenText = s;
    const int   tt = parseToken(s);

    if (tt == TOK_NUM)
        yylval = cast(long) strtoll(s, null, 10);

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
