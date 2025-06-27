module dparser;

import std.stdio;
import std.array : array;
import std.algorithm;
import std.conv : to;
import dlexer;

alias Action = long delegate(long, long);

/// Simple recursive-descent parser framework with an example
/// arithmetic parser to demonstrate defining a pseudo language.
class Parser {
    Token[] tokens;
    size_t pos;

    this(Token[] toks) {
        tokens = toks;
        pos = 0;
    }

    bool peek(string type) {
        return pos < tokens.length && tokens[pos].type == type;
    }

    Token consume(string type) {
        if (!peek(type)) {
            throw new Exception("Expected " ~ type ~ ", got " ~ (pos < tokens.length ? tokens[pos].type : "EOF"));
        }
        return tokens[pos++];
    }

    // Example expression grammar:
    // expr  -> term ((PLUS|MINUS) term)*
    // term  -> factor ((TIMES|DIVIDE) factor)*
    // factor-> NUMBER | LPAREN expr RPAREN

    long parseExpression() {
        long value = parseTerm();
        while (peek("PLUS") || peek("MINUS")) {
            auto op = consume(tokens[pos].type);
            long rhs = parseTerm();
            final switch (op.type) {
                case "PLUS":  value += rhs; break;
                case "MINUS": value -= rhs; break;
            }
        }
        return value;
    }

    long parseTerm() {
        long value = parseFactor();
        while (peek("TIMES") || peek("DIVIDE")) {
            auto op = consume(tokens[pos].type);
            long rhs = parseFactor();
            final switch (op.type) {
                case "TIMES":  value *= rhs; break;
                case "DIVIDE": value /= rhs; break;
            }
        }
        return value;
    }

    long parseFactor() {
        if (peek("NUMBER")) {
            auto t = consume("NUMBER");
            return to!long(t.value);
        } else if (peek("LPAREN")) {
            consume("LPAREN");
            long value = parseExpression();
            consume("RPAREN");
            return value;
        }
        throw new Exception("Unexpected token " ~ (pos < tokens.length ? tokens[pos].type : "EOF"));
    }
}

