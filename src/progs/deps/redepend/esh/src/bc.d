module bc;

import dlexer;
import std.regex : regex;
import std.array : array, join;
import std.algorithm : filter;
import std.bigint : BigInt;
import std.conv : to;
import std.stdio;
import std.string : splitLines;
import shell.syscalls;

class BCParser {
    Token[] tokens;
    size_t pos;

    this(Token[] t) {
        tokens = t;
        pos = 0;
    }

    bool peek(string type) {
        return pos < tokens.length && tokens[pos].type == type;
    }

    Token consume(string type) {
        if(!peek(type))
            throw new Exception("Expected " ~ type);
        return tokens[pos++];
    }

    BigInt parseExpression() {
        auto value = parseTerm();
        while(peek("PLUS") || peek("MINUS")) {
            auto op = consume(tokens[pos].type);
            auto rhs = parseTerm();
            final switch(op.type) {
                case "PLUS":  value += rhs; break;
                case "MINUS": value -= rhs; break;
            }
        }
        return value;
    }

    BigInt parseTerm() {
        auto value = parseFactor();
        while(peek("TIMES") || peek("DIVIDE")) {
            auto op = consume(tokens[pos].type);
            auto rhs = parseFactor();
            final switch(op.type) {
                case "TIMES":  value *= rhs; break;
                case "DIVIDE": value /= rhs; break;
            }
        }
        return value;
    }

    BigInt parseFactor() {
        if(peek("NUMBER")) {
            auto t = consume("NUMBER");
            return BigInt(t.value);
        } else if(peek("LPAREN")) {
            consume("LPAREN");
            auto val = parseExpression();
            consume("RPAREN");
            return val;
        }
        throw new Exception("Unexpected token");
    }
}

BigInt bcEval(string expr) {
    auto rules = [
        Rule("NUMBER", regex("[0-9]+")),
        Rule("PLUS", regex("\\+")),
        Rule("MINUS", regex("-")),
        Rule("TIMES", regex("\\*")),
        Rule("DIVIDE", regex("/")),
        Rule("LPAREN", regex("\\(")),
        Rule("RPAREN", regex("\\)")),
        Rule("WS", regex("\\s+"))
    ];
    auto lex = new Lexer(rules);
    auto tokens = lex.tokenize(expr);
    tokens = tokens.filter!(t => t.type != "WS").array;
    auto parser = new BCParser(tokens);
    return parser.parseExpression();
}

void bcCommand(string[] tokens) {
    if (tokens.length > 1) {
        // Evaluate args as expression
        string expr = tokens[1..$].join(" ");
        try {
            writeln(bcEval(expr));
        } catch (Exception e) {
            writeln("Runtime error: ", e.msg);
        }
    } else {
        // REPL mode reading stdin
        writeln("bc 1.0 (minimal)");
        ubyte[1024] buf;
        long n;
        while ((n = sys_read(0, buf.ptr, 1024)) > 0) {
            string chunk = cast(string)buf[0..n];
            foreach(line; chunk.splitLines) {
                 if (line.length == 0 || line == "quit") return;
                 try { writeln(bcEval(line)); } catch(Exception e) { writeln(e.msg); }
            }
        }
    }
}
