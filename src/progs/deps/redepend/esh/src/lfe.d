module lfe;

import dlexer;
import dparser;
import std.regex : regex;
import std.stdio;
import std.string;
import std.algorithm : map, filter;
import std.array : join, array;

struct Expr {
    bool isList;
    string atom;
    Expr[] list;
}

class LfeParser : Parser {
    this(Token[] toks) {
        super(toks);
    }

    Expr parseExpr() {
        if (peek("LPAREN")) {
            consume("LPAREN");
            Expr[] elems;
            while (!peek("RPAREN")) {
                elems ~= parseExpr();
                if (pos >= tokens.length) break;
            }
            consume("RPAREN");
            return Expr(true, "", elems);
        } else if (peek("NUMBER")) {
            auto t = consume("NUMBER");
            return Expr(false, t.value, null);
        } else if (peek("STRING")) {
            auto t = consume("STRING");
            return Expr(false, t.value, null);
        } else if (peek("SYMBOL")) {
            auto t = consume("SYMBOL");
            return Expr(false, t.value, null);
        }
        throw new Exception("Unexpected token");
    }
}

string exprToErlang(Expr e) {
    if (!e.isList) {
        return e.atom;
    }
    if (e.list.length == 0) return "";
    auto head = e.list[0];
    if (!head.isList) {
        auto op = head.atom;
        if (op == "defmodule") {
            auto name = e.list[1].atom;
            string body;
            foreach (expr; e.list[2 .. $]) {
                body ~= exprToErlang(expr);
            }
            return "-module(" ~ name ~ ").\n" ~ body;
        } else if (op == "export") {
            string exports;
            foreach (item; e.list[1].list) {
                auto fname = item.list[0].atom;
                auto arity = item.list[1].atom;
                exports ~= fname ~ "/" ~ arity ~ ", ";
            }
            if (exports.length > 2) exports = exports[0 .. $-2];
            return "-export([" ~ exports ~ "]).\n";
        } else if (op == "defun") {
            auto fname = e.list[1].atom;
            auto params = e.list[2].list.map!(p => p.atom).join(", ");
            auto body = e.list[3].list.map!(exprToErlang).join("\n");
            return fname ~ "(" ~ params ~ ") ->\n    " ~ body ~ ";\n";
        } else if (op == "+" || op == "-" || op == "*" || op == "/") {
            auto a = exprToErlang(e.list[1]);
            auto b = exprToErlang(e.list[2]);
            return a ~ " " ~ op ~ " " ~ b;
        } else if (op == "print") {
            auto val = exprToErlang(e.list[1]);
            return "io:format(\"~p~n\", [" ~ val ~ "])";
        }
    }
    // generic list -> function call
    auto func = exprToErlang(head);
    auto args = e.list[1 .. $].map!(exprToErlang).join(", ");
    return func ~ "(" ~ args ~ ")";
}

/// Convert a minimal LFE program to Erlang source.
void lfeMain(string[] args) {
    if (args.length < 2) {
        writeln("Usage: lfe \"(defmodule ... )\"");
        return;
    }
    auto rules = [
        Rule("LPAREN", regex("\\(")),
        Rule("RPAREN", regex("\\)")),
        Rule("STRING", regex("\"[^\"]*\"")),
        Rule("NUMBER", regex("[0-9]+")),
        Rule("SYMBOL", regex("[a-zA-Z_+*/:<>=!?-][a-zA-Z0-9_+*/:<>=!?-]*")),
        Rule("WS", regex("\\s+"))
    ];
    auto lex = new Lexer(rules);
    auto toks = lex.tokenize(args[1]);
    toks = toks.filter!(t => t.type != "WS").array;
    auto parser = new LfeParser(toks);
    auto ast = parser.parseExpr();
    auto erl = exprToErlang(ast);
    writeln(erl);
}

