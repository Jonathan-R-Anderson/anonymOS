module example;

import dlexer;
import dparser;
import std.regex : regex;
import std.stdio;
import std.algorithm : filter;
import std.array : array;

/// Run the arithmetic parser example.
void exampleMain(string[] args) {
    if (args.length < 2) {
        writeln("Usage: example \"1 + 2 * 3\"");
        return;
    }
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
    auto tokens = lex.tokenize(args[1]);
    // filter out whitespace tokens
    tokens = tokens.filter!(t => t.type != "WS").array;
    auto parser = new Parser(tokens);
    auto result = parser.parseExpression();
    writeln(result);
}
