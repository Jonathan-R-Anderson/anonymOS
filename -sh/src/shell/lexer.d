module shell.lexer;

import dlexer;
import std.regex : regex;

public Rule[] shellRules = [
    Rule("PIPE", regex(`\|`)),
    Rule("DGT", regex(`>>`)),
    Rule("GT", regex(`>`)),
    Rule("LT", regex(`<`)),
    Rule("SEMI", regex(`;`)),
    Rule("AMP", regex(`&`)),
    Rule("WORD", regex(`[a-zA-Z0-9_./%-]+`)),
    Rule("WS", regex(`\s+`)),
];

public Lexer createShellLexer() {
    return new Lexer(shellRules);
}
