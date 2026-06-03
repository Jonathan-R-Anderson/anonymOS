module shell.lexer;

import dlexer;
import std.regex : regex;

public Rule[] shellRules = [
    // Complex terminators
    Rule("DSEMI_AND", regex(`;;&`)),
    Rule("SEMI_AND", regex(`;&`)),
    Rule("DSEMI", regex(`;;`)),
    Rule("COMMENT", regex(`#.*`)),
    Rule("EXCLAMATION", regex(`!`)),

    // Logical
    Rule("AND_IF", regex(`&&`)),
    Rule("OR_IF", regex(`\|\|`)),
    Rule("PIPE_STDERR", regex(`\|&`)),

    // Double brackets for Test (Must be before WORD)
    Rule("D_LBRACKET", regex(`\[\[`)),
    Rule("D_RBRACKET", regex(`\]\]`)),

    // Redirections - Complex / FD attached (Must be before WORD)
    Rule("FD_DGT", regex(`[0-9]+>>`)),
    Rule("FD_GT", regex(`[0-9]+>`)),
    Rule("FD_LT", regex(`[0-9]+<`)),

    // Here ops (Must be before LT/GT)
    Rule("TLESS", regex(`<<<`)),
    Rule("DLESSDASH", regex(`<<-`)),
    Rule("DLESS", regex(`<<`)),
    
    // Combined ops
    Rule("ANDDGT", regex(`&>>`)),
    Rule("ANDGT", regex(`&>`)),
    
    Rule("CLOBBER", regex(`>\|`)),
    Rule("LESSGREAT", regex(`<>`)),
    Rule("GREATAND", regex(`>&`)),
    Rule("LESSAND", regex(`<&`)),

    // Process Substitution
    Rule("PROC_IN", regex(`<\(`)),
    Rule("PROC_OUT", regex(`>\(`)),

    // Simple Redirections
    Rule("DGT", regex(`>>`)),
    Rule("GT", regex(`>`)),
    Rule("LT", regex(`<`)),

    // Basic Operators
    Rule("PIPE", regex(`\|`)),
    Rule("SEMI", regex(`;`)),
    Rule("AMP", regex(`&`)),
    
    // Grouping and Expansion Markers
    Rule("D_LPAREN", regex(`\(\(`)), // (( for arithmetic command
    Rule("LPAREN", regex(`\(`)),
    Rule("RPAREN", regex(`\)`)),
    Rule("LBRACE", regex(`\{`)),
    Rule("RBRACE", regex(`\}`)),
    Rule("DOLLAR", regex(`\$`)),
    Rule("BACKTICK", regex("`")),
    
    // Keywords
    Rule("CASE", regex(`case`)),
    Rule("ESAC", regex(`esac`)),
    Rule("IF", regex(`if`)),
    Rule("THEN", regex(`then`)),
    Rule("ELSE", regex(`else`)),
    Rule("ELIF", regex(`elif`)),
    Rule("FI", regex(`fi`)),
    Rule("FOR", regex(`for`)),
    Rule("WHILE", regex(`while`)),
    Rule("UNTIL", regex(`until`)),
    Rule("DO", regex(`do`)),
    Rule("DONE", regex(`done`)),
    Rule("SELECT", regex(`select`)),
    Rule("TIME", regex(`time`)),
    Rule("IN", regex(`in`)),
    
    // Quoting & Escaping
    Rule("ANSI_QUOTE", regex(`\$'`)),
    Rule("LOCALE_QUOTE", regex(`\$"`)),
    Rule("SQUOTE", regex(`'`)),
    Rule("DQUOTE", regex(`"`)),
    Rule("BSLASH", regex(`\\`)),

    // Word (allowing more characters for expansion)
    Rule("WORD", regex(`[a-zA-Z0-9_./%-*?\[\]+=:,@~^#!]+`)), 
    Rule("WS", regex(`\s+`)),
];

public Lexer createShellLexer() {
    return new Lexer(shellRules);
}
