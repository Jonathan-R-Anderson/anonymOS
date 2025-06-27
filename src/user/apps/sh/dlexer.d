module dlexer;

import std.regex : regex, match, Captures;
import std.array : array;
import std.string : strip;

/// Represents a lexical token with type and value.
struct Token {
    string type;
    string value;
}

/// Defines a single tokenization rule.
struct Rule {
    string name;
    Regex!char pattern;
}

/// Simple regex-based lexer inspired by Python's SLY.
class Lexer {
    private Rule[] rules;

    this(Rule[] rules) {
        this.rules = rules;
    }

    /// Tokenize the given input string.
    Token[] tokenize(string input) {
        Token[] tokens;
        size_t pos = 0;
        while (pos < input.length) {
            bool matched = false;
            foreach (rule; rules) {
                auto m = match(input[pos .. $], rule.pattern);
                if (m.hit && m.hit.length > 0 && m.pre.length == 0) {
                    tokens ~= Token(rule.name, m.hit);
                    pos += m.hit.length;
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                // Skip unknown characters
                pos++;
            }
        }
        return tokens;
    }
}

