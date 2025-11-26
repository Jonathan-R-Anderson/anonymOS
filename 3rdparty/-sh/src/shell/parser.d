module shell.parser;

import shell.ast;
import shell.lexer;
import dlexer;
import dparser;
import std.algorithm : filter;
import std.array : array;

class ShellParser : Parser {
    this(Token[] tokens) {
        super(tokens);
    }

    public Node parse() {
        Node node = parseSequence();
        bool bg = false;
        if (peek("AMP")) {
            consume("AMP");
            bg = true;
        }

        if (bg) {
            if (auto seq = cast(Sequence)node) {
                seq.background = true;
            } else if (node !is null) {
                node = new Sequence([node], true);
            }
        }
        return node;
    }

    // sequence -> pipeline (SEMI pipeline)*
    public Node parseSequence() {
        Node left = parsePipeline();

        if (peek("SEMI")) {
            Node[] commands;
            if (left !is null) {
                commands ~= left;
            }
            while (peek("SEMI")) {
                consume("SEMI");
                if (pos >= tokens.length || peek("AMP")) break;
                auto right = parsePipeline();
                if (right !is null) {
                    commands ~= right;
                }
            }
            if (commands.length == 0) return null;
            if (commands.length == 1) return commands[0];
            return new Sequence(commands);
        }

        return left;
    }

    // pipeline -> command (PIPE command)*
    public Node parsePipeline() {
        Node left = parseCommand();

        if (left is null) {
            if (!peek("PIPE")) return null;
        }

        if (peek("PIPE")) {
            Node[] commands;
            if (left !is null) {
                commands ~= left;
            }
            while (peek("PIPE")) {
                consume("PIPE");
                auto right = parseCommand();
                if (right is null) {
                    break;
                }
                commands ~= right;
            }
            if (commands.length == 0) return null;
            if (commands.length == 1) return commands[0];
            return new Pipeline(commands);
        }

        return left;
    }

    // command -> simple_command (redirection)*
    public Node parseCommand() {
        Node cmd = parseSimpleCommand();

        if (cmd is null && !(peek("GT") || peek("DGT") || peek("LT"))) {
            return null;
        }

        while (peek("GT") || peek("DGT") || peek("LT")) {
            RedirectionType type;
            if (peek("DGT")) {
                consume("DGT");
                type = RedirectionType.OutputAppend;
            } else if (peek("GT")) {
                consume("GT");
                type = RedirectionType.Output;
            } else {
                consume("LT");
                type = RedirectionType.Input;
            }

            if (!peek("WORD")) {
                return cmd;
            }
            string filename = consume("WORD").value;
            if (cmd is null) {
                cmd = new SimpleCommand(new string[0]);
            }
            cmd = new Redirection(cmd, type, filename);
        }

        return cmd;
    }

    // simple_command -> WORD+
    public SimpleCommand parseSimpleCommand() {
        if (!peek("WORD")) {
            return null;
        }
        string[] arguments;
        while (peek("WORD")) {
            arguments ~= consume("WORD").value;
        }
        return new SimpleCommand(arguments);
    }
}

public Node parseShellCommand(string command) {
    auto lexer = createShellLexer();
    auto allTokens = lexer.tokenize(command);
    auto tokens = allTokens.filter!(t => t.type != "WS").array;

    if (tokens.length == 0) {
        return null;
    }

    auto parser = new ShellParser(tokens);
    return parser.parse();
}
