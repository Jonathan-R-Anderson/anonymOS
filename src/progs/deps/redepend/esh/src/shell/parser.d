module shell.parser;

import shell.ast;
import shell.lexer;
import dlexer;
import dparser;
import std.algorithm : filter;
import std.array : array;
import std.conv : to;
import std.string : endsWith;

class ShellParser : Parser {
    this(Token[] tokens) {
        super(tokens);
    }

    public Node parse() {
        return parseList();
    }

    void skipWS() {
        while (pos < tokens.length && (tokens[pos].type == "WS" || tokens[pos].type == "COMMENT")) pos++;
    }

    string peekType() {
        if (pos >= tokens.length) return "EOF";
        return tokens[pos].type;
    }

    public Node parseList() {
        Node[] cmds;
        while (pos < tokens.length) {
            skipWS();
            if (pos >= tokens.length) break;
            if (peek("DSEMI") || peek("SEMI_AND") || peek("DSEMI_AND") || peek("ESAC") || peek("RPAREN") || peek("RBRACE") || peek("DONE") || peek("FI")) break;
            auto node = parseAndOr();
            if (node is null) break;
            skipWS();
            bool bg = false;
            if (peek("AMP")) { consume("AMP"); bg = true; }
            else if (peek("SEMI")) { consume("SEMI"); }
            if (bg) node = new Sequence([node], true);
            cmds ~= node;
        }
        if (cmds.length == 0) return null;
        if (cmds.length == 1) return cmds[0];
        return new Sequence(cmds, false);
    }

    Node parseAndOr() {
        Node left = parsePipeline();
        while (true) {
            skipWS();
            if (peek("AND_IF") || peek("OR_IF")) {
                bool isAnd = peek("AND_IF");
                consume(isAnd ? "AND_IF" : "OR_IF");
                skipWS();
                Node right = parsePipeline();
                if (right !is null) left = new LogicNode(left, right, isAnd);
            } else break;
        }
        return left;
    }

    public Node parsePipeline() {
        Node left = parseCommand();
        if (left is null) return null;
        while (true) {
            skipWS();
            if (peek("PIPE") || peek("PIPE_STDERR")) {
                Node[] commands; bool[] stderrs;
                commands ~= left;
                while (peek("PIPE") || peek("PIPE_STDERR")) {
                    bool stderr = peek("PIPE_STDERR");
                    stderrs ~= stderr;
                    consume(stderr ? "PIPE_STDERR" : "PIPE");
                    skipWS();
                    Node right = parseCommand();
                    if (right is null) break;
                    commands ~= right;
                    skipWS();
                }
                if (commands.length == 1) return commands[0];
                return new Pipeline(commands, stderrs);
            } else break;
        }
        return left;
    }

    public Node parseCommand() {
        skipWS();
        if (peek("CASE")) return parseCase();
        if (peek("SELECT")) return parseSelect();
        if (peek("LPAREN")) return parseSubshell();
        if (peek("LBRACE")) return parseGroup();
        if (peek("D_LPAREN")) return parseArithmeticCommand();
        if (peek("D_LBRACKET")) return parseTestCommand();
        
        Node cmd = parseSimpleCommand();
        if (cmd is null) {
            if (isRedirection()) cmd = new SimpleCommand(new string[0]);
            else return null;
        }
        
        while (true) {
            skipWS();
            if (!isRedirection()) break;
            
            RedirectionType type;
            int io = -1;
            bool matched = false;
            string tokenText = "";

            if (peek("FD_GT")) {
                matched=true; tokenText=consume("FD_GT").value;
                io = to!int(tokenText[0..$-1]);
                type = RedirectionType.Output;
            } else if (peek("FD_DGT")) {
                matched=true; tokenText=consume("FD_DGT").value;
                io = to!int(tokenText[0..$-2]);
                type = RedirectionType.OutputAppend;
            } else if (peek("FD_LT")) {
                matched=true; tokenText=consume("FD_LT").value;
                io = to!int(tokenText[0..$-1]);
                type = RedirectionType.Input;
            } 
            else if (peek("GT")) { consume("GT"); type = RedirectionType.Output; matched=true; }
            else if (peek("DGT")) { consume("DGT"); type = RedirectionType.OutputAppend; matched=true; }
            else if (peek("LT")) { consume("LT"); type = RedirectionType.Input; matched=true; }
            else if (peek("CLOBBER")) { consume("CLOBBER"); type = RedirectionType.Clobber; matched=true; }
            else if (peek("LESSGREAT")) { consume("LESSGREAT"); type = RedirectionType.ReadWrite; matched=true; }
            else if (peek("ANDGT")) { consume("ANDGT"); type = RedirectionType.OutputBoth; matched=true; }
            else if (peek("ANDDGT")) { consume("ANDDGT"); type = RedirectionType.OutputBothAppend; matched=true; }
            else if (peek("TLESS")) { consume("TLESS"); type = RedirectionType.HereString; matched=true; }
            else if (peek("DLESS")) { consume("DLESS"); type = RedirectionType.HereDoc; matched=true; }
            else if (peek("DLESSDASH")) { consume("DLESSDASH"); type = RedirectionType.HereDocDash; matched=true; }
            else if (peek("GREATAND")) { consume("GREATAND"); type = RedirectionType.DupOutput; matched=true; }
            else if (peek("LESSAND")) { consume("LESSAND"); type = RedirectionType.DupInput; matched=true; }

            if (!matched) break;

            skipWS();
            if (!isWordPart()) break; 
            string val = parseWord();
            cmd = new Redirection(cmd, type, val, io);
        }
        
        return cmd;
    }

    bool isRedirection() {
        string t = peekType();
        return t == "GT" || t == "DGT" || t == "LT" || t == "FD_GT" || t == "FD_DGT" || t == "FD_LT" ||
               t == "CLOBBER" || t == "LESSGREAT" || t == "ANDGT" || t == "ANDDGT" || t == "TLESS" ||
               t == "DLESS" || t == "DLESSDASH" || t == "GREATAND" || t == "LESSAND";
    }
    
    Node parseSubshell() {
        consume("LPAREN");
        Node n = parseList();
        consume("RPAREN");
        return new SubshellNode(n);
    }

    Node parseGroup() {
        consume("LBRACE");
        Node n = parseList();
        consume("RBRACE");
        return n; // A group is just a list executed in the current shell
    }

    Node parseArithmeticCommand() {
        consume("D_LPAREN");
        string expr = "";
        int depth = 1;
        while (pos < tokens.length && depth > 0) {
            if (peek("LPAREN")) depth++;
            if (peek("RPAREN")) {
                depth--;
                if (depth == 0) {
                    consume("RPAREN");
                    if (peek("RPAREN")) consume("RPAREN");
                    break;
                }
            }
            expr ~= consume(peekType()).value;
        }
        return new ArithmeticNode(expr);
    }

    Node parseTestCommand() {
        consume("D_LBRACKET");
        string[] args;
        while (pos < tokens.length && !peek("D_RBRACKET")) {
            skipWS();
            if (peek("D_RBRACKET")) break;
            
            // Collect tokens as words. If it's a redirection token, take its value as a word.
            if (isRedirection() || peek("PIPE") || peek("AND_IF") || peek("OR_IF")) {
                 args ~= consume(peekType()).value;
            } else if (isWordPart()) {
                 args ~= parseWord();
            } else {
                 // Unknown token, skip or consume as word
                 args ~= consume(peekType()).value;
            }
        }
        if (peek("D_RBRACKET")) consume("D_RBRACKET");
        return new TestNode(args);
    }

    Node parseCase() {
        consume("CASE");
        skipWS();
        string word = parseWord();
        skipWS();
        consume("IN");
        CaseItem[] items;
        while (true) {
            skipWS();
            if (peek("ESAC") || pos >= tokens.length) break;
            
            if (peek("LPAREN")) consume("LPAREN");
            string[] patterns;
            while (isWordPart()) {
                patterns ~= parseWord();
                skipWS();
                if (peek("PIPE")) { consume("PIPE"); skipWS(); continue; }
                break;
            }
            if (peek("RPAREN")) consume("RPAREN");
            Node list = parseList();
            string term = ";;";
            skipWS();
            if (peek("DSEMI")) { consume("DSEMI"); }
            else if (peek("SEMI_AND")) { term = ";&"; consume("SEMI_AND"); }
            else if (peek("DSEMI_AND")) { term = ";;&"; consume("DSEMI_AND"); }
            items ~= new CaseItem(patterns, list, term);
        }
        consume("ESAC");
        return new CaseNode(word, items);
    }

    Node parseSelect() {
        consume("SELECT");
        skipWS();
        string name = parseWord();
        skipWS();
        string[] words;
        if (peek("IN")) {
            consume("IN");
            skipWS();
            while (isWordPart()) {
                words ~= parseWord();
                skipWS();
            }
            if (peek("SEMI")) consume("SEMI");
        }
        skipWS();
        consume("DO");
        Node body = parseList();
        consume("DONE");
        return new SelectNode(name, words, body);
    }

    public SimpleCommand parseSimpleCommand() {
        if (!isWordPart()) return null;
        string[] arguments;
        while (isWordPart()) {
            arguments ~= parseWord();
            skipWS();
        }
        return new SimpleCommand(arguments);
    }

    bool isWordPart() {
        if (pos >= tokens.length) return false;
        string t = tokens[pos].type;
        return t == "WORD" || t == "DOLLAR" || t == "LPAREN" || t == "RPAREN" || 
               t == "LBRACE" || t == "RBRACE" || t == "BACKTICK" ||
               t == "SQUOTE" || t == "DQUOTE" || t == "BSLASH" || 
               t == "ANSI_QUOTE" || t == "LOCALE_QUOTE" ||
               t == "PROC_IN" || t == "PROC_OUT" ||
               t == "CASE" || t == "IF" || t == "FOR" || t == "WHILE" || t == "UNTIL" || t == "SELECT" || t == "TIME" || t == "IN" || t == "THEN" || t == "ELSE" || t == "ELIF" || t == "FI" || t == "DO" || t == "DONE" || t == "ESAC";
    }

    string parseWord() {
        string word = "";
        bool inSQuote = false;
        bool inDQuote = false;

        while (pos < tokens.length) {
            string t = peekType();
            
            if (!inSQuote && !inDQuote) {
                if (t == "WS") break;
                if (!isWordPart()) break;
            }

            if (t == "SQUOTE" || t == "ANSI_QUOTE") {
                if (!inDQuote) inSQuote = !inSQuote;
                word ~= consume(t).value;
            } else if (t == "DQUOTE" || t == "LOCALE_QUOTE") {
                if (!inSQuote) inDQuote = !inDQuote;
                word ~= consume(t).value;
            } else if (t == "DOLLAR") {
                word ~= consume("DOLLAR").value;
                if (peek("LPAREN")) word ~= parseGrouping("LPAREN", "RPAREN");
                else if (peek("LBRACE")) word ~= parseGrouping("LBRACE", "RBRACE");
            } else if (t == "PROC_IN") {
                word ~= parseGrouping("PROC_IN", "RPAREN");
            } else if (t == "PROC_OUT") {
                word ~= parseGrouping("PROC_OUT", "RPAREN");
            } else if (t == "BACKTICK") {
                word ~= parseGrouping("BACKTICK", "BACKTICK");
            } else {
                word ~= consume(t).value;
            }
        }
        return word;
    }
    
    string parseGrouping(string open, string close) {
        string result = consume(open).value;
        int depth = 1;
        while (pos < tokens.length && depth > 0) {
            string t = peekType();
            if (t == open) depth++;
            else if (t == close) {
                depth--;
                if (depth == 0) {
                    result ~= consume(close).value;
                    break;
                }
            }
            result ~= consume(t).value;
        }
        return result;
    }
}

public Node parseShellCommand(string command) {
    auto lexer = createShellLexer();
    auto allTokens = lexer.tokenize(command);
    if (allTokens.length == 0) return null;
    auto parser = new ShellParser(allTokens);
    return parser.parse();
}
