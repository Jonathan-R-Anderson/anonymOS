module shell.ast;

import std.string : join;
import std.conv : to;

interface Node {
    string toString();
}

public enum RedirectionType {
    Input,          // <
    Output,         // >
    OutputAppend,   // >>
    Clobber,        // >|
    ReadWrite,      // <>
    DupInput,       // <&
    DupOutput,      // >&
    HereDoc,        // <<
    HereDocDash,    // <<-
    HereString,     // <<<
    OutputBoth,     // &>
    OutputBothAppend // &>>
}

class Redirection : Node {
    public Node command;
    public RedirectionType type;
    public string filename; // Target filename, FD number, or HereDoc content
    public int ioNumber;    // Source FD (e.g. 2 in 2>file). -1 if default.

    this(Node cmd, RedirectionType t, string file, int io = -1) {
        this.command = cmd;
        this.type = t;
        this.filename = file;
        this.ioNumber = io;
    }

    override string toString() {
        return "Redirection(" ~ to!string(type) ~ ", fd:" ~ to!string(ioNumber) ~ ", '" ~ filename ~ "', " ~ command.toString() ~ ")";
    }
}

class SimpleCommand : Node {
    public string[] arguments;
    this(string[] args) { this.arguments = args; }
    override string toString() { return "SimpleCommand(" ~ join(arguments, " ") ~ ")"; }
}

class Sequence : Node {
    public Node[] commands;
    public bool background = false;
    this(Node[] cmds, bool bg = false) { this.commands = cmds; this.background = bg; }
    override string toString() {
        string s = "Sequence(";
        foreach(i, c; commands) {
            s ~= c.toString();
            if (i < commands.length - 1) s ~= "; ";
        }
        return s ~ (background ? " &" : "") ~ ")";
    }
}

class Pipeline : Node {
    public Node[] commands;
    public bool[] pipeStderrs;
    this(Node[] cmds, bool[] stderrs = null) {
        this.commands = cmds;
        this.pipeStderrs = stderrs;
        if (pipeStderrs.length < commands.length) pipeStderrs.length = commands.length;
    }
    override string toString() { return "Pipeline(...)"; }
}

class LogicNode : Node {
    public Node left;
    public Node right;
    public bool isAnd;
    this(Node l, Node r, bool and) { left=l; right=r; isAnd=and; }
    override string toString() { return "(" ~ left.toString() ~ (isAnd?" && ":" || ") ~ right.toString() ~ ")"; }
}

class CaseItem {
    public string[] patterns;
    public Node list;
    public string terminator;
    this(string[] p, Node l, string t) { patterns=p; list=l; terminator=t; }
}

class CaseNode : Node {
    public string word;
    public CaseItem[] items;
    this(string w, CaseItem[] i) { word=w; items=i; }
    override string toString() { return "Case(" ~ word ~ ")"; }
}

class ArithmeticNode : Node {
    public string expression;
    this(string expr) { expression = expr; }
    override string toString() { return "Arithmetic((" ~ expression ~ "))"; }
}

class TestNode : Node {
    public string[] arguments;
    this(string[] args) { arguments = args; }
    override string toString() { return "TestNode([[" ~ join(arguments, " ") ~ "]])"; }
}

class SubshellNode : Node {
    public Node node;
    this(Node n) { node = n; }
    override string toString() { return "Subshell(" ~ node.toString() ~ ")"; }
}

class SelectNode : Node {
    public string name;
    public string[] words;
    public Node body;
    this(string n, string[] w, Node b) { name=n; words=w; body=b; }
    override string toString() { return "Select(" ~ name ~ ")"; }
}
