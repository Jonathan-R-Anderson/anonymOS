module shell.ast;

import std.string : join;
import std.conv : to;

// Base interface for all AST nodes
interface Node {
    // A toString for debugging
    string toString();
}

// Enum for redirection types
public enum RedirectionType {
    Input,         // <
    Output,        // >
    OutputAppend,  // >>
}

// Represents a command with I/O redirection
class Redirection : Node {
    public Node command;
    public RedirectionType type;
    public string filename;

    this(Node cmd, RedirectionType t, string file) {
        this.command = cmd;
        this.type = t;
        this.filename = file;
    }

    override string toString() {
        return "Redirection(type=" ~ to!string(type) ~ ", file='" ~ filename ~ "', cmd=" ~ command.toString() ~ ")";
    }
}

// Represents a simple command with arguments
class SimpleCommand : Node {
    public string[] arguments;

    this(string[] args) {
        this.arguments = args;
    }

    override string toString() {
        return "SimpleCommand(" ~ join(arguments, ", ") ~ ")";
    }
}

// Represents a sequence of commands
class Sequence : Node {
    public Node[] commands;
    public bool background = false;

    this(Node[] cmds, bool bg = false) {
        this.commands = cmds;
        this.background = bg;
    }

    override string toString() {
        string[] cmdStrings;
        foreach(cmd; commands) {
            cmdStrings ~= cmd.toString();
        }
        return "Sequence(" ~ join(cmdStrings, " ; ") ~ ")";
    }
}

// Represents a pipeline of commands
class Pipeline : Node {
    public Node[] commands;

    this(Node[] cmds) {
        this.commands = cmds;
    }

    override string toString() {
        string[] cmdStrings;
        foreach(cmd; commands) {
            cmdStrings ~= cmd.toString();
        }
        return "Pipeline(" ~ join(cmdStrings, " | ") ~ ")";
    }
}
