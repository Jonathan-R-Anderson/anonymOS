import std.stdio;
import std.string;
import std.array;
import std.algorithm;
import std.range;
import std.conv : to;
import std.file : chdir, getcwd, dirEntries, SpanMode;
import std.process : executeShell, environment;

string[] history;
string[string] aliases;

string[string] variables;
string[string] colorCodes = [
    "black": "\033[30m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m"
];

/**
 * Simple interpreter skeleton for a Lisp-like language.
 * This implementation is intentionally minimal and is
 * provided as an example of building language tooling
 * with the D cross-compiler.
 */

void runCommand(string cmd);
void runParallel(string input);

void run(string input) {
    auto seqs = input.split(";");
    foreach(s; seqs) {
        auto trimmed = s.strip;
        if(trimmed.length == 0) continue;
        runParallel(trimmed);
    }
}

void runParallel(string input) {
    auto cmds = input.split("&");
    foreach(c; cmds) {
        runCommand(c.strip);
    }
}

void runCommand(string cmd) {
    history ~= cmd;
    auto tokens = cmd.split();
    if(tokens.length == 0) return;

    if(auto ali = tokens[0] in aliases) {
        auto aliTokens = (*ali).split();
        tokens = aliTokens ~ tokens[1 .. $];
    }

    // variable expansion
    foreach(ref t; tokens) {
        if(t.length > 1 && t[0] == '$') {
            auto key = t[1 .. $];
            if(auto val = key in variables) t = *val;
        }
    }

    // variable assignment of form name=value
    auto eqPos = tokens[0].indexOf('=');
    if(eqPos > 0 && tokens.length == 1) {
        auto name = tokens[0][0 .. eqPos];
        auto value = tokens[0][eqPos + 1 .. $];
        variables[name] = value;
        return;
    }

    auto op = tokens[0];
    if(op == "echo") {
        writeln(tokens[1 .. $].join(" "));
    } else if(op == "+" || op == "-" || op == "*" || op == "/") {
        if(tokens.length < 3) {
            writeln("Invalid arithmetic expression");
            return;
        }
        int a = to!int(tokens[1]);
        int b = to!int(tokens[2]);
        int result;
        final switch(op) {
            case "+": result = a + b; break;
            case "-": result = a - b; break;
            case "*": result = a * b; break;
            case "/": result = b == 0 ? 0 : a / b; break;
        }
        writeln(result);
    } else if(op == "for") {
        if(tokens.length < 3) {
            writeln("Usage: for start..end command");
            return;
        }
        auto rangeParts = tokens[1].split("..");
        if(rangeParts.length != 2) {
            writeln("Invalid range");
            return;
        }
        int start = to!int(rangeParts[0]);
        int finish = to!int(rangeParts[1]);
        string sub = tokens[2 .. $].join(" ");
        foreach(i; iota(start, finish + 1)) {
            runCommand(sub);
        }
    } else if(op == "cd") {
        if(tokens.length < 2) {
            writeln("cd: missing operand");
            return;
        }
        chdir(tokens[1]);
    } else if(op == "pwd") {
        writeln(getcwd());
    } else if(op == "ls") {
        string path = tokens.length > 1 ? tokens[1] : ".";
        foreach(entry; dirEntries(path, SpanMode.shallow)) {
            writeln(entry.name);
        }
    } else if(op == "alias") {
        if(tokens.length == 1) {
            foreach(name, val; aliases) {
                writeln(name, "=", val);
            }
        } else if(tokens.length == 2 && tokens[1].indexOf('=') > 0) {
            auto eq = tokens[1].indexOf('=');
            auto name = tokens[1][0 .. eq];
            auto value = tokens[1][eq+1 .. $];
            aliases[name] = value;
        } else if(tokens.length >= 3) {
            auto name = tokens[1];
            auto value = tokens[2 .. $].join(" ");
            aliases[name] = value;
        } else if(tokens.length == 2) {
            auto name = tokens[1];
            if(auto val = name in aliases) writeln(name, "=", *val);
        }
    } else if(op == "history") {
        foreach(i, cmdLine; history) {
            writeln(i + 1, " ", cmdLine);
        }
    } else {
        // attempt to run external command
        auto result = executeShell(cmd);
        if(result.status != 0) {
            writeln("Unknown command: ", op);
        }
    }
}

void repl() {
    auto ps1 = environment.get("PS1", "sh> ");
    auto colorName = environment.get("PS_COLOR", "");
    string colorCode;
    if(auto c = colorName in colorCodes) colorCode = *c;
    auto reset = colorCode.length ? "\033[0m" : "";
    for(;;) {
        write(colorCode, ps1, reset);
        auto line = readln();
        if(line is null) break;
        line = line.strip;
        if(line == "exit") break;
        if(line.length == 0) continue;
        if(line == "!!" && history.length) {
            line = history[$-1];
            writeln(line);
        }
        run(line);
    }
}

void main(string[] args) {
    if(args.length < 2) {
        repl();
        return;
    }
    run(args[1]);
}
