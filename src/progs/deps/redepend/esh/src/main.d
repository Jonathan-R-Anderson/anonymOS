import std.stdio;
import std.string;
import core.stdc.stdlib;
import core.stdc.stdio;
version(ANONYMOS_MINIMAL) {
    // No isatty on AnonymOS
} else {
    import core.sys.posix.unistd : isatty, STDIN_FILENO;
}
import frontend;
import lferepl;
import shell.executor : execute, initializeShell, update_job_status, shellHistory;
import shell.parser : parseShellCommand;
import shell.ast : Node;

// Performs history expansion (e.g. !!, !ls)
string expandHistory(string line) {
    if (!line.startsWith("!")) return line;
    if (line == "!!") {
        if (shellHistory.length > 0) return shellHistory[$-1];
        writeln("esh: no previous command");
        return "";
    }
    if (line.length > 1) {
        string prefix = line[1..$];
        for (int i = cast(int)shellHistory.length - 1; i >= 0; i--) {
            if (shellHistory[i].startsWith(prefix)) {
                return shellHistory[i];
            }
        }
    }
    return line;
}

// Processes a single line of input (either shell or LFE)
void processLine(string line) {
    if (line.length == 0) {
        return;
    }

    string interpolatedLine = interpolateLfe(line);

    if (isLfeInput(interpolatedLine)) {
        try {
            auto result = evalString(interpolatedLine);
            writeln(valueToString(result));
        } catch (Exception e) {
            writeln("LFE Error: ", e.msg);
        }
    } else {
        Node ast = parseShellCommand(interpolatedLine);
        execute(ast);
    }
}

// The main interactive shell loop
void runInteractiveShell() {
    import std.stdio : stdout;
    
    update_job_status();
    write("esh> ");
    stdout.flush();
    string line;
    while ((line = readln()) !is null) {
        line = line.strip;
        if (line.length > 0) {
           string expanded = expandHistory(line);
           if (expanded != line) {
               if (expanded == "") {
                   write("esh> ");
                   stdout.flush();
                   continue;
               }
               writeln(expanded);
               line = expanded;
           }
           shellHistory ~= line;
        }

        if (line == "exit") {
            break;
        }

        processLine(line);
        update_job_status();
        write("esh> ");
        stdout.flush();
    }
    writeln("\nexit");
}

// Main entry point for the shell
void main(string[] args) {
    initializeShell();

    // Set positional parameters
    if (args.length > 0) {
        import interpreter : variables;
        import std.conv : to;
        variables["0"] = args[0];
        
        bool isScript = false;
        int startArgs = 1;
        
        if (args.length > 1 && !args[1].startsWith("-")) {
            variables["0"] = args[1];
            isScript = true;
            startArgs = 2;
        }

        for (int i = startArgs; i < args.length; i++) {
            variables[to!string(i - startArgs + 1)] = args[i];
        }

        if (isScript) {
            try {
                import std.file : readText;
                string content = readText(variables["0"]);
                Node ast = parseShellCommand(content);
                if (ast) execute(ast);
                return;
            } catch (Exception e) {
                writeln("esh: cannot open script ", variables["0"]);
                return;
            }
        }
    }

    version(ANONYMOS_MINIMAL) {
        // AnonymOS: Always run in interactive mode, no TTY detection
        writeln("AnonymOS Enhanced Shell (esh) - Minimal Mode");
        writeln("Type 'help' for available commands, 'exit' to quit");
        runInteractiveShell();
    } else {
        if (isatty(STDIN_FILENO)) {
            runInteractiveShell();
        } else {
            // Non-interactive mode (e.g., from a pipe)
            string line;
            while((line = std.stdio.stdin.readln()) !is null) {
                processLine(line.strip);
            }
        }
    }
}
