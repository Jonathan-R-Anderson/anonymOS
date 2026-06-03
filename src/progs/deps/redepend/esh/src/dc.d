module dc;

import std.stdio;
import std.bigint;
import std.conv;
import std.string;
import shell.syscalls;

string dcEval(string expr) {
    BigInt[] stack;
    return dcEval(expr, stack);
}

string dcEval(string expr, ref BigInt[] stack) {
    string output;
    foreach(token; split(expr)) {
        if(token.length == 0) continue;
        
        switch(token) {
            case "+":
                if(stack.length < 2) { output ~= "stack empty\n"; break; }
                auto b = stack[$-1]; stack.length--;
                auto a = stack[$-1]; stack.length--;
                stack ~= a + b;
                break;
            case "-":
                if(stack.length < 2) { output ~= "stack empty\n"; break; }
                auto b = stack[$-1]; stack.length--;
                auto a = stack[$-1]; stack.length--;
                stack ~= a - b;
                break;
            case "*":
                if(stack.length < 2) { output ~= "stack empty\n"; break; }
                auto b = stack[$-1]; stack.length--;
                auto a = stack[$-1]; stack.length--;
                stack ~= a * b;
                break;
            case "/":
                if(stack.length < 2) { output ~= "stack empty\n"; break; }
                auto b = stack[$-1]; stack.length--;
                auto a = stack[$-1]; stack.length--;
                if(b == 0) { output ~= "divide by zero\n"; stack ~= a; stack ~= b; break; }
                stack ~= a / b;
                break;
            case "p":
                if(stack.length < 1) { output ~= "stack empty\n"; break; }
                output ~= to!string(stack[$-1]) ~ "\n";
                break;
            case "f":
                foreach_reverse(s; stack) output ~= to!string(s) ~ "\n";
                break;
            case "c":
                stack.length = 0;
                break;
            default:
                try {
                    stack ~= BigInt(token);
                } catch(Exception e) {
                    output ~= "parse error: " ~ token ~ "\n";
                }
                break;
        }
    }
    return output;
}

void dcCommand(string[] tokens) {
    BigInt[] stack;
    
    if(tokens.length > 2 && tokens[1] == "-e") {
        write(dcEval(tokens[2], stack));
        return;
    }
    
    // REPL
    ubyte[1024] buf;
    long n;
    while((n = sys_read(0, buf.ptr, 1024)) > 0) {
        string chunk = cast(string)buf[0..n];
        // Split by lines? dc parses whitespace separated.
        // We'll just pass buffer string to eval.
        write(dcEval(chunk, stack));
    }
}
