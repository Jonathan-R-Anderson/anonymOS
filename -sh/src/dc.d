module dc;

import std.bigint : BigInt;
import std.conv : to;
import std.string : split, strip;

string dcEval(string expr) {
    BigInt[] stack;
    string output;
    foreach(token; split(expr)) {
        switch(token) {
            case "":
                break;
            case "+":
                if(stack.length < 2) throw new Exception("stack underflow");
                auto b = stack[$-1];
                auto a = stack[$-2];
                stack.length -= 2;
                stack ~= a + b;
                break;
            case "-":
                if(stack.length < 2) throw new Exception("stack underflow");
                auto b = stack[$-1];
                auto a = stack[$-2];
                stack.length -= 2;
                stack ~= a - b;
                break;
            case "*":
                if(stack.length < 2) throw new Exception("stack underflow");
                auto b = stack[$-1];
                auto a = stack[$-2];
                stack.length -= 2;
                stack ~= a * b;
                break;
            case "/":
                if(stack.length < 2) throw new Exception("stack underflow");
                auto b = stack[$-1];
                auto a = stack[$-2];
                stack.length -= 2;
                stack ~= b == 0 ? BigInt(0) : a / b;
                break;
            case "p":
                if(stack.length > 0)
                    output ~= to!string(stack[$-1]) ~ "\n";
                break;
            case "f":
                foreach(val; stack)
                    output ~= to!string(val) ~ "\n";
                break;
            case "c":
                stack.length = 0;
                break;
            case "d":
                if(stack.length < 1) throw new Exception("stack underflow");
                stack ~= stack[$-1];
                break;
            case "r":
                if(stack.length < 2) throw new Exception("stack underflow");
                auto tmp = stack[$-1];
                stack[$-1] = stack[$-2];
                stack[$-2] = tmp;
                break;
            default:
                try {
                    stack ~= BigInt(token);
                } catch(Exception) {
                    // ignore invalid tokens
                }
                break;
        }
    }
    if(output.length && output[$-1] == '\n')
        output = output[0 .. $-1];
    return output;
}
