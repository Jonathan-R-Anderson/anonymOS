module expr;

import std.stdio;
import std.conv : to, ConvException;
import std.regex : regex, matchFirst;
import std.string : indexOf;

struct Value {
    bool isNumber;
    long num;
    string str;
}

private Value makeNumber(long n) {
    return Value(true, n, to!string(n));
}

private Value makeString(string s) {
    return Value(false, 0, s);
}

private bool truthy(Value v) {
    return v.isNumber ? v.num != 0 : v.str.length != 0;
}

// Forward declarations
private Value parseExpr(string[] tokens, ref size_t idx);

private Value parsePrimary(string[] tokens, ref size_t idx) {
    if(idx >= tokens.length)
        return makeString("");

    auto tok = tokens[idx];

    if(tok == "(") {
        idx++;
        auto val = parseExpr(tokens, idx);
        if(idx < tokens.length && tokens[idx] == ")")
            idx++;
        return val;
    } else if(tok == "+") { // quote next token
        idx++;
        if(idx < tokens.length)
            return makeString(tokens[idx++]);
        return makeString("");
    } else if(tok == "length") {
        idx++;
        auto v = parsePrimary(tokens, idx);
        auto s = v.isNumber ? to!string(v.num) : v.str;
        return makeNumber(cast(long)s.length);
    } else if(tok == "index") {
        idx++;
        auto sVal = parsePrimary(tokens, idx);
        auto cVal = parsePrimary(tokens, idx);
        auto s = sVal.isNumber ? to!string(sVal.num) : sVal.str;
        auto chars = cVal.isNumber ? to!string(cVal.num) : cVal.str;
        size_t pos;
        for(pos = 0; pos < s.length; pos++)
            if(chars.indexOf(s[pos]) != -1)
                break;
        if(pos == s.length)
            return makeNumber(0);
        return makeNumber(cast(long)(pos + 1));
    } else if(tok == "substr") {
        idx++;
        auto sVal = parsePrimary(tokens, idx);
        auto pVal = parsePrimary(tokens, idx);
        auto lVal = parsePrimary(tokens, idx);
        auto s = sVal.isNumber ? to!string(sVal.num) : sVal.str;
        long p = pVal.isNumber ? pVal.num : 0;
        long l = lVal.isNumber ? lVal.num : 0;
        if(p <= 0 || l <= 0)
            return makeString("");
        size_t start = cast(size_t)(p - 1);
        if(start >= s.length)
            return makeString("");
        size_t end = start + cast(size_t)l;
        if(end > s.length) end = s.length;
        return makeString(s[start .. end]);
    } else if(tok == "match") {
        idx++;
        auto sVal = parsePrimary(tokens, idx);
        auto rVal = parsePrimary(tokens, idx);
        auto s = sVal.isNumber ? to!string(sVal.num) : sVal.str;
        auto r = rVal.isNumber ? to!string(rVal.num) : rVal.str;
        try {
            auto rx = regex("^" ~ r);
            auto m = matchFirst(s, rx);
            if(m.empty)
                return makeNumber(0);
            if(m.captures.length > 1)
                return makeString(m.captures[1]);
            return makeNumber(cast(long)m.hit.length);
        } catch(Exception) {
            return makeNumber(0);
        }
    }

    idx++;
    try {
        return makeNumber(to!long(tok));
    } catch(ConvException) {
        return makeString(tok);
    }
}

private Value parseMatchOp(string[] tokens, ref size_t idx) {
    auto val = parsePrimary(tokens, idx);
    while(idx < tokens.length && tokens[idx] == ":") {
        idx++;
        auto rVal = parsePrimary(tokens, idx);
        auto s = val.isNumber ? to!string(val.num) : val.str;
        auto r = rVal.isNumber ? to!string(rVal.num) : rVal.str;
        try {
            auto rx = regex("^" ~ r);
            auto m = matchFirst(s, rx);
            if(m.empty) {
                val = makeNumber(0);
            } else if(m.captures.length > 1) {
                val = makeString(m.captures[1]);
            } else {
                val = makeNumber(cast(long)m.hit.length);
            }
        } catch(Exception) {
            val = makeNumber(0);
        }
    }
    return val;
}

private Value parseMul(string[] tokens, ref size_t idx) {
    auto val = parseMatchOp(tokens, idx);
    while(idx < tokens.length && (tokens[idx] == "*" || tokens[idx] == "/" || tokens[idx] == "%")) {
        auto op = tokens[idx++];
        auto rhs = parseMatchOp(tokens, idx);
        if(!val.isNumber || !rhs.isNumber) {
            val = makeNumber(0);
        } else {
            switch(op) {
                case "*": val.num *= rhs.num; break;
                case "/": val.num = rhs.num == 0 ? 0 : val.num / rhs.num; break;
                case "%": val.num = rhs.num == 0 ? 0 : val.num % rhs.num; break;
                default: break;
            }
        }
    }
    return val;
}

private Value parseAdd(string[] tokens, ref size_t idx) {
    auto val = parseMul(tokens, idx);
    while(idx < tokens.length && (tokens[idx] == "+" || tokens[idx] == "-")) {
        auto op = tokens[idx++];
        auto rhs = parseMul(tokens, idx);
        if(!val.isNumber || !rhs.isNumber) {
            val = makeNumber(0);
        } else {
            switch(op) {
                case "+": val.num += rhs.num; break;
                case "-": val.num -= rhs.num; break;
                default: break;
            }
        }
    }
    return val;
}

private Value parseCompare(string[] tokens, ref size_t idx) {
    auto val = parseAdd(tokens, idx);
    if(idx < tokens.length) {
        auto op = tokens[idx];
        if(op == "<" || op == "<=" || op == "=" || op == "==" || op == "!=" || op == ">=" || op == ">") {
            idx++;
            auto rhs = parseAdd(tokens, idx);
            bool res = false;
            if(val.isNumber && rhs.isNumber) {
                auto a = val.num; auto b = rhs.num;
                switch(op) {
                    case "<": res = a < b; break;
                    case "<=": res = a <= b; break;
                    case "=": res = a == b; break;
                    case "==": res = a == b; break;
                    case "!=": res = a != b; break;
                    case ">=": res = a >= b; break;
                    case ">": res = a > b; break;
                    default: break;
                }
            } else {
                auto a = val.isNumber ? to!string(val.num) : val.str;
                auto b = rhs.isNumber ? to!string(rhs.num) : rhs.str;
                switch(op) {
                    case "<": res = a < b; break;
                    case "<=": res = a <= b; break;
                    case "=": res = a == b; break;
                    case "==": res = a == b; break;
                    case "!=": res = a != b; break;
                    case ">=": res = a >= b; break;
                    case ">": res = a > b; break;
                    default: break;
                }
            }
            val = makeNumber(res ? 1 : 0);
        }
    }
    return val;
}

private Value parseAnd(string[] tokens, ref size_t idx) {
    auto val = parseCompare(tokens, idx);
    while(idx < tokens.length && tokens[idx] == "&") {
        idx++;
        auto rhs = parseCompare(tokens, idx);
        if(truthy(val) && truthy(rhs)) {
            /* keep current value */
        } else {
            val = makeNumber(0);
        }
    }
    return val;
}

private Value parseOr(string[] tokens, ref size_t idx) {
    auto val = parseAnd(tokens, idx);
    while(idx < tokens.length && tokens[idx] == "|") {
        idx++;
        auto rhs = parseAnd(tokens, idx);
        if(!truthy(val))
            val = rhs;
    }
    return val;
}

private Value parseExpr(string[] tokens, ref size_t idx) {
    return parseOr(tokens, idx);
}

string exprEval(string[] tokens) {
    size_t idx = 0;
    auto val = parseExpr(tokens, idx);
    if(val.isNumber)
        return to!string(val.num);
    else
        return val.str;
}

/// Evaluate an expression and print the result.
void exprCommand(string[] tokens) {
    if(tokens.length < 2) {
        writeln("Usage: expr expression");
        return;
    }
    try {
        auto res = exprEval(tokens[1 .. $]);
        if(res.length)
            writeln(res);
    } catch(Exception) {
        writeln("expr: invalid expression");
    }
}

