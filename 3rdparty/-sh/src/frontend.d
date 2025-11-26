module frontend;

import lferepl : evalString, valueToString, ValueKind;
import std.ascii : isWhite;
import std.string : strip, stripLeft, startsWith, indexOf;

// Determine whether a command should be treated as raw LFE input.
//
// The original implementation assumed the `:lfe` prefix would appear at
// the very start of the string.  In practice users often type leading
// whitespace before the prefix.  We therefore strip leading whitespace
// before checking and, when a prefix is found, return the remainder of
// the line with surrounding whitespace removed so it can be passed
// directly to the evaluator.
bool forceLfe(ref string line) {
    auto trimmed = line.stripLeft;
    enum prefix = ":lfe";
    if(trimmed.startsWith(prefix)) {
        // Remove prefix and any following whitespace
        auto rest = trimmed[prefix.length .. $];
        line = rest.strip;
        return true;
    }
    return false;
}

// Detect whether the given line should be interpreted as an LFE
// expression.  Leading whitespace is ignored so that commands like
// "\t(expr)" are recognised correctly.  Besides traditional list forms,
// we also handle quoted forms and the map/tuple shorthand used by the
// LFE REPL.
bool isLfeInput(string s) {
    auto trimmed = s.stripLeft;
    if(trimmed.length == 0) return false;
    auto c = trimmed[0];
    if(c == '(' || c == '\'') return true;
    if(c == '#') {
        return trimmed.length > 1 && (trimmed[1] == '(' || trimmed[1] == 'M');
    }
    return false;
}

string evalToString(string code) {
    auto val = evalString(code);

    // If the result is a tuple that looks like the output of (sh ...),
    // extract the stdout part for shell interpolation.
    if (val.kind == ValueKind.Tuple && val.tuple.length == 3 && val.tuple[0].kind == ValueKind.Number) {
        auto stdout_val = val.tuple[1];
        if (stdout_val.kind == ValueKind.Atom) {
            return stdout_val.atom;
        }
    }

    // Otherwise, return the standard string representation.
    return valueToString(val);
}

string interpolateLfe(string line) {
    string result = line;
    // $(lfe ...)
    size_t pos;
    while((pos = result.indexOf("$(lfe")) != -1) {
        size_t start = pos + 5; // after $(lfe
        while(start < result.length && isWhite(result[start])) start++;
        size_t i = start;
        int depth = 0;
        for(; i < result.length; i++) {
            auto ch = result[i];
            if(ch == '(') depth++;
            else if(ch == ')') {
                if(depth == 0) break;
                else depth--;
            }
        }
        if(i >= result.length) break;
        auto expr = result[start .. i];
        string evald;
        try {
            evald = evalToString(expr);
        } catch(Exception e) {
            evald = "";
        }
        result = result[0 .. pos] ~ evald ~ result[i+1 .. $];
    }
    // ${lfe:...}
    while((pos = result.indexOf("${lfe:")) != -1) {
        size_t start = pos + 6; // after ${lfe:
        size_t i = start;
        int depth = 0;
        for(; i < result.length; i++) {
            auto ch = result[i];
            if(ch == '{') depth++;
            else if(ch == '}') {
                if(depth == 0) break;
                else depth--;
            }
        }
        if(i >= result.length) break;
        auto expr = result[start .. i];
        string evald;
        try {
            evald = evalToString(expr);
        } catch(Exception e) {
            evald = "";
        }
        result = result[0 .. pos] ~ evald ~ result[i+1 .. $];
    }
    return result;
}
