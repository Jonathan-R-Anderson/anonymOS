module shell.expansion;

import std.stdio;
import std.string;
import std.array;
import std.algorithm;
import std.regex;
import std.path;
import std.file;
import std.conv;

/**
 * Enhanced glob matching supporting extglob.
 * Converts glob patterns to Regex.
 */
bool enhancedGlobMatch(string text, string pattern, bool extglob = false) {
    string re = globToRegex(pattern, extglob);
    try {
        auto r = regex("^" ~ re ~ "$");
        auto m = matchFirst(text, r);
        return !m.empty;
    } catch (Exception e) {
        return false;
    }
}

string globToRegex(string pattern, bool extglob = false) {
    string res = "";
    int i = 0;
    while (i < pattern.length) {
        char c = pattern[i];
        
        // Handle Escape markers (\x01 or \)
        if ((c == '\x01' || c == '\\') && i + 1 < pattern.length) {
            char next = pattern[i+1];
            // Escape it for regex
            res ~= "\\" ~ next;
            i += 2;
            continue;
        }

        bool handled = false;
        if (extglob && i + 1 < pattern.length && pattern[i+1] == '(') {
            char op = c;
            if (op == '?' || op == '*' || op == '+' || op == '@' || op == '!') {
                i += 2;
                int depth = 1;
                string inner = "";
                while (i < pattern.length && depth > 0) {
                    if (pattern[i] == '(') depth++;
                    else if (pattern[i] == ')') depth--;
                    if (depth > 0) inner ~= pattern[i];
                    i++;
                }
                i--; // position at ')'
                string innerRe = extglobListToRegex(inner, extglob);
                if (op == '?') res ~= "(?:" ~ innerRe ~ ")?";
                else if (op == '*') res ~= "(?:" ~ innerRe ~ ")*";
                else if (op == '+') res ~= "(?:" ~ innerRe ~ ")+";
                else if (op == '@') res ~= "(?:" ~ innerRe ~ ")";
                else if (op == '!') res ~= "(?!" ~ innerRe ~ "$).*";
                handled = true;
            }
        }

        if (!handled) {
            switch (c) {
                case '*': res ~= ".*"; break;
                case '?': res ~= "."; break;
                case '[':
                    res ~= "[";
                    i++;
                    if (i < pattern.length && pattern[i] == '!') {
                        res ~= "^"; i++;
                    }
                    while (i < pattern.length && pattern[i] != ']') {
                        res ~= pattern[i]; i++;
                    }
                    res ~= "]";
                    break;
                case '.': case '(': case ')': case '+': case '|': case '^': case '$': case '\\': case '{': case '}':
                    res ~= "\\" ~ c;
                    break;
                default:
                    res ~= c;
                    break;
            }
        }
        i++;
    }
    return res;
}

string extglobListToRegex(string inner, bool extglob) {
    auto parts = inner.split("|");
    string[] partRes;
    foreach(p; parts) {
        partRes ~= globToRegex(p, extglob);
    }
    return partRes.join("|");
}

/**
 * Brace expansion: {a,b} and {1..10}
 */
string[] braceExpand(string word) {
    auto openIdx = word.indexOf('{');
    if (openIdx == -1) return [word];
    
    int depth = 0;
    int closeIdx = -1;
    for (int i = cast(int)openIdx; i < word.length; i++) {
        if (word[i] == '{') depth++;
        else if (word[i] == '}') {
            depth--;
            if (depth == 0) {
                closeIdx = i;
                break;
            }
        }
    }
    
    if (closeIdx == -1) return [word];
    
    string prefix = word[0 .. openIdx];
    string suffix = word[closeIdx + 1 .. $];
    string content = word[openIdx + 1 .. closeIdx];
    
    string[] expanded;
    
    // Check for sequence expansion {1..10} or {a..z}
    auto dotsIdx = content.indexOf("..");
    if (dotsIdx != -1) {
        string startStr = content[0 .. dotsIdx];
        string endStr = content[dotsIdx + 2 .. $];
        
        try {
            long start = to!long(startStr);
            long end = to!long(endStr);
            long step = (start <= end) ? 1 : -1;
            for (long i = start; (step > 0 ? i <= end : i >= end); i += step) {
                expanded ~= prefix ~ to!string(i) ~ suffix;
            }
        } catch (Exception e) {
            if (startStr.length == 1 && endStr.length == 1) {
                char start = startStr[0];
                char end = endStr[0];
                int step = (start <= end) ? 1 : -1;
                for (char c = start; (step > 0 ? c <= end : c >= end); c = cast(char)(c + step)) {
                    expanded ~= prefix ~ to!string(c) ~ suffix;
                }
            } else {
                // Not a sequence, maybe comma separated?
                goto commaSep;
            }
        }
    } else {
    commaSep:
        // Comma-separated expansion {a,b,c}
        string[] parts;
        string current = "";
        int innerDepth = 0;
        for (int i = 0; i < content.length; i++) {
            if (content[i] == '{') innerDepth++;
            else if (content[i] == '}') innerDepth--;
            else if (content[i] == ',' && innerDepth == 0) {
                parts ~= current;
                current = "";
                continue;
            }
            current ~= content[i];
        }
        parts ~= current;
        
        foreach(p; parts) {
            expanded ~= prefix ~ p ~ suffix;
        }
    }
    
    // Recurse to handle more braces
    string[] finalResult;
    foreach(e; expanded) {
        foreach(res; braceExpand(e)) finalResult ~= res;
    }
    return finalResult;
}

/**
 * Pathname expansion (globbing)
 */
string[] pathnameExpand(string word, bool extglob = false) {
    if (!word.canFind('*') && !word.canFind('?') && !word.canFind('[') && !word.canFind('(')) {
        return [word];
    }
    
    // Split by / and expand recursively
    string[] parts = word.split("/");
    string[] currentDirs = (word.startsWith("/")) ? ["/"] : ["."];
    
    foreach (i, part; parts) {
        if (part == "" && i == 0) continue; // Leading /
        if (!part.canFind('*') && !part.canFind('?') && !part.canFind('[') && !part.canFind('(')) {
            string[] nextDirs;
            foreach (d; currentDirs) {
                string path = (d == ".") ? part : (d == "/" ? "/" ~ part : d ~ "/" ~ part);
                nextDirs ~= path;
            }
            currentDirs = nextDirs;
            continue;
        }
        
        string[] nextDirs;
        foreach (d; currentDirs) {
            try {
                if (std.file.exists(d) && std.file.isDir(d)) {
                    foreach (DirEntry de; dirEntries(d, SpanMode.shallow)) {
                        string name = baseName(de.name);
                        // Standard shell skip hidden files unless explicitly requested
                        if (name.startsWith(".") && !part.startsWith(".")) continue;
                        if (enhancedGlobMatch(name, part, extglob)) {
                            nextDirs ~= de.name;
                        }
                    }
                }
            } catch (Exception e) {}
        }
        currentDirs = nextDirs;
        if (currentDirs.length == 0) break;
    }
    
    if (currentDirs.length == 0) return [word];
    // Clean up "." prefix if word didn't start with it
    string[] result;
    foreach(d; currentDirs) {
        string path = d;
        if (!word.startsWith("./") && path.startsWith("./")) path = path[2 .. $];
        result ~= path;
    }
    result.sort();
    return result;
}
