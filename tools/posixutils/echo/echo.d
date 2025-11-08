// esc.d — D translation of the provided C code
module esc;

import std.stdio : stdout, stderr, write, writef, writeln;
import std.string : representation;
import std.algorithm : canFind;
import core.stdc.stdlib : exit;

// Convert a base-10 number composed of octal digits into decimal.
// Mirrors the recursive C version.
int convertOctal(int num, int rem, int m)
{
    int q = num / 10;
    int r = rem + (num % 10) * m;
    if (q > 0)
        return convertOctal(q, r, m * 8);
    return r;
}

// Process a \0… octal sequence starting at s (s begins at the first octal digit).
// Prints the converted value (decimal) or the original text if beyond 8-bit (377).
// Then continues processing the remainder of the string.
void getOctal(string s)
{
    enum maxlen = 4;              // accept up to 4 octal digits
    enum upperLimit = 377;        // 8-bit octal upper bound
    size_t olen = 0;

    // strspn(s, "01234567")
    while (olen < s.length)
    {
        char ch = s[olen];
        if (ch < '0' || ch > '7') break;
        ++olen;
    }

    size_t take = olen < maxlen ? olen : maxlen;
    auto octStr = s[0 .. take];

    // atoi(o)
    int oct = 0;
    foreach (c; octStr) oct = oct * 10 + (c - '0');

    if (oct > upperLimit)
    {
        // print original sequence verbatim (like printf("%s", s))
        write(s);
        return;
    }

    // Convert and print as decimal (matching original behavior)
    int val = convertOctal(oct, 0, 1);
    write(val);

    // If more remains, continue parsing it as an escaped string
    if (take < s.length)
        escapedString(s[take .. $]);
}

// Parse/print a string handling backslash escapes.
void escapedString(string s)
{
    bool escape = false;

    foreach (immutable ch; s)
    {
        if (escape)
        {
            final switch (ch)
            {
                case 'a': stdout.putc('\a'); break;
                case 'b': stdout.putc('\b'); break;
                case 'c': exit(0);
                case 'f': stdout.putc('\f'); break;
                case 'n': stdout.putc('\n'); break;
                case 'r': stdout.putc('\r'); break;
                case 't': stdout.putc('\t'); break;
                case 'v': stdout.putc('\v'); break;
                case '\\': stdout.putc('\\'); break;
                case '0':
                    // Delegate to octal handler; it will continue the rest.
                    // We must stop here to avoid double-consuming.
                    if (s.length > 0)
                    {
                        // slice after the '0'
                        auto afterZero = s[s.indexOf(ch) + 1 .. $];
                        getOctal(afterZero);
                    }
                    return;
                default:
                    write('\\', ch);
                    break;
            }
            escape = false;
        }
        else
        {
            if (ch == '\\')
                escape = true;
            else
                stdout.putc(ch);
        }
    }
}

int main(string[] args)
{
    // Print each arg; if it contains a backslash, process escapes; else print raw.
    foreach (i, arg; args[1 .. $])
    {
        if (arg.canFind('\\'))
            escapedString(arg);
        else
            write(arg);

        if (i < args.length - 2)
            stdout.putc(' ');
    }

    stdout.putc('\n');
    return 0;
}
