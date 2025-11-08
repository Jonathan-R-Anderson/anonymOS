// echo.d — fixed
module echo;

import std.stdio : stdout, write, writeln;
import core.stdc.stdlib : exit;

// Convert a base-10 number composed of octal digits into decimal.
int convertOctal(int num, int rem, int m)
{
    int q = num / 10;
    int r = rem + (num % 10) * m;
    if (q > 0) return convertOctal(q, r, m * 8);
    return r;
}

// Consume up to 4 octal digits from s and print the result.
// If > 0377 (255), print the original octal text.
// Then continue parsing the remainder as escapes.
void getOctal(string s)
{
    enum maxlen = 4;
    enum upperLimit = 377; // octal 0377 == 255 decimal
    size_t olen = 0;

    while (olen < s.length)
    {
        char ch = s[olen];
        if (ch < '0' || ch > '7') break;
        ++olen;
    }

    size_t take = olen < maxlen ? olen : maxlen;
    auto octStr = s[0 .. take];

    int oct = 0;
    foreach (c; octStr) oct = oct * 10 + (c - '0');

    if (oct > upperLimit)
    {
        write(s); // print verbatim
    }
    else
    {
        int val = convertOctal(oct, 0, 1);
        write(val);
    }

    if (take < s.length)
        escapedString(s[take .. $]);
}

// Parse/print a string handling backslash escapes.
void escapedString(string s)
{
    bool escape = false;

    for (size_t i = 0; i < s.length; ++i)
    {
        immutable ch = s[i];

        if (escape)
        {
            // Not 'final switch' — we need a default branch.
            switch (ch)
            {
                case 'a': stdout.write('\a'); break;
                case 'b': stdout.write('\b'); break;
                case 'c': exit(0);
                case 'f': stdout.write('\f'); break;
                case 'n': stdout.write('\n'); break;
                case 'r': stdout.write('\r'); break;
                case 't': stdout.write('\t'); break;
                case 'v': stdout.write('\v'); break;
                case '\\': stdout.write('\\'); break;
                case '0':
                    // Delegate remainder after the '0' to octal parser.
                    if (i + 1 < s.length)
                        getOctal(s[i + 1 .. $]);
                    return; // getOctal() will continue the rest
                default:
                    // Unknown escape => print backslash literally then char
                    stdout.write('\\', ch);
                    break;
            }
            escape = false;
        }
        else
        {
            if (ch == '\\')
                escape = true;
            else
                stdout.write(ch);
        }
    }

    // Trailing single backslash => print it literally
    if (escape) stdout.write('\\');
}

int main(string[] args)
{
    if (args.length <= 1)
    {
        stdout.write('\n');
        return 0;
    }

    foreach (i, arg; args[1 .. $])
    {
        // Always run the escape parser (cheap) — it prints raw chars when no '\'
        escapedString(arg);

        if (i < args.length - 2)
            stdout.write(' ');
    }

    stdout.write('\n');
    return 0;
}
