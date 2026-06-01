module userland.shell.console;

import core.console : console_putchar, console_write;

@nogc nothrow:

private size_t cstrLen(const(char)* s) {
    size_t n = 0;
    if (s is null) return 0;
    while (s[n] != 0) ++n;
    return n;
}

private void putChars(const(char)* s, size_t n) {
    console_write(s, n);
}

void print(const(char)[] s) {
    putChars(s.ptr, s.length);
}

void printLine(const(char)[] s) {
    print(s);
    console_putchar('\n');
}

void printHex(ulong v) {
    char[16] buf;
    char[16] hex = "0123456789abcdef";
    for (int i = 15; i >= 0; i--) {
        buf[i] = hex[v & 0xF];
        v >>= 4;
    }
    putChars(buf.ptr, buf.length);
}

void printUnsigned(ulong v) {
    char[21] buf;
    size_t i = buf.length;
    do {
        --i;
        buf[i] = cast(char)('0' + (v % 10));
        v /= 10;
    } while (v != 0 && i > 0);
    putChars(buf.ptr + i, buf.length - i);
}
