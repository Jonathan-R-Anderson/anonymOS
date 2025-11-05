module object;

enum bool_false = false;
enum bool_true = true;

alias size_t = typeof(0.sizeof);
alias ptrdiff_t = typeof((cast(char*) null) - (cast(char*) null));

alias string = immutable(char)[];
alias wstring = immutable(wchar)[];
alias dstring = immutable(dchar)[];

alias hash_t = size_t;

extern(C):
@nogc nothrow pure void _d_assert_fail(const char*, const char*, uint) {}
@nogc nothrow pure void _d_switch_error(const char*, size_t) {}
@nogc nothrow pure void _d_arraybounds(size_t, size_t) {}
