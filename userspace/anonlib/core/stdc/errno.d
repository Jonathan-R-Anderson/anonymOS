module core.stdc.errno;

extern(C):
__gshared int errno;

pure nothrow @nogc @trusted pragma(inline, true) int getErrno()
{
    return errno;
}

pure nothrow @nogc @trusted pragma(inline, true) void setErrno(int e)
{
    errno = e;
} 