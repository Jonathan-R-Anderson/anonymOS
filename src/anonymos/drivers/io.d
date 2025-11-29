module anonymos.drivers.io;

@nogc nothrow:

export void outportb(ushort port, ubyte value) {
    asm @nogc nothrow {
        mov DX, port;
        mov AL, value;
        out DX, AL;
    }
}

export ubyte inportb(ushort port) {
    ubyte value;
    asm @nogc nothrow {
        mov DX, port;
        in AL, DX;
        mov value, AL;
    }
    return value;
}

export void outportw(ushort port, ushort value) {
    asm @nogc nothrow {
        mov DX, port;
        mov AX, value;
        out DX, AX;
    }
}

export ushort inportw(ushort port) {
    ushort value;
    asm @nogc nothrow {
        mov DX, port;
        in AX, DX;
        mov value, AX;
    }
    return value;
}

export void outportl(ushort port, uint value) {
    asm @nogc nothrow {
        mov DX, port;
        mov EAX, value;
        out DX, EAX;
    }
}

export uint inportl(ushort port) {
    uint value;
    asm @nogc nothrow {
        mov DX, port;
        in EAX, DX;
        mov value, EAX;
    }
    return value;
}
