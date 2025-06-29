module kernel.arch_interface.ports;

extern(C):
    void outb(ushort port, ubyte val);
    ubyte inb(ushort port);
    void outw(ushort port, ushort val);
    ushort inw(ushort port);
    void outl(ushort port, uint val);
    uint inl(ushort port);
