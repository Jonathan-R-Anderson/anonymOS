// kernel/io.d

module kernel.io;

public: // Export these functions

extern (C) void outb(ushort port, ubyte value); // Implemented in kernel/ports.s
extern (C) ubyte inb(ushort port);             // Implemented in kernel/ports.s

// The D function bodies are removed as the implementation is now external.
