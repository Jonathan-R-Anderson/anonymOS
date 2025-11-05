module minimal_os.main;

extern(C):
@nothrow:
@nogc:

/// Entry point invoked from boot.s once the CPU is ready to run D code.
/// Displays a short message in the VGA text buffer and halts the CPU.
void kmain(ulong magic, ulong info)
{
    // Parameters supplied by the multiboot loader; unused in this example.
    cast(void) magic;
    cast(void) info;

    // Write a coloured greeting to the VGA text buffer.
    auto buffer = cast(ushort*)0xB8000;
    immutable message = "Hello from the D kernel!";

    size_t i = 0;
    foreach (immutable c; message)
    {
        buffer[i] = cast(ushort)c | (0x0F << 8); // white on black.
        ++i;
    }

    // Prevent the compiler from optimising the loop away while we halt.
    for (;;) {
        asm { hlt; }
    }
}
