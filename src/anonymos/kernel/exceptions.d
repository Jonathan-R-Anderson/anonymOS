module anonymos.kernel.exceptions;

import anonymos.console : printLine;

nothrow:
@nogc:

extern(C) void handleInvalidOpcode()
{
    printLine("");
    printLine("[fault] Invalid opcode encountered by CPU.");
    printLine("[halt] System halted to prevent undefined behaviour.");

    for (;;)
    {
    }
}
